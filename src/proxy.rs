//! SMP proxy support (PRXY/PKEY/PFWD/RFWD/PRES/RRES) between smp-rs engines.
//!
//! Layering (per spec simplex-messaging.md v20, simplified self-consistent nonces):
//!   client --PFWD--> proxy router --RFWD--> destination router
//!   client layer:  enc = crypto_box(DH(clientEph, destSessionPub), cbNonce(pfwdCorr), pad(transmission, 16226))
//!   proxy layer:   enc = crypto_box(sessSecret(proxy,dest), cbNonce(rfwdCorr), fwdTransmission)   [no pad]
//!   dest -> proxy: RRES = crypto_box(sessSecret, reverse(cbNonce(rfwdCorr)), short(fwdCorr) <> clientEncResp)
//!   proxy -> client: PRES = clientEncResp (same corrId as PFWD)
//!   client decrypts PRES with DH(clientEph, destSessionPub), nonce reverse(cbNonce(pfwdCorr)).
//!
//! Deviation from spec (documented): our plain-mode hello has empty sessionId, so the proxy
//! generates a random 24-byte proxy session id used as PFWD entity id; PKEY carries it as sessionId.

use std::sync::{Arc, Mutex};

use crate::crypto::*;
use crate::encoding::*;
use crate::protocol::*;
use crate::transport::*;

pub const PROXIED_T_LEN: usize = 16226;

pub fn reverse_nonce(n: &[u8; 24]) -> [u8; 24] {
    let mut r = *n;
    r.reverse();
    r
}

/// One proxied session held by the proxy router: a live connection to the destination router.
pub struct ProxyConn {
    pub stream: BoxStream,
    pub sess_secret: [u8; 32], // DH(proxyEph, destSessionPub) — proxy<->dest layer
    pub dest_session_id: Vec<u8>,
    pub dest_session_pub: [u8; 32], // raw X25519 pub of dest (for PKEY cert_key)
    pub v_min: u16,
    pub v_max: u16,
}

pub type ProxyMap = std::collections::HashMap<Vec<u8>, Arc<Mutex<ProxyConn>>>;

/// Proxy router: handle PRXY — open a session to the destination router.
pub fn open_proxy_session(dest_host: &str, dest_port: u16, dest_key_hash: &[u8]) -> Result<ProxyConn, String> {
    let addr: std::net::SocketAddr = format!("{dest_host}:{dest_port}").parse().map_err(|e| format!("{e}"))?;
    let mut stream = connect_plain(addr).map_err(|e| e.to_string())?;
    // read dest server hello (has dest session pub in authPubKey)
    let sh = read_block(&mut stream).map_err(|e| e.to_string())?;
    let (v_min, v_max, dest_sid, auth) = parse_server_hello_key(&sh).map_err(|e| e.to_string())?;
    let dest_pub_der = auth.ok_or("destination router did not send a session key")?;
    let (_alg, dest_pub_raw) = parse_spki(&dest_pub_der).map_err(|e| e.to_string())?;
    // send our client hello as a proxy client (proxyServer = T) with our ephemeral pubkey
    let eph = x25519_keypair();
    let ch = client_hello_block_key(SMP_VERSION, dest_key_hash, true, Some(spki_x25519(&eph.public.to_bytes())))
        .map_err(|e| e.to_string())?;
    write_block(&mut stream, &ch).map_err(|e| e.to_string())?;
    let sess_secret = x25519_dh(&eph.secret, &x25519_public(dest_pub_raw));
    let mut dest_pub = [0u8; 32];
    dest_pub.copy_from_slice(&dest_pub_raw);
    Ok(ProxyConn { stream, sess_secret, dest_session_id: dest_sid, dest_session_pub: dest_pub, v_min, v_max })
}

/// Proxy router: handle PFWD — wrap the client-encrypted transmission into RFWD and relay.
/// Returns the client-encrypted response (PRES payload).
pub fn relay_pfwd(conn: &Arc<Mutex<ProxyConn>>, pfwd_corr: &[u8], version: u16, command_key: &[u8], client_enc: &[u8]) -> Result<Vec<u8>, String> {
    let mut g = conn.lock().unwrap_or_else(|e| e.into_inner());
    let rfwd_corr = random_bytes(24);
    let mut fwd = Vec::new();
    w_short(&mut fwd, pfwd_corr).map_err(|e| e.to_string())?;
    w_u16(&mut fwd, version);
    w_short(&mut fwd, command_key).map_err(|e| e.to_string())?;
    fwd.extend_from_slice(client_enc); // transmission tail, raw
    let mut n = [0u8; 24];
    n.copy_from_slice(&rfwd_corr);
    let outer = secretbox_encrypt(&g.sess_secret, &n, &fwd);
    let mut cmd = b"RFWD ".to_vec();
    cmd.extend_from_slice(&outer);
    let t = Transmission { authenticator: vec![], corr_id: rfwd_corr.clone(), entity_id: vec![], command: cmd };
    let wire = encode_transmission(&t).map_err(|e| e.to_string())?;
    let blk = encode_block(&[wire]).map_err(|e| e.to_string())?;
    write_block(&mut g.stream, &blk).map_err(|e| e.to_string())?;
    // read RRES
    let rb = read_block(&mut g.stream).map_err(|e| e.to_string())?;
    let wires = decode_block(&rb).map_err(|e| e.to_string())?;
    for w in &wires {
        let rt = decode_transmission(w).map_err(|e| e.to_string())?;
        if let Ok(BrokerMsg::Rres { enc }) = parse_broker(&rt.command) {
            let rn = reverse_nonce(&n);
            let plain = secretbox_decrypt(&g.sess_secret, &rn, &enc).ok_or("RRES decrypt failed")?;
            // plain = short(fwdCorr) <> clientEncResp
            let mut r = Reader::new(&plain);
            let _fwd_corr = r.short().map_err(|e| e.to_string())?;
            return Ok(r.rest().to_vec());
        }
    }
    Err("no RRES in response block".into())
}

/// Destination router: handle RFWD — decrypt proxy layer, then client layer, dispatch, encrypt response.
/// `sess` = this connection's proxy<->dest session secret; `server_eph_priv` = this server's hello ephemeral priv.
pub fn handle_rfwd(
    enc: &[u8],
    corr_id: &[u8],
    sess: &[u8; 32],
    server_eph_priv: &x25519_dalek::StaticSecret,
    dest_sid: &[u8],
    dispatch: &dyn Fn(&Transmission) -> Vec<Transmission>,
) -> Result<Vec<u8>, String> {
    let mut n = [0u8; 24];
    n.copy_from_slice(corr_id);
    let fwd = secretbox_decrypt(sess, &n, enc).ok_or("RFWD proxy-layer decrypt failed")?;
    let mut r = Reader::new(&fwd);
    let fwd_corr = r.short().map_err(|e| e.to_string())?;
    let _version = r.u16().map_err(|e| e.to_string())?;
    let command_key = r.short().map_err(|e| e.to_string())?;
    let client_enc = r.rest().to_vec();
    // client layer: DH(serverEph, clientEphPub from command_key), nonce cbNonce(fwd_corr)
    let (_alg, client_eph_raw) = parse_spki(&command_key).map_err(|e| e.to_string())?;
    let client_sess = x25519_dh(server_eph_priv, &x25519_public(client_eph_raw));
    let mut fc = [0u8; 24];
    fc.copy_from_slice(&fwd_corr);
    let padded = secretbox_decrypt(&client_sess, &fc, &client_enc).ok_or("RFWD client-layer decrypt failed")?;
    let wire = unpad(&padded).map_err(|e| e.to_string())?;
    let t = decode_transmission(&wire).map_err(|e| e.to_string())?;
    let responses = dispatch(&t);
    let mut inner = Vec::new();
    for resp in &responses {
        inner.extend_from_slice(&encode_transmission(resp).map_err(|e| e.to_string())?);
    }
    let padded_resp = pad(&inner, PROXIED_T_LEN).map_err(|e| e.to_string())?;
    let rn = reverse_nonce(&fc);
    let client_enc_resp = secretbox_encrypt(&client_sess, &rn, &padded_resp);
    // RRES payload = short(fwd_corr) <> client_enc_resp ; outer nonce = reverse(cbNonce(rfwd corr))
    let mut payload = Vec::new();
    w_short(&mut payload, &fwd_corr).map_err(|e| e.to_string())?;
    payload.extend_from_slice(&client_enc_resp);
    let outer_n = reverse_nonce(&n);
    let _ = dest_sid;
    Ok(secretbox_encrypt(sess, &outer_n, &payload))
}
