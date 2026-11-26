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
    // U-15 (audit #3): with a real keyHash the proxy hop MUST be TLS 1.3 pinned to
    // it (PinVerifier) — plain TCP lets a MITM impersonate the destination router.
    // An all-zero hash is accepted only for local dev/test engines.
    let zero = [0u8; 32];
    let mut stream: crate::transport::BoxStream = if dest_key_hash.len() == 32 && dest_key_hash != zero {
        let kh: [u8; 32] = dest_key_hash.try_into().map_err(|_| "bad keyhash len".to_string())?;
        crate::transport::connect_tls_sni(addr, dest_host, kh, true).map_err(|e| e.to_string())?
    } else {
        connect_plain(addr).map_err(|e| e.to_string())?
    };
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
    let sess_secret = x25519_dh_checked(&eph.secret, &x25519_public(dest_pub_raw))?;
    let dest_pub: [u8; 32] = dest_pub_raw
        .as_slice()
        .try_into()
        .map_err(|_| "proxy dest: bad session pubkey length".to_string())?;
    Ok(ProxyConn { stream, sess_secret, dest_session_id: dest_sid, dest_session_pub: dest_pub, v_min, v_max })
}

/// Error code returned when a forwarded payload carries more than one
/// transaction. Haskell uses the `BLOCK` error type for this case.
pub const FORWARD_BLOCK_ERR: &str = "BLOCK: only single forwarded transactions allowed";

/// Enforce the Haskell rule that a forwarded transaction carries exactly ONE
/// transmission ("only allowing single forwarded transactions",
/// `Simplex/Messaging/Server.hs:2134`).
///
/// The reference implementation parses the forwarded payload as a non-empty list
/// of transmissions and accepts it only when the list has a single element
/// (`t :| []`); anything else is a `BLOCK`. Without this rule a peer could smuggle
/// several commands through one forwarded transaction and get them dispatched
/// atomically, which is exactly the smuggling the reference implementation
/// refuses.
///
/// The one documented extension is this crate's onion nesting, which sends
/// exactly two transmissions — a `[PRXY, PFWD]` pair dispatched atomically so
/// that the inner PFWD can use the proxy session the PRXY just opened. Any other
/// combination of two or more transmissions is rejected.
pub fn check_forwarded_transmissions(wires: &[Vec<u8>]) -> Result<(), &'static str> {
    match wires.len() {
        0 => Err(FORWARD_BLOCK_ERR),
        1 => Ok(()),
        2 => {
            let tags: Vec<String> = wires
                .iter()
                .filter_map(|w| decode_transmission(w).ok())
                .map(|t| crate::protocol::tag_of(&t.command))
                .collect();
            if tags.len() == 2 && tags[0] == "PRXY" && tags[1] == "PFWD" {
                Ok(())
            } else {
                Err(FORWARD_BLOCK_ERR)
            }
        }
        _ => Err(FORWARD_BLOCK_ERR),
    }
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
    let n: [u8; 24] = rfwd_corr.as_slice().try_into().expect("rfwd_corr is random_bytes(24)");
    let outer = secretbox_encrypt(&g.sess_secret, &n, &fwd)?;
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
    // U-02 (audit #3): corr_id/fwd_corr come from the wire (shortString, 0..=255B) —
    // never copy_from_slice into a fixed array (remote panic / DoS).
    let n: [u8; 24] = corr_id
        .try_into()
        .map_err(|_| "RFWD: bad corr_id length".to_string())?;
    let fwd = secretbox_decrypt(sess, &n, enc).ok_or("RFWD proxy-layer decrypt failed")?;
    let mut r = Reader::new(&fwd);
    let fwd_corr = r.short().map_err(|e| e.to_string())?;
    let _version = r.u16().map_err(|e| e.to_string())?;
    let command_key = r.short().map_err(|e| e.to_string())?;
    let client_enc = r.rest().to_vec();
    // client layer: DH(serverEph, clientEphPub from command_key), nonce cbNonce(fwd_corr)
    let (_alg, client_eph_raw) = parse_spki(&command_key).map_err(|e| e.to_string())?;
    let client_sess = x25519_dh_checked(server_eph_priv, &x25519_public(client_eph_raw))?;
    let fc: [u8; 24] = fwd_corr
        .as_slice()
        .try_into()
        .map_err(|_| "RFWD: bad fwd_corr length".to_string())?;
    let padded = secretbox_decrypt(&client_sess, &fc, &client_enc).ok_or("RFWD client-layer decrypt failed")?;
    let content = unpad(&padded).map_err(|e| e.to_string())?;
    // onion nesting: inner payload may be a block of several wires ([Proxy{next}, Pfwd{…}]).
    // Try block first (and require full consumption + valid transmissions), then legacy single wire.
    let wires: Vec<Vec<u8>> = {
        let block_ok = decode_block_raw(&content)
            .ok()
            .filter(|ws| {
                ws.iter().all(|w| decode_transmission(w).is_ok())
                    && ws.iter().map(|w| 2 + w.len()).sum::<usize>() + 1 == content.len()
            });
        match block_ok {
            Some(ws) => ws,
            None => match decode_transmission(&content) {
                Ok(_) => vec![content.clone()],
                Err(e) => return Err(e.to_string()),
            },
        }
    };
    if std::env::var_os("SMP_DEBUG").is_some() { eprintln!("[rfwd] content_len={} wires={} tags={:?}", content.len(), wires.len(), wires.iter().map(|w| crate::protocol::tag_of(w).chars().take(8).collect::<String>()).collect::<Vec<_>>()); }
    let mut resp_wires: Vec<Vec<u8>> = Vec::new();
    match check_forwarded_transmissions(&wires) {
        Ok(()) => {
            for w in &wires {
                let t = decode_transmission(w).map_err(|e| e.to_string())?;
                let responses = dispatch(&t);
                for resp in &responses {
                    resp_wires.push(encode_transmission(resp).map_err(|e| e.to_string())?);
                }
            }
        }
        Err(code) => {
            // Haskell `processForwardedCommand` maps a rejection to
            // `either (Just . ERR) id`: the error travels INSIDE the forwarded
            // response, so the client gets a well-formed RRES carrying ERR BLOCK
            // rather than a transport-level failure.
            let corr = wires
                .first()
                .and_then(|w| decode_transmission(w).ok())
                .map(|t| t.corr_id)
                .unwrap_or_default();
            let err_t = Transmission {
                authenticator: Vec::new(),
                corr_id: corr,
                entity_id: Vec::new(),
                command: format!("ERR {code}").into_bytes(),
            };
            resp_wires.push(encode_transmission(&err_t).map_err(|e| e.to_string())?);
        }
    }
    // single response: raw transmission (legacy single-hop); multiple: block content
    let inner = if resp_wires.len() == 1 {
        resp_wires.pop().unwrap_or_default()
    } else {
        encode_block_raw(&resp_wires).map_err(|e| e.to_string())?
    };
    // response pad budget shrinks with nesting depth: request padded size minus one
    // layer of overhead (~256B: PKEY + framing + 16B tag), so a 2-hop response still
    // fits into one block on the way back
    let req_pad = client_enc.len().saturating_sub(16);
    let mut budget = req_pad.saturating_sub(256).min(PROXIED_T_LEN);
    if budget < inner.len() + 2 {
        budget = inner.len() + 2;
    }
    let padded_resp = pad(&inner, budget).map_err(|e| e.to_string())?;
    let rn = reverse_nonce(&fc);
    let client_enc_resp = secretbox_encrypt(&client_sess, &rn, &padded_resp)?;
    // RRES payload = short(fwd_corr) <> client_enc_resp ; outer nonce = reverse(cbNonce(rfwd corr))
    let mut payload = Vec::new();
    w_short(&mut payload, &fwd_corr).map_err(|e| e.to_string())?;
    payload.extend_from_slice(&client_enc_resp);
    let outer_n = reverse_nonce(&n);
    let _ = dest_sid;
    secretbox_encrypt(sess, &outer_n, &payload)
}
