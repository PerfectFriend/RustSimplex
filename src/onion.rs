//! Onion routing over SMP proxy chains: `client -> R1 -> R2 -> ... -> Rn -> dest`.
//!
//! The client opens ONE connection (to R1) and writes a single block whose wires
//! are nested layers. Layer *i* is
//! `secretbox(DH(eph_i, pub_of_next_hop), corr_i, pad(block_content_of_inner_wires))`
//! and is peeled by the relay/dest that is `next_hop` via the existing RFWD
//! client-layer path. The innermost layer is the real transmission to the
//! destination queue. A nested inner block is `[Proxy{next}, Pfwd{entity=∅,
//! enc=inner}]`; the empty entity makes the Pfwd use the proxy session that the
//! preceding inner Proxy just opened on that connection (`ConnCtx::last_proxy`),
//! so the client never learns intermediate proxy_ids.
//!
//! Privacy property: R1 only learns R2's address; R_i only learns R_{i+1};
//! only the destination sees the final queue id; the innermost layer is
//! end-to-end between client and destination.

use std::net::SocketAddr;

use crate::client::Client;
use crate::crypto::{cb_nonce, pad, random_bytes, secretbox_decrypt, secretbox_encrypt, spki_x25519, unpad, x25519_dh, x25519_keypair, x25519_public};
use crate::identity::Ed25519Keypair;
use crate::protocol::{
    auth_sign, decode_block, decode_block_raw, decode_transmission, encode_block, encode_block_raw,
    encode_command, encode_transmission, parse_broker, parse_command, BrokerMsg, Command, Transmission, SMP_VERSION,
};
use crate::proxy::{reverse_nonce, PROXIED_T_LEN};

/// One onion hop: relay address + its server ephemeral X25519 pub (from server hello).
#[derive(Clone, Debug)]
pub struct OnionHop {
    pub addr: SocketAddr,
    pub server_pub: [u8; 32],
}

/// Fetch a relay's ephemeral X25519 pub via a plain handshake (server hello authPubKey).
pub fn fetch_hop(addr: SocketAddr) -> Result<OnionHop, String> {
    let c = Client::connect_plain(addr, &[0u8; 32])?;
    let server_pub = c.server_eph_pub.ok_or("server hello had no authPubKey")?;
    Ok(OnionHop { addr, server_pub })
}

/// Send `cmd` (with `entity`, optionally signed with `auth_kp`) to `dest` through
/// the onion chain `hops` (at least one hop). Returns broker messages from the dest.
pub fn onion_request(
    hops: &[OnionHop],
    dest: SocketAddr,
    dest_pub: [u8; 32],
    cmd: Command,
    entity: Vec<u8>,
    auth_kp: Option<&Ed25519Keypair>,
) -> Result<Vec<BrokerMsg>, String> {
    if hops.is_empty() {
        return Err("onion_request: at least one hop required".into());
    }
    let mut entry = Client::connect_plain(hops[0].addr, &[0u8; 32])?;

    // innermost wire: the real transmission to the destination
    let mut t_d = Transmission {
        authenticator: Vec::new(),
        corr_id: random_bytes(24),
        entity_id: entity,
        command: encode_command(&cmd).map_err(|e| e.to_string())?,
    };
    if let Some(kp) = auth_kp {
        auth_sign(entry.session_id(), &mut t_d, kp).map_err(|e| e.to_string())?;
    }
    let wire_d = encode_transmission(&t_d).map_err(|e| e.to_string())?;
    let mut wires = vec![wire_d];

    // build layers inside-out; remember the innermost (eph, corr) to decrypt the response
    let mut next_addr = dest;
    let mut next_pub = dest_pub;
    let mut first_eph = None;
    let mut first_corr = None;
    for i in (0..hops.len()).rev() {
        let eph = x25519_keypair();
        let key = x25519_dh(&eph.secret, &x25519_public(next_pub));
        let corr = random_bytes(24);
        let content = encode_block_raw(&wires).map_err(|e| e.to_string())?;
        let padded = pad(&content, PROXIED_T_LEN).map_err(|e| e.to_string())?;
        let enc = secretbox_encrypt(&key, &cb_nonce(&corr), &padded);
        if i == hops.len() - 1 {
            first_eph = Some(eph);
            first_corr = Some(corr.clone());
        }
        let pfwd_wire = encode_transmission(&Transmission {
            authenticator: Vec::new(),
            corr_id: corr,
            entity_id: Vec::new(),
            command: encode_command(&Command::Pfwd {
                version: SMP_VERSION,
                command_key: spki_x25519(&eph.public.to_bytes()),
                enc,
            })
            .map_err(|e| e.to_string())?,
        })
        .map_err(|e| e.to_string())?;
        let proxy_wire = encode_transmission(&Transmission {
            authenticator: Vec::new(),
            corr_id: random_bytes(24),
            entity_id: Vec::new(),
            command: encode_command(&Command::Proxy {
                host: next_addr.ip().to_string().into_bytes(),
                port: next_addr.port().to_string().into_bytes(),
                auth: None,
            })
            .map_err(|e| e.to_string())?,
        })
        .map_err(|e| e.to_string())?;
        wires = vec![proxy_wire, pfwd_wire];
        next_addr = hops[i].addr;
        next_pub = hops[i].server_pub;
    }

    // the outermost block [Proxy{R2}, Pfwd{enc_0}] goes straight to R1; Proxy sets
    // last_proxy before Pfwd runs, so the empty entity_id resolves correctly
    let blk = encode_block(&wires).map_err(|e| e.to_string())?;
    entry.write_raw_block(&blk)?;
    let resp_block = entry.read_raw_block()?;
    let resp_wires = decode_block(&resp_block).map_err(|e| e.to_string())?;

    // responses come back PRES-wrapped; the outermost PRES is encrypted with the
    // innermost (destination) client-layer key
    let eph = first_eph.ok_or("no innermost layer")?;
    let corr = first_corr.ok_or("no innermost corr")?;
    let key = x25519_dh(&eph.secret, &x25519_public(dest_pub));
    let nonce = cb_nonce(&corr);
    let mut msgs = Vec::new();
    for w in &resp_wires {
        let t = decode_transmission(w).map_err(|e| e.to_string())?;
        if let Command::Pres { enc } = parse_command(&t.command).map_err(|e| e.to_string())? {
            let rn = reverse_nonce(&nonce);
            let plain = secretbox_decrypt(&key, &rn, &enc).ok_or("PRES decrypt failed")?;
            let inner = unpad(&plain).map_err(|e| e.to_string())?;
            match decode_transmission(&inner) {
                Ok(_) => msgs.push(parse_broker(&inner).ok_or("bad broker msg in PRES")?),
                Err(_) => {
                    for iw in decode_block_raw(&inner).map_err(|e| e.to_string())? {
                        msgs.push(parse_broker(&iw).ok_or("bad broker msg in PRES")?);
                    }
                }
            }
        } else {
            msgs.push(parse_broker(w).ok_or("bad broker msg")?);
        }
    }
    Ok(msgs)
}
