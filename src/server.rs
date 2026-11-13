//! SMP router engine (server). In-memory queue store, command dispatch, Ed25519
//! signature auth. Transport-agnostic: works over plain TCP or TLS 1.3 (rustls).
//!
//! Concurrency model: one pump thread per connection owns the stream (non-blocking
//! reads). Recipient pushes (MSG) go to a per-connection outbox channel that the
//! pump drains and writes — so a single writer per connection, no TLS split needed.

use std::collections::{HashMap, VecDeque};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::Duration;

use crate::crypto::*;
use crate::encoding::{EncodeError, BLOCK_SIZE};
use crate::identity::RouterIdentity;
use crate::protocol::*;
use crate::transport::*;

pub struct Queue {
    pub rcv_id: Vec<u8>,
    pub snd_id: Vec<u8>,
    pub rcv_auth_raw: [u8; 32],
    pub rcv_auth_x: bool, // true = X25519 crypto_box authenticator (needs server eph key), false = Ed25519 signature
    pub snd_auth: Option<[u8; 32]>,
    pub rcv_dh_secret: [u8; 32],
    pub messages: VecDeque<(Vec<u8>, Vec<u8>)>, // (msg_id, body)
    pub subscriber: Option<mpsc::Sender<Vec<u8>>>, // outbox of wire transmissions to push
    // notifier (NTF) — separate queue id so router compromise can't correlate
    pub ntf_id: Option<Vec<u8>>,
    pub ntf_auth_raw: Option<[u8; 32]>,       // notifier's Ed25519 pubkey (raw)
    pub rcv_ntf_dh_secret: Option<[u8; 32]>,  // DH(srv_ntf_priv, rcv_ntf_dh_pub)
    pub ntf_subscriber: Option<mpsc::Sender<Vec<u8>>>,
}

pub struct ServerState {
    pub by_rcv: HashMap<Vec<u8>, Queue>,
    pub by_snd: HashMap<Vec<u8>, Vec<u8>>, // snd_id -> rcv_id
    pub by_ntf: HashMap<Vec<u8>, Vec<u8>>, // ntf_id -> rcv_id
    pub proxies: crate::proxy::ProxyMap,   // proxy_session_id -> dest conn
    pub xftp: crate::xftp::XftpStore,      // packet_id -> XftpPacket
    pub persist: Option<std::path::PathBuf>,
}

/// Per-connection proxy context (session key from hello exchange).
pub struct ConnCtx {
    pub sess_secret: Option<[u8; 32]>,
    pub server_eph_priv: Option<x25519_dalek::StaticSecret>,
}

impl ServerState {
    pub fn new() -> Self {
        ServerState { by_rcv: HashMap::new(), by_snd: HashMap::new(), by_ntf: HashMap::new(), proxies: HashMap::new(), xftp: HashMap::new(), persist: None }
    }
    pub fn persist_now(&self) {
        if let Some(p) = &self.persist {
            let _ = crate::store::save(p, self);
        }
    }
}

pub fn new_state() -> Arc<Mutex<ServerState>> {
    Arc::new(Mutex::new(ServerState::new()))
}

pub fn new_state_persist(path: std::path::PathBuf) -> Arc<Mutex<ServerState>> {
    let mut st = crate::store::load(&path).unwrap_or_else(ServerState::new);
    st.persist = Some(path);
    Arc::new(Mutex::new(st))
}

fn resp(corr_id: Vec<u8>, entity_id: Vec<u8>, m: BrokerMsg) -> Result<Transmission, EncodeError> {
    Ok(Transmission {
        authenticator: Vec::new(),
        corr_id,
        entity_id,
        command: encode_broker(&m)?,
    })
}

/// Poison-tolerant state lock (v0.22): a panicked writer must not take the whole
/// server down — recover the inner state from a poisoned mutex.
fn lock_state(st: &Arc<Mutex<ServerState>>) -> std::sync::MutexGuard<'_, ServerState> {
    st.lock().unwrap_or_else(|e| e.into_inner())
}

fn err_resp(corr_id: Vec<u8>, entity_id: Vec<u8>, e: &str) -> Result<Transmission, EncodeError> {
    resp(corr_id, entity_id, BrokerMsg::Err(e.to_string()))
}

/// Never-panicking response builders (v0.22): on encode failure return a minimal raw
/// `ERR INTERNAL` transmission instead of unwrapping.
macro_rules! resp_np {
    ($c:expr, $e:expr, $m:expr) => {
        resp($c, $e, $m).unwrap_or_else(|_| Transmission {
            authenticator: Vec::new(),
            corr_id: Vec::new(),
            entity_id: Vec::new(),
            command: b"ERR INTERNAL".to_vec(),
        })
    };
}
macro_rules! err_np {
    ($c:expr, $e:expr, $s:expr) => {
        err_resp($c, $e, $s).unwrap_or_else(|_| Transmission {
            authenticator: Vec::new(),
            corr_id: Vec::new(),
            entity_id: Vec::new(),
            command: b"ERR INTERNAL".to_vec(),
        })
    };
}
use resp_np;
use err_np;

pub fn encrypt_for_recipient(rcv_dh_secret: &[u8; 32], msg_id: &[u8], body: &[u8]) -> Result<Vec<u8>, EncodeError> {
    let padded = crate::encoding::pad(body, MAX_RCV_MSG_LEN)?;
    Ok(secretbox_encrypt(rcv_dh_secret, &cb_nonce(msg_id), &padded))
}
pub fn decrypt_for_recipient(rcv_dh_secret: &[u8; 32], msg_id: &[u8], enc: &[u8]) -> Option<Vec<u8>> {
    let pt = secretbox_decrypt(rcv_dh_secret, &cb_nonce(msg_id), enc)?;
    crate::encoding::unpad(&pt).ok()
}

/// public wrapper for debug
pub fn hsalsa20_pub(key: &[u8; 32], nonce: &[u8; 16]) -> [u8; 32] {
    crate::crypto::hsalsa20_pub(key, nonce)
}

/// Recipient-side auth check: Ed25519 signature, or X25519 crypto_box authenticator
/// keyed by DH(server per-connection eph priv, queue X25519 auth pub) when rcv_auth_x.
fn qauth(session_id: &[u8], t: &Transmission, q: &Queue, ctx: &ConnCtx) -> bool {
    if q.rcv_auth_x {
        match &ctx.server_eph_priv {
            Some(eph) => verify_box(session_id, t, &x25519_dh(eph, &x25519_public(q.rcv_auth_raw))),
            None => false,
        }
    } else {
        verify_sign(session_id, t, &q.rcv_auth_raw)
    }
}

fn dispatch(
    t: &Transmission,
    st: &Arc<Mutex<ServerState>>,
    session_id: &[u8],
    outbox: &mpsc::Sender<Vec<u8>>,
    ctx: &ConnCtx,
) -> Vec<Transmission> {
    let cmd = match parse_command(&t.command) {
        Ok(c) => c,
        Err(e) => return vec![err_np!(t.corr_id.clone(), t.entity_id.clone(), &format!("CMD {e}"))],
    };
    let dirty = matches!(
        cmd,
        Command::New { .. } | Command::Send { .. } | Command::Ack(_) | Command::Key(_) | Command::Skey(_) | Command::Del
            | Command::Nkey { .. } | Command::Nsub | Command::Ndel
            | Command::Fnew { .. } | Command::Fput { .. } | Command::Fdel { .. }
    );
    let out = dispatch_cmd(cmd, t, st, session_id, outbox, ctx);
    if dirty {
        lock_state(st).persist_now();
    }
    out
}

fn dispatch_cmd(
    cmd: Command,
    t: &Transmission,
    st: &Arc<Mutex<ServerState>>,
    session_id: &[u8],
    outbox: &mpsc::Sender<Vec<u8>>,
    ctx: &ConnCtx,
) -> Vec<Transmission> {
    match cmd {
        Command::New { rcv_auth_key, rcv_dh_key, .. } => {
            if !t.entity_id.is_empty() {
                return vec![err_np!(t.corr_id.clone(), vec![], "CMD HAS_AUTH")];
            }
            let (alg, raw) = match parse_spki(&rcv_auth_key) {
                Ok(x) => x,
                Err(_) => return vec![err_np!(t.corr_id.clone(), vec![], "AUTH")],
            };
            let ok = match alg {
                AuthAlg::Ed25519 => verify_sign(session_id, t, &raw),
                // X25519 queue auth: crypto_box authenticator with dhSecret = DH(server eph priv, queue auth pub)
                // (C.cbVerify k pk (cbNonce corrId) authenticator authorized, Server.hs verifyCmdAuth)
                AuthAlg::X25519 => match &ctx.server_eph_priv {
                    Some(eph) => verify_box(session_id, t, &x25519_dh(eph, &x25519_public(raw))),
                    None => false,
                },
            };
            if !ok {
                return vec![err_np!(t.corr_id.clone(), vec![], "AUTH")];
            }
            let (_dh_alg, dh_raw) = match parse_spki(&rcv_dh_key) {
                Ok(x) => x,
                Err(_) => return vec![err_np!(t.corr_id.clone(), vec![], "CMD SYNTAX")],
            };
            let client_dh_pub = x25519_public(dh_raw);
            let srv = x25519_keypair();
            let rcv_dh_secret = x25519_dh(&srv.secret, &client_dh_pub);
            let rcv_id = random_bytes(16);
            let snd_id = random_bytes(24);
            let srv_dh_der = spki_x25519(&srv.public.to_bytes());
            {
                let mut s = lock_state(st);
                s.by_rcv.insert(rcv_id.clone(), Queue {
                    rcv_id: rcv_id.clone(),
                    snd_id: snd_id.clone(),
                    rcv_auth_raw: raw,
                    rcv_auth_x: matches!(alg, AuthAlg::X25519),
                    snd_auth: None,
                    rcv_dh_secret,
                    messages: VecDeque::new(),
                    subscriber: None,
                    ntf_id: None,
                    ntf_auth_raw: None,
                    rcv_ntf_dh_secret: None,
                    ntf_subscriber: None,
                });
                s.by_snd.insert(snd_id.clone(), rcv_id.clone());
            }
            vec![resp_np!(t.corr_id.clone(), vec![], BrokerMsg::Ids {
                rcv_id, snd_id, rcv_dh_key: srv_dh_der,
                queue_mode: None, link_id: None, service_id: None, ntf_creds: None,
            })]
        }
        Command::Sub => {
            let rcv_id = t.entity_id.clone();
            let mut s = lock_state(st);
            let Some(q) = s.by_rcv.get_mut(&rcv_id) else {
                return vec![err_np!(t.corr_id.clone(), rcv_id, "AUTH")];
            };
            if !qauth(session_id, t, q, ctx) {
                return vec![err_np!(t.corr_id.clone(), rcv_id, "AUTH")];
            }
            q.subscriber = Some(outbox.clone());
            let mut out = vec![resp_np!(t.corr_id.clone(), rcv_id.clone(), BrokerMsg::Sok(None))];
            while let Some((mid, body)) = q.messages.pop_front() {
                let enc = match encrypt_for_recipient(&q.rcv_dh_secret, &mid, &body) {
                    Ok(e) => e,
                    Err(_) => {
                        // v0.21: oversized msg breaks the queue — drop it, reply ERR to client
                        let _ = q.messages.clear();
                        return vec![err_np!(t.corr_id.clone(), rcv_id, "INTERNAL")]
                    }
                };
                out.push(resp_np!(random_bytes(24), rcv_id.clone(), BrokerMsg::Msg { msg_id: mid, body: enc }));
            }
            out
        }
        Command::Get => {
            let rcv_id = t.entity_id.clone();
            let mut s = lock_state(st);
            let Some(q) = s.by_rcv.get_mut(&rcv_id) else {
                return vec![err_np!(t.corr_id.clone(), rcv_id, "AUTH")];
            };
            if !qauth(session_id, t, q, ctx) {
                return vec![err_np!(t.corr_id.clone(), rcv_id, "AUTH")];
            }
            match q.messages.pop_front() {
                Some((mid, body)) => {
                    let enc = match encrypt_for_recipient(&q.rcv_dh_secret, &mid, &body) {
                        Ok(e) => e,
                        Err(_) => return vec![err_np!(t.corr_id.clone(), rcv_id, "INTERNAL")]
                    };
                    vec![resp_np!(t.corr_id.clone(), rcv_id, BrokerMsg::Msg { msg_id: mid, body: enc })]
                }
                None => vec![resp_np!(t.corr_id.clone(), rcv_id, BrokerMsg::Sok(None))],
            }
        }
        Command::Send { flags, body } => {
            // v0.21: oversized body checked inside dispatch_cmd (wrapped in catch_unwind) → ERR INTERNAL
            // instead of panic; the actual size validation happens on encrypt_for_recipient.
            let snd_id = t.entity_id.clone();
            let rcv_id = {
                let s = lock_state(st);
                let Some(rcv_id) = s.by_snd.get(&snd_id).cloned() else {
                    return vec![err_np!(t.corr_id.clone(), snd_id, "AUTH")];
                };
                rcv_id
            };
            let mut s = lock_state(st);
            let Some(q) = s.by_rcv.get_mut(&rcv_id) else {
                return vec![err_np!(t.corr_id.clone(), snd_id, "AUTH")];
            };
            if let Some(snd_raw) = &q.snd_auth {
                if !verify_sign(session_id, t, snd_raw) {
                    return vec![err_np!(t.corr_id.clone(), vec![], "AUTH bad signature")];
                }
            }
            let msg_id = random_bytes(16);
            q.messages.push_back((msg_id.clone(), body.clone()));
            if let Some(sub) = &q.subscriber {
                // v0.21: oversized message — drop it, deliver ERR INTERNAL via push pipe (no panic)
                match encrypt_for_recipient(&q.rcv_dh_secret, &msg_id, &body) {
                    Ok(enc) => {
                        if let msg_t = resp_np!(random_bytes(24), rcv_id.clone(), BrokerMsg::Msg { msg_id: msg_id.clone(), body: enc }) {
                            if let Ok(wire) = encode_transmission(&msg_t) {
                                let _ = sub.send(wire);
                            }
                        }
                    }
                    Err(_) => {
                        // v0.21: oversized message — drop it, deliver ERR INTERNAL via push pipe (no panic)
                        let _ = q.messages.pop_back();
                        if let Ok(w) = encode_transmission(
                            &err_np!(random_bytes(24), rcv_id.clone(), "INTERNAL"),
                        ) {
                            let _ = sub.send(w);
                        }
                    }
                }
            }
            // NTF: if notifications enabled and SEND has notify flag, push NMSG to notifier subscriber
            if flags {
                if let (Some(ntf_secret), Some(ntf_sub)) = (&q.rcv_ntf_dh_secret, &q.ntf_subscriber) {
                    let nonce = random_bytes(24);
                    let mut meta = Vec::new();
                    crate::encoding::w_short(&mut meta, &msg_id);
                    let ts = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs() as i64)
                        .unwrap_or(0);
                    crate::encoding::w_i64(&mut meta, ts);
                    if let Ok(padded) = crate::encoding::pad(&meta, 128) {
                        let mut n24 = [0u8; 24];
                        n24.copy_from_slice(&nonce);
                        let enc_meta = secretbox_encrypt(ntf_secret, &n24, &padded);
                        if let ntf_t = resp_np!(random_bytes(24), q.ntf_id.clone().unwrap_or_default(), BrokerMsg::Nmsg { nonce, enc_meta }) {
                            if let Ok(wire) = encode_transmission(&ntf_t) {
                                let _ = ntf_sub.send(wire);
                            }
                        }
                    }
                }
            }
            vec![resp_np!(t.corr_id.clone(), snd_id, BrokerMsg::Ok)]
        }
        Command::Ack(msg_id) => {
            let rcv_id = t.entity_id.clone();
            let mut s = lock_state(st);
            let Some(q) = s.by_rcv.get_mut(&rcv_id) else {
                return vec![err_np!(t.corr_id.clone(), rcv_id, "AUTH")];
            };
            if !qauth(session_id, t, q, ctx) {
                return vec![err_np!(t.corr_id.clone(), rcv_id, "AUTH")];
            }
            q.messages.retain(|(m, _)| *m != msg_id);
            vec![resp_np!(t.corr_id.clone(), rcv_id, BrokerMsg::Ok)]
        }
        Command::Key(k) | Command::Skey(k) => {
            let rcv_id = t.entity_id.clone();
            let mut s = lock_state(st);
            let Some(q) = s.by_rcv.get_mut(&rcv_id) else {
                return vec![err_np!(t.corr_id.clone(), rcv_id, "AUTH")];
            };
            let is_recipient = tag_of(&t.command) == "KEY";
            let key_ok = if is_recipient {
                qauth(session_id, t, q, ctx)
            } else {
                q.snd_auth.map(|r| verify_sign(session_id, t, &r)).unwrap_or(true)
            };
            if !key_ok {
                return vec![err_np!(t.corr_id.clone(), rcv_id, "AUTH")];
            }
            if let Ok((_alg, raw)) = parse_spki(&k) {
                q.snd_auth = Some(raw);
            }
            vec![resp_np!(t.corr_id.clone(), rcv_id, BrokerMsg::Ok)]
        }
        Command::Del => {
            let rcv_id = t.entity_id.clone();
            let mut s = lock_state(st);
            let Some(q) = s.by_rcv.get_mut(&rcv_id) else {
                return vec![err_np!(t.corr_id.clone(), rcv_id, "AUTH")];
            };
            if !qauth(session_id, t, q, ctx) {
                return vec![err_np!(t.corr_id.clone(), rcv_id, "AUTH")];
            }
            let snd = q.snd_id.clone();
            if let Some(nid) = q.ntf_id.take() {
                let s = &mut *s;
                s.by_ntf.remove(&nid);
                s.by_rcv.remove(&rcv_id);
                s.by_snd.remove(&snd);
            } else {
                let s = &mut *s;
                s.by_rcv.remove(&rcv_id);
                s.by_snd.remove(&snd);
            }
            vec![resp_np!(t.corr_id.clone(), rcv_id, BrokerMsg::Deld)]
        }
        Command::Off => vec![resp_np!(t.corr_id.clone(), t.entity_id.clone(), BrokerMsg::Ok)],
        Command::Ping => vec![resp_np!(t.corr_id.clone(), vec![], BrokerMsg::Pong)],
        Command::Fnew { size, digest, sender_key } => {
            let (_alg, sender_raw) = match parse_spki(&sender_key) {
                Ok(v) => v,
                Err(e) => return vec![err_np!(t.corr_id.clone(), vec![], &format!("AUTH {e}"))],
            };
            if !verify_sign(session_id, t, &sender_raw) {
                return vec![err_np!(t.corr_id.clone(), vec![], "AUTH bad signature")];
            }
            let packet_id = random_bytes(16);
            lock_state(st).xftp.insert(
                packet_id.clone(),
                crate::xftp::XftpPacket { size, digest, sender_raw, chunks: Default::default() },
            );
            vec![resp_np!(t.corr_id.clone(), vec![], BrokerMsg::Fid { packet_id })]
        }
        Command::Fput { packet_id, offset, chunk } => {
            let mut g = lock_state(st);
            let Some(p) = g.xftp.get(&packet_id) else {
                return vec![err_np!(t.corr_id.clone(), vec![], "NO_FILE")];
            };
            if !verify_sign(session_id, t, &p.sender_raw) {
                return vec![err_np!(t.corr_id.clone(), vec![], "AUTH bad signature")];
            }
            let Some(p) = g.xftp.get_mut(&packet_id) else {
                return vec![err_np!(t.corr_id.clone(), vec![], "NO_FILE")];
            };
            p.chunks.insert(offset, chunk);
            drop(g);
            vec![resp_np!(t.corr_id.clone(), vec![], BrokerMsg::Ok)]
        }
        Command::Fget { packet_id, offset } => {
            let g = lock_state(st);
            let Some(p) = g.xftp.get(&packet_id) else {
                return vec![err_np!(t.corr_id.clone(), vec![], "NO_FILE")];
            };
            // as many chunks as fit into one 16KB block starting at `offset` (15KB chunk -> 1 per block)
            let mut out = Vec::new();
            let mut size = 0usize;
            for (off, ch) in p.chunks.range(offset..) {
                let need = 8 + ch.len(); // approx transmission overhead + FDATA
                if !out.is_empty() && size + need > 16000 {
                    break;
                }
                size += need;
                if let r = resp_np!(t.corr_id.clone(), vec![], BrokerMsg::Fdata { offset: *off, chunk: ch.clone() }) {
                    out.push(r);
                }
            }
            if out.is_empty() {
                out.push(err_np!(t.corr_id.clone(), vec![], "NO_FILE"));
            }
            out
        }
        Command::Fdel { packet_id } => {
            let mut g = lock_state(st);
            let Some(p) = g.xftp.get(&packet_id) else {
                return vec![err_np!(t.corr_id.clone(), vec![], "NO_FILE")];
            };
            if !verify_sign(session_id, t, &p.sender_raw) {
                return vec![err_np!(t.corr_id.clone(), vec![], "AUTH bad signature")];
            }
            g.xftp.remove(&packet_id);
            drop(g);
            vec![resp_np!(t.corr_id.clone(), vec![], BrokerMsg::Ok)]
        }
        Command::Proxy { host, port, .. } => {
            let host = String::from_utf8_lossy(&host).to_string();
            let port: u16 = String::from_utf8_lossy(&port).parse().unwrap_or(0);
            // connect to destination router as a proxy client (plain TCP for now)
            let dest_kh = [0u8; 32]; // plain mode: no keyHash pinning between our engines
            match crate::proxy::open_proxy_session(&host, port, &dest_kh) {
                Ok(conn) => {
                    let proxy_id = random_bytes(24);
                    let pkey = BrokerMsg::Pkey {
                        session_id: proxy_id.clone(),
                        v_min: conn.v_min,
                        v_max: conn.v_max,
                        cert_key: spki_x25519(&conn.dest_session_pub),
                    };
                    lock_state(st).proxies.insert(proxy_id.clone(), Arc::new(Mutex::new(conn)));
                    vec![resp_np!(t.corr_id.clone(), vec![], pkey)]
                }
                Err(e) => vec![err_np!(t.corr_id.clone(), vec![], &format!("PROXY {e}"))],
            }
        }
        Command::Pfwd { version, command_key, enc } => {
            let proxy_id = t.entity_id.clone();
            let conn = lock_state(st).proxies.get(&proxy_id).cloned();
            let Some(conn) = conn else {
                return vec![err_np!(t.corr_id.clone(), proxy_id, "NO_AUTH")];
            };
            match crate::proxy::relay_pfwd(&conn, &t.corr_id, version, &command_key, &enc) {
                Ok(client_enc_resp) => vec![resp_np!(t.corr_id.clone(), proxy_id, BrokerMsg::Pres { enc: client_enc_resp })],
                Err(e) => vec![err_np!(t.corr_id.clone(), proxy_id, &format!("PROXY {e}"))],
            }
        }
        Command::Rfwd { enc } => {
            let Some(sess) = ctx.sess_secret else {
                return vec![err_np!(t.corr_id.clone(), vec![], "NO_AUTH")];
            };
            let Some(eph_priv) = &ctx.server_eph_priv else {
                return vec![err_np!(t.corr_id.clone(), vec![], "NO_AUTH")];
            };
            let st2 = st.clone();
            let sid = session_id.to_vec();
            let outbox2 = outbox.clone();
            let ctx2 = ConnCtx { sess_secret: Some(sess), server_eph_priv: None };
            match crate::proxy::handle_rfwd(&enc, &t.corr_id, &sess, eph_priv, session_id, &move |inner| {
                dispatch(inner, &st2, &sid, &outbox2, &ctx2)
            }) {
                Ok(rres_enc) => vec![resp_np!(t.corr_id.clone(), vec![], BrokerMsg::Rres { enc: rres_enc })],
                Err(e) => vec![err_np!(t.corr_id.clone(), vec![], &format!("CRYPTO {e}"))],
            }
        }
        Command::Nkey { ntf_key, rcv_ntf_dh_key } => {
            // recipient-signed, entity = rcv_id
            let rcv_id = t.entity_id.clone();
            let mut g = lock_state(st);
            let s = &mut *g;
            let Some(q) = s.by_rcv.get_mut(&rcv_id) else {
                return vec![err_np!(t.corr_id.clone(), rcv_id, "AUTH")];
            };
            if !qauth(session_id, t, q, ctx) {
                return vec![err_np!(t.corr_id.clone(), rcv_id, "AUTH")];
            }
            let (_alg, ntf_raw) = match parse_spki(&ntf_key) {
                Ok(x) => x,
                Err(_) => return vec![err_np!(t.corr_id.clone(), rcv_id, "AUTH")],
            };
            let (_dh_alg, rcv_ntf_dh_raw) = match parse_spki(&rcv_ntf_dh_key) {
                Ok(x) => x,
                Err(_) => return vec![err_np!(t.corr_id.clone(), rcv_id, "CMD SYNTAX")],
            };
            let srv_ntf = x25519_keypair();
            let rcv_ntf_dh_secret = x25519_dh(&srv_ntf.secret, &x25519_public(rcv_ntf_dh_raw));
            let ntf_id = random_bytes(16);
            let srv_ntf_dh_der = spki_x25519(&srv_ntf.public.to_bytes());
            q.ntf_id = Some(ntf_id.clone());
            q.ntf_auth_raw = Some(ntf_raw);
            q.rcv_ntf_dh_secret = Some(rcv_ntf_dh_secret);
            s.by_ntf.insert(ntf_id.clone(), rcv_id.clone());
            vec![resp_np!(t.corr_id.clone(), rcv_id, BrokerMsg::Nid { ntf_id, srv_ntf_dh: srv_ntf_dh_der })]
        }
        Command::Nsub => {
            // notifier-key-signed, entity = ntf_id
            let ntf_id = t.entity_id.clone();
            let mut s = lock_state(st);
            let rcv_id = match s.by_ntf.get(&ntf_id) {
                Some(r) => r.clone(),
                None => return vec![err_np!(t.corr_id.clone(), ntf_id, "AUTH")],
            };
            let Some(q) = s.by_rcv.get_mut(&rcv_id) else {
                return vec![err_np!(t.corr_id.clone(), ntf_id, "AUTH")];
            };
            let Some(ntf_raw) = q.ntf_auth_raw else {
                return vec![err_np!(t.corr_id.clone(), ntf_id, "AUTH")];
            };
            if !verify_sign(session_id, t, &ntf_raw) {
                return vec![err_np!(t.corr_id.clone(), ntf_id, "AUTH")];
            }
            q.ntf_subscriber = Some(outbox.clone());
            vec![resp_np!(t.corr_id.clone(), ntf_id, BrokerMsg::Sok(None))]
        }
        Command::Ndel => {
            let rcv_id = t.entity_id.clone();
            let mut g = lock_state(st);
            let s = &mut *g;
            let Some(q) = s.by_rcv.get_mut(&rcv_id) else {
                return vec![err_np!(t.corr_id.clone(), rcv_id, "AUTH")];
            };
            if !qauth(session_id, t, q, ctx) {
                return vec![err_np!(t.corr_id.clone(), rcv_id, "AUTH")];
            }
            if let Some(nid) = q.ntf_id.take() {
                s.by_ntf.remove(&nid);
            }
            q.ntf_auth_raw = None;
            q.rcv_ntf_dh_secret = None;
            q.ntf_subscriber = None;
            vec![resp_np!(t.corr_id.clone(), rcv_id, BrokerMsg::Ok)]
        }
    }
}

fn io_err<E: std::fmt::Display>(e: E) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())
}

/// One connection: blocking SMP/TLS handshake, then a poll pump (50 ms read timeout)
/// that reads commands and drains the outbox of pushed transmissions.
pub fn handle_conn(tcp: std::net::TcpStream, mode: &Mode, st: Arc<Mutex<ServerState>>) -> std::io::Result<()> {
    let ctrl = tcp.try_clone()?;
    let mut stream: BoxStream = match mode {
        Mode::Plain => Box::new(tcp),
        Mode::Tls(cfg) => match rustls::ServerConnection::new(cfg.clone()) {
            Ok(c) => Box::new(rustls::StreamOwned::new(c, tcp)),
            Err(e) => return Err(io_err(e)),
        },
    };
    let session_id: Vec<u8> = Vec::new();
    // --- phase 1: blocking handshake (drives the TLS handshake too) ---
    // per-connection ephemeral X25519 key for proxy sessions (authPubKey in server hello)
    let eph = x25519_keypair();
    let eph_pub = eph.public.to_bytes();
    let hello = server_hello_block_key(SMP_VERSION, SMP_VERSION, &session_id, Some(&eph_pub)).map_err(io_err)?;
    write_block(&mut stream, &hello)?;
    let ch = read_block(&mut stream)?;
    let (v, _kh, _proxy, client_auth) = parse_client_hello_key(&ch).map_err(io_err)?;
    if v != SMP_VERSION {
        return Err(io_err(format!("version {v} != {SMP_VERSION}")));
    }
    let ctx = ConnCtx {
        sess_secret: client_auth.and_then(|der| {
            parse_spki(&der)
                .ok()
                .map(|(_a, raw)| x25519_dh(&eph.secret, &x25519_public(raw)))
        }),
        server_eph_priv: Some(eph.secret),
    };
    // --- phase 2: poll pump ---
    ctrl.set_read_timeout(Some(Duration::from_millis(50)))?;
    let (tx, rx) = mpsc::channel::<Vec<u8>>();
    let mut rbuf = vec![0u8; BLOCK_SIZE];
    let mut rpos = 0usize;
    loop {
        // drain outbox (pushes from SEND on other connections)
        let mut pushes: Vec<Vec<u8>> = Vec::new();
        while let Ok(w) = rx.try_recv() {
            pushes.push(w);
        }
        if !pushes.is_empty() {
            let blk = encode_block(&pushes).map_err(io_err)?;
            if write_block(&mut stream, &blk).is_err() {
                break;
            }
        }
        // one non-blocking read attempt
        match stream.read(&mut rbuf[rpos..]) {
            Ok(0) => break,
            Ok(n) => {
                rpos += n;
                if rpos == BLOCK_SIZE {
                    let wires = match decode_block(&rbuf) {
                        Ok(w) => w,
                        Err(_) => {
                            rpos = 0;
                            continue;
                        }
                    };
                    let mut responses: Vec<Vec<u8>> = Vec::new();
                    for w in &wires {
                        let t = match decode_transmission(w) {
                            Ok(t) => t,
                            Err(_) => continue,
                        };
                        // v0.18 robustness: a malformed command must never kill the
                        // connection — a panic inside dispatch becomes ERR INTERNAL.
                        let dispatched = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            dispatch(&t, &st, &session_id, &tx, &ctx)
                        }));
                        match dispatched {
                            Ok(rs) => {
                                for r in rs {
                                    if let Ok(enc) = encode_transmission(&r) {
                                        responses.push(enc);
                                    }
                                }
                            }
                            Err(_) => {
                                if let Ok(enc) = encode_transmission(
                                    &err_resp(t.corr_id.clone(), t.entity_id.clone(), "INTERNAL").unwrap_or_else(|_| {
                                        // err_resp is infallible for reasonable sizes; fall back to empty
                                        Transmission { authenticator: vec![], corr_id: t.corr_id.clone(), entity_id: t.entity_id.clone(), command: b"ERR INTERNAL".to_vec() }
                                    }),
                                ) {
                                    responses.push(enc);
                                }
                            }
                        }
                    }
                    if !responses.is_empty() {
                        let out = encode_block(&responses).map_err(io_err)?;
                        if write_block(&mut stream, &out).is_err() {
                            break;
                        }
                    }
                    // v0.23: flush pushes that arrived while we were dispatching — otherwise a
                    // peer blocked in recv_block can starve (flaky "failed to fill whole buffer").
                    let mut late: Vec<Vec<u8>> = Vec::new();
                    while let Ok(w) = rx.try_recv() {
                        late.push(w);
                    }
                    if !late.is_empty() {
                        if let Ok(lb) = encode_block(&late) {
                            if write_block(&mut stream, &lb).is_err() {
                                break;
                            }
                        }
                    }
                    rpos = 0;
                }
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(_) => break,
        }
        thread::sleep(Duration::from_millis(2));
    }
    Ok(())
}

#[derive(Clone)]
pub enum Mode {
    Plain,
    Tls(Arc<rustls::ServerConfig>),
}

/// The server engine: a bound listener + shared state + transport mode.
pub struct Engine {
    pub listener: TcpListener,
    pub state: Arc<Mutex<ServerState>>,
    pub mode: Mode,
    pub identity: Option<RouterIdentity>,
    pub host: String,
    pub shutdown: Arc<AtomicBool>,
}

impl Engine {
    pub fn bind_plain(addr: &str) -> std::io::Result<Engine> {
        Self::bind_plain_store(addr, None)
    }

    pub fn bind_plain_store(addr: &str, store: Option<std::path::PathBuf>) -> std::io::Result<Engine> {
        let listener = TcpListener::bind(addr)?;
        Ok(Engine {
            listener,
            state: match store {
                Some(p) => new_state_persist(p),
                None => new_state(),
            },
            mode: Mode::Plain,
            identity: None,
            host: addr.to_string(),
            shutdown: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Bind with TLS; generates a fresh router identity. `host` goes into the cert SAN
    /// and the printed smp:// address.
    pub fn bind_tls(addr: &str, host: &str) -> Result<Engine, String> {
        Self::bind_tls_store(addr, host, None)
    }

    pub fn bind_tls_store(addr: &str, host: &str, store: Option<std::path::PathBuf>) -> Result<Engine, String> {
        let listener = TcpListener::bind(addr).map_err(|e| e.to_string())?;
        let id = RouterIdentity::generate(host)?;
        let cfg = tls_server_config(&id);
        Ok(Engine {
            listener,
            state: match store {
                Some(p) => new_state_persist(p),
                None => new_state(),
            },
            mode: Mode::Tls(Arc::new((*cfg).clone())),
            identity: Some(id),
            host: host.to_string(),
            shutdown: Arc::new(AtomicBool::new(false)),
        })
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// smp://<keyHash>@<host>:<port>  (TLS mode only)
    pub fn address(&self) -> Option<String> {
        let id = self.identity.as_ref()?;
        let port = self.local_addr().ok()?.port();
        Some(id.address(&self.host, port))
    }

    pub fn key_hash(&self) -> Option<[u8; 32]> {
        self.identity.as_ref().map(|i| i.key_hash)
    }

    /// Accept loop (blocking). Spawns a pump thread per connection.
    pub fn serve(&self) -> std::io::Result<()> {
        for conn in self.listener.incoming() {
            if self.shutdown.load(Ordering::Relaxed) {
                break;
            }
            let tcp = match conn {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("[engine] incoming: {e}");
                    continue;
                }
            };
            let st = self.state.clone();
            let mode = self.mode.clone();
            thread::spawn(move || {
                let _ = handle_conn(tcp, &mode, st);
            });
        }
        Ok(())
    }
}

// The `serve` above re-accepts; provide a cleaner accept that uses the already-accepted stream.
// (Kept for clarity; tests use spawn_engine.)

/// Spawn the engine on a background thread. Returns (addr, state, shutdown, join).
pub fn spawn_engine(engine: Engine) -> (SocketAddr, Arc<Mutex<ServerState>>, Arc<AtomicBool>, thread::JoinHandle<()>) {
    let addr = engine.local_addr().expect("local addr");
    let state = engine.state.clone();
    let shutdown = engine.shutdown.clone();
    let handle = thread::spawn(move || {
        let _ = engine.serve();
    });
    (addr, state, shutdown, handle)
}

pub fn run(addr: &str) -> std::io::Result<()> {
    let engine = Engine::bind_plain(addr)?;
    eprintln!("[smp-server] listening on {addr} (SMP v{SMP_VERSION}, plain)");
    engine.serve()
}
