//! SMP router engine (server). In-memory queue store, command dispatch, Ed25519
//! signature auth. Transport-agnostic: works over plain TCP or TLS 1.3 (rustls).
//!
//! Concurrency model: one pump thread per connection owns the stream (non-blocking
//! reads). Recipient pushes (MSG) go to a per-connection outbox channel that the
//! pump drains and writes — so a single writer per connection, no TLS split needed.

use std::collections::{HashMap, VecDeque};
use std::io::Read;
use std::net::{SocketAddr, TcpListener};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::Duration;

use crate::sb_chain::{decrypt_block, strict_keys, write_block_encrypted};
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
    /// store encryption key, kept next to the path it belongs to (P1-5: wiped on drop)
    pub persist_key: Option<crate::store::StoreKey>,
    /// persisted router identity (P0-4: the smp:// keyHash must survive a restart)
    pub identity: Option<crate::identity::StoredIdentity>,
    /// stable per-engine server ephemeral key (authPubKey in every server hello),
    /// so onion hops can be addressed by this pub across connections
    pub eph_secret: [u8; 32],
    pub eph_pub: [u8; 32],
    /// U-05 (audit #3): monotonic revision of REAL mutations + last persisted revision.
    /// Not serialized — both start at 0 after a load, so the first mutation persists.
    pub revision: u64,
    pub persisted_revision: u64,
}

/// Serializes store snapshots+writes across connection threads (U-05): without it,
/// a stale snapshot can rename over a newer one (silent state rollback on disk).
static PERSIST_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Per-connection proxy context (session key from hello exchange).
pub struct ConnCtx {
    pub sess_secret: Option<[u8; 32]>,
    pub server_eph_priv: Option<x25519_dalek::StaticSecret>,
    /// most recent PROXY session opened on this connection (for onion-nested PFWD
    /// with empty entity_id: the inner [Proxy, Pfwd] pair is dispatched atomically)
    pub last_proxy: std::sync::Arc<std::sync::Mutex<Option<Vec<u8>>>>,
    /// Whether this engine may proxy to local/private destinations.
    ///
    /// Per-connection context derived from the engine setting, so the SSRF guard
    /// never depends on the process environment.
    pub allow_local_proxy: bool,
}

impl ServerState {
    pub fn new() -> Self {
        let kp = x25519_keypair();
        ServerState { by_rcv: HashMap::new(), by_snd: HashMap::new(), by_ntf: HashMap::new(), proxies: HashMap::new(), xftp: HashMap::new(), persist: None, persist_key: None, identity: None, eph_secret: kp.secret.to_bytes(), eph_pub: kp.public.to_bytes(), revision: 0, persisted_revision: 0 }
    }
    pub fn persist_now(&self) {
        if let Some(p) = &self.persist {
            // A failed persist must be visible: swallowing it means the server keeps
            // serving from memory while the on-disk state silently diverges.
            let key = self.persist_key.as_ref().map(|k| *k.as_bytes());
            if let Err(e) = crate::store::save_with_key(p, self, key) {
                eprintln!("smp-server: FAILED to persist store to {}: {e}", p.display());
            }
        }
    }
    /// Serialize + seal the state for persistence. Call while holding the state lock.
    pub fn sealed_store(&self) -> Result<Vec<u8>, String> {
        let key = self.persist_key.as_ref().map(|k| *k.as_bytes());
        crate::store::seal_state(self, key)
    }
}

impl Default for ServerState {
    fn default() -> Self {
        Self::new()
    }
}

pub fn new_state() -> Arc<Mutex<ServerState>> {
    Arc::new(Mutex::new(ServerState::new()))
}

/// Load a persistent server state, FAILING CLOSED if the store file exists but cannot
/// be read (audited as P0-2: starting with an empty state would overwrite the real
/// store on the first mutation).
pub fn new_state_persist(path: std::path::PathBuf) -> Result<Arc<Mutex<ServerState>>, String> {
    let key = crate::store::env_key().map_err(|e| e.to_string())?;
    new_state_persist_with_key(path, key)
}

/// Load a persistent server state with an explicit store key (no env lookup).
pub fn new_state_persist_with_key(path: std::path::PathBuf, key: Option<[u8; 32]>) -> Result<Arc<Mutex<ServerState>>, String> {
    let mut st = crate::store::load_checked_with_key(&path, key)?.unwrap_or_default();
    st.persist = Some(path);
    st.persist_key = key.map(crate::store::StoreKey::from_bytes);
    Ok(Arc::new(Mutex::new(st)))
}

/// Options for an engine that persists its state.
pub struct StoreOpts {
    /// Store encryption key. `None` together with `allow_plain_store == false` is refused (P1-5).
    pub key: Option<crate::store::StoreKey>,
    /// Explicit opt-in to an UNENCRYPTED store (a plaintext store leaks `rcv_dh_secret`).
    pub allow_plain_store: bool,
}

impl StoreOpts {
    /// Key from the environment (`SMP_STORE_KEY_FILE`, then `SMP_STORE_KEY`); plaintext refused.
    pub fn from_env() -> Result<StoreOpts, String> {
        Ok(StoreOpts { key: crate::store::store_key_from_env()?, allow_plain_store: false })
    }
    /// Explicit opt-in to a plaintext store (tests / local debugging only).
    pub fn plain() -> StoreOpts {
        StoreOpts { key: None, allow_plain_store: true }
    }
    fn key_bytes(&self) -> Option<[u8; 32]> {
        self.key.as_ref().map(|k| *k.as_bytes())
    }
}

/// P1-5: a configured store must be encrypted unless the caller explicitly opted in.
fn ensure_store_encryption(path: &std::path::Path, opts: &StoreOpts) -> Result<(), String> {
    if opts.key.is_some() || opts.allow_plain_store {
        return Ok(());
    }
    Err(format!(
        "refusing to persist the store at {} without an encryption key (a plaintext store carries rcv_dh_secret); \
         set SMP_STORE_KEY / SMP_STORE_KEY_FILE, pass --store-key-file, or opt in with --insecure-plain-store",
        path.display()
    ))
}

/// `smp-server init`: create/open a store with a router identity and return the stable
/// `smp://` address (P0-4 — the keyHash must survive restarts).
pub fn init_router_store(bind: &str, host: &str, store: &std::path::Path, opts: StoreOpts) -> Result<String, String> {
    ensure_store_encryption(store, &opts)?;
    let st = new_state_persist_with_key(store.to_path_buf(), opts.key_bytes())?;
    let id = {
        let mut g = st.lock().unwrap();
        match &g.identity {
            Some(sid) => sid.to_router()?,
            None => {
                let id = RouterIdentity::generate(host)?;
                g.identity = Some(crate::identity::StoredIdentity::from_router(&id));
                g.persist_now();
                id
            }
        }
    };
    let port = bind.rsplit(':').next().and_then(|p| p.parse::<u16>().ok()).unwrap_or(5223);
    Ok(id.address(host, port))
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

pub fn encrypt_for_recipient(rcv_dh_secret: &[u8; 32], msg_id: &[u8], body: &[u8]) -> Result<Vec<u8>, EncodeError> {
    let padded = crate::encoding::pad(body, MAX_RCV_MSG_LEN)?;
    secretbox_encrypt(rcv_dh_secret, &cb_nonce(msg_id), &padded).map_err(EncodeError)
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
            // U-07: small-order peer key must fail CLOSED, never derive a predictable secret
            Some(eph) => match x25519_dh_checked(eph, &x25519_public(q.rcv_auth_raw)) {
                Ok(k) => verify_box(session_id, t, &k),
                Err(_) => false,
            },
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
    let mutating = matches!(
        cmd,
        Command::New { .. } | Command::Send { .. } | Command::Ack(_) | Command::Key(_) | Command::Skey(_) | Command::Del
            | Command::Nkey { .. } | Command::Nsub | Command::Ndel
            | Command::Fnew { .. } | Command::Fput { .. } | Command::Fdel { .. }
    );
    let out = dispatch_cmd(cmd, t, st, session_id, outbox, ctx);
    // U-05/H1: persist only on a REAL mutation — a command that came back with ERR
    // changed nothing (e.g. SEND with a foreign snd_id gets ERR AUTH) and must not
    // trigger a full O(N) snapshot + fsync (that was a cheap unauthenticated DoS).
    let mutated = mutating
        && !out.iter().any(|t| matches!(crate::protocol::parse_broker(&t.command), Ok(crate::protocol::BrokerMsg::Err(_))));
    if mutated {
        {
            let mut g = lock_state(st);
            g.revision = g.revision.wrapping_add(1);
        }
        // U-05/H2: serialize snapshot+write under PERSIST_MUTEX and re-check the
        // revision, so a stale snapshot can never rename over a newer one.
        let _pm = PERSIST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let plan = {
            let g = lock_state(st);
            if g.revision > g.persisted_revision {
                (g.persist.clone(), g.sealed_store().ok(), g.revision)
            } else {
                (None, None, 0)
            }
        };
        if let (Some(p), Some(bytes), rev) = plan {
            match crate::store::write_store_bytes(&p, &bytes) {
                Ok(()) => lock_state(st).persisted_revision = rev,
                Err(e) => eprintln!("smp-server: FAILED to persist store to {}: {e}", p.display()),
            }
        }
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
                    Some(eph) => match x25519_dh_checked(eph, &x25519_public(raw)) {
                        Ok(k) => verify_box(session_id, t, &k),
                        Err(_) => false,
                    },
                    None => false,
                },
            };
            if !ok {
                return vec![err_np!(t.corr_id.clone(), vec![], "AUTH")];
            }
            // U-19: rcv_dh_key must be an X25519 SPKI (Ed25519 here would be a protocol violation)
            let (dh_alg, dh_raw) = match parse_spki(&rcv_dh_key) {
                Ok(x) => x,
                Err(_) => return vec![err_np!(t.corr_id.clone(), vec![], "CMD SYNTAX")],
            };
            if dh_alg != AuthAlg::X25519 {
                return vec![err_np!(t.corr_id.clone(), vec![], "CMD SYNTAX")];
            }
            let client_dh_pub = x25519_public(dh_raw);
            let srv = x25519_keypair();
            let rcv_dh_secret = match x25519_dh_checked(&srv.secret, &client_dh_pub) {
                Ok(k) => k,
                Err(e) => return vec![err_np!(t.corr_id.clone(), vec![], &format!("CRYPTO {e}"))],
            };
            let rcv_id = random_bytes(16);
            let snd_id = random_bytes(24);
            let srv_dh_der = spki_x25519(&srv.public.to_bytes());
            {
                let mut s = lock_state(st);
                // U-19: global queue quota — NEW past the cap is refused (memory bound).
                if s.by_rcv.len() >= MAX_QUEUES {
                    return vec![err_np!(t.corr_id.clone(), vec![], "QUOTA queues")];
                }
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
            // SEC-03: deliver at most one pending message, keep it until ACK; never clear the queue on encrypt error
            if let Some((mid, body)) = q.messages.front() {
                match encrypt_for_recipient(&q.rcv_dh_secret, mid, body) {
                    Ok(enc) => out.push(resp_np!(random_bytes(24), rcv_id.clone(), BrokerMsg::Msg { msg_id: mid.clone(), body: enc })),
                    Err(_) => return vec![err_np!(t.corr_id.clone(), rcv_id, "INTERNAL")],
                }
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
            match q.messages.front() {
                Some((mid, body)) => {
                    match encrypt_for_recipient(&q.rcv_dh_secret, mid, body) {
                        Ok(enc) => vec![resp_np!(t.corr_id.clone(), rcv_id.clone(), BrokerMsg::Msg { msg_id: mid.clone(), body: enc })],
                        Err(_) => vec![err_np!(t.corr_id.clone(), rcv_id, "INTERNAL")],
                    }
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
            // SEC-08: validate on input, never poison the queue with an undeliverable message
            if body.len() > 16088 {
                return vec![err_np!(t.corr_id.clone(), snd_id, "LARGE_MSG")];
            }
            // P1: bounded offline queue — fail closed instead of growing memory unbounded
            if q.messages.len() >= MAX_QUEUE_MSGS {
                return vec![err_np!(t.corr_id.clone(), snd_id, "QUEUE_FULL")];
            }
            let msg_id = random_bytes(16);
            q.messages.push_back((msg_id.clone(), body.clone()));
            if let Some(sub) = &q.subscriber {
                // v0.21: oversized message — drop it, deliver ERR INTERNAL via push pipe (no panic)
                match encrypt_for_recipient(&q.rcv_dh_secret, &msg_id, &body) {
                    Ok(enc) => {
                        let msg_t = resp_np!(random_bytes(24), rcv_id.clone(), BrokerMsg::Msg { msg_id: msg_id.clone(), body: enc });
                        if let Ok(wire) = encode_transmission(&msg_t) {
                            let _ = sub.send(wire);
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
                    let _ = crate::encoding::w_short(&mut meta, &msg_id);
                    let ts = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs() as i64)
                        .unwrap_or(0);
                    crate::encoding::w_i64(&mut meta, ts);
                    if let Ok(padded) = crate::encoding::pad(&meta, 128) {
                        let mut n24 = [0u8; 24];
                        n24.copy_from_slice(&nonce);
                        // FAIL-CLOSED: never push a notification whose payload could not
                        // be encrypted — a zero-filled "ciphertext" would be accepted by
                        // the client as a valid message.
                        match secretbox_encrypt(ntf_secret, &n24, &padded) {
                            Ok(enc_meta) => {
                                let ntf_t = resp_np!(random_bytes(24), q.ntf_id.clone().unwrap_or_default(), BrokerMsg::Nmsg { nonce, enc_meta });
                                if let Ok(wire) = encode_transmission(&ntf_t) {
                                    let _ = ntf_sub.send(wire);
                                }
                            }
                            Err(e) => eprintln!("smp-server: NMSG encrypt failed: {e}"),
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
        Command::Key(k) => {
            // Recipient auth-key rotation. entity = rcv_id; must pass the CURRENT
            // recipient auth (qauth). Updates rcv_auth_raw / rcv_auth_x.
            let rcv_id = t.entity_id.clone();
            let mut s = lock_state(st);
            let Some(q) = s.by_rcv.get_mut(&rcv_id) else {
                return vec![err_np!(t.corr_id.clone(), rcv_id, "AUTH")];
            };
            if !qauth(session_id, t, q, ctx) {
                return vec![err_np!(t.corr_id.clone(), rcv_id, "AUTH")];
            }
            match parse_spki(&k) {
                Ok((alg, raw)) => {
                    q.rcv_auth_x = alg == AuthAlg::X25519;
                    q.rcv_auth_raw = raw;
                    vec![resp_np!(t.corr_id.clone(), rcv_id, BrokerMsg::Ok)]
                }
                // U-04: a malformed key must be a hard CMD SYNTAX, never a silent Ok
                Err(_) => vec![err_np!(t.corr_id.clone(), rcv_id, "CMD SYNTAX")],
            }
        }
        Command::Skey(k) => {
            // U-04/H12: SKEY is addressed by the SENDER id (entity = snd_id) and the
            // signature is MANDATORY. The old code looked the queue up by rcv_id —
            // but rcv_id travels in invitation links, so anyone knowing it could bind
            // their own snd_auth via `.unwrap_or(true)` and lock out the real sender.
            let snd_id = t.entity_id.clone();
            let mut s = lock_state(st);
            let Some(rcv_id) = s.by_snd.get(&snd_id).cloned() else {
                return vec![err_np!(t.corr_id.clone(), snd_id, "AUTH")];
            };
            let Some(q) = s.by_rcv.get_mut(&rcv_id) else {
                return vec![err_np!(t.corr_id.clone(), rcv_id, "AUTH")];
            };
            let (alg, raw) = match parse_spki(&k) {
                Ok(x) => x,
                Err(_) => return vec![err_np!(t.corr_id.clone(), snd_id, "CMD SYNTAX")],
            };
            // snd_auth is a signing key — Ed25519 only
            if alg != AuthAlg::Ed25519 {
                return vec![err_np!(t.corr_id.clone(), snd_id, "CMD SYNTAX")];
            }
            // rotation: signed by the OLD key; first binding: signed by the NEW key
            let key_ok = match &q.snd_auth {
                Some(old) => verify_sign(session_id, t, old),
                None => verify_sign(session_id, t, &raw),
            };
            if !key_ok {
                return vec![err_np!(t.corr_id.clone(), snd_id, "AUTH")];
            }
            q.snd_auth = Some(raw);
            vec![resp_np!(t.corr_id.clone(), snd_id, BrokerMsg::Ok)]
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
            // U-19: XFTP quotas — per-file size, packet count, aggregate declared bytes.
            if size > MAX_XFTP_FILE_SIZE {
                return vec![err_np!(t.corr_id.clone(), vec![], "QUOTA file size")];
            }
            {
                let g = lock_state(st);
                if g.xftp.len() >= MAX_XFTP_PACKETS {
                    return vec![err_np!(t.corr_id.clone(), vec![], "QUOTA packets")];
                }
                let total: u64 = g.xftp.values().map(|p| p.size).sum();
                if total.saturating_add(size) > MAX_XFTP_TOTAL {
                    return vec![err_np!(t.corr_id.clone(), vec![], "QUOTA total")];
                }
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
            // U-19: Fput validation — chunk size, chunk-index range, chunk count.
            // NOTE: `offset` is a CHUNK INDEX (u32), not a byte offset — upload_file
            // sends i as u32 and Fget ranges over chunk indices.
            if chunk.len() > MAX_XFTP_CHUNK {
                return vec![err_np!(t.corr_id.clone(), vec![], "QUOTA chunk size")];
            }
            if offset as usize >= MAX_XFTP_CHUNKS {
                return vec![err_np!(t.corr_id.clone(), vec![], "QUOTA offset")];
            }
            if p.chunks.len() >= MAX_XFTP_CHUNKS && !p.chunks.contains_key(&offset) {
                return vec![err_np!(t.corr_id.clone(), vec![], "QUOTA chunks")];
            }
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
                out.push(resp_np!(t.corr_id.clone(), vec![], BrokerMsg::Fdata { offset: *off, chunk: ch.clone() }));
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
            if let Err(e) = guard_proxy_dest(&host, port, ctx.allow_local_proxy) {
                return vec![err_np!(t.corr_id.clone(), vec![], &e)];
            }
            // U-19: cap proxy sessions per engine.
            if lock_state(st).proxies.len() >= MAX_PROXIES {
                return vec![err_np!(t.corr_id.clone(), vec![], "QUOTA proxies")];
            }
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
                    *ctx.last_proxy.lock().unwrap_or_else(|e| e.into_inner()) = Some(proxy_id.clone());
                    vec![resp_np!(t.corr_id.clone(), vec![], pkey)]
                }
                Err(e) => vec![err_np!(t.corr_id.clone(), vec![], &format!("PROXY {e}"))],
            }
        }
        Command::Pfwd { version, command_key, enc } => {
            // onion nesting: empty entity_id = the proxy session just opened on this
            // connection by the preceding inner Proxy command
            let proxy_id = if t.entity_id.is_empty() {
                ctx.last_proxy.lock().unwrap_or_else(|e| e.into_inner()).clone().unwrap_or_default()
            } else {
                t.entity_id.clone()
            };
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
            // U-04/F-06: keep server_eph_priv — inner commands on X25519-auth queues
            // (qauth/verify_box) got a guaranteed AUTH with None.
            let ctx2 = ConnCtx { sess_secret: Some(sess), server_eph_priv: ctx.server_eph_priv.clone(), last_proxy: ctx.last_proxy.clone(), allow_local_proxy: ctx.allow_local_proxy };
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
            let (ntf_dh_alg, rcv_ntf_dh_raw) = match parse_spki(&rcv_ntf_dh_key) {
                Ok(x) => x,
                Err(_) => return vec![err_np!(t.corr_id.clone(), rcv_id, "CMD SYNTAX")],
            };
            if ntf_dh_alg != AuthAlg::X25519 {
                return vec![err_np!(t.corr_id.clone(), rcv_id, "CMD SYNTAX")];
            }
            let srv_ntf = x25519_keypair();
            let rcv_ntf_dh_secret = match x25519_dh_checked(&srv_ntf.secret, &x25519_public(rcv_ntf_dh_raw)) {
                Ok(k) => k,
                Err(e) => return vec![err_np!(t.corr_id.clone(), rcv_id, &format!("CRYPTO {e}"))],
            };
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

/// Write a batch of pushed wires as a single block (strict-encrypted when chain keys active).
/// Callers must chunk wires so the padded content fits BLOCK_SIZE (see pump drain loops).
fn write_push_block(stream: &mut BoxStream, s_snd: Option<&mut [u8; 32]>, wires: &[Vec<u8>]) -> std::io::Result<()> {
    if let Some(k) = s_snd {
        let raw = encode_block_raw(wires).map_err(io_err)?;
        write_block_encrypted(stream, k, &raw)
    } else {
        let blk = encode_block(wires).map_err(io_err)?;
        write_block(stream, &blk)
    }
}

/// One connection: blocking SMP/TLS handshake, then a poll pump (50 ms read timeout)
/// that reads commands and drains the outbox of pushed transmissions.
pub fn handle_conn(
    tcp: std::net::TcpStream,
    mode: &Mode,
    st: Arc<Mutex<ServerState>>,
    strict: bool,
    allow_local_proxy: bool,
) -> std::io::Result<()> {
    let ctrl = tcp.try_clone()?;
    // U-13: handshake slowloris guard — pre-hello reads/writes are bounded; the
    // receive pump later lowers the read timeout to its 50 ms poll.
    ctrl.set_read_timeout(Some(HANDSHAKE_TIMEOUT))?;
    ctrl.set_write_timeout(Some(HANDSHAKE_TIMEOUT))?;
    let mut tls_binding: Option<Vec<u8>> = None;
    let mut stream: BoxStream = match mode {
        Mode::Plain => Box::new(tcp),
        Mode::Tls(cfg) => {
            let mut so = rustls::StreamOwned::new(
                rustls::ServerConnection::new(cfg.clone()).map_err(io_err)?,
                tcp,
            );
            // complete the TLS 1.3 handshake BEFORE the SMP server hello, so that
            // sessionId can be bound to the TLS session
            so.conn.complete_io(&mut so.sock).map_err(io_err)?;
            let mut exporter = [0u8; 32];
            so.conn
                .export_keying_material(&mut exporter, b"SimpleX-channel-binding", None)
                .map_err(io_err)?;
            // rustls cannot expose the TLS 1.3 Finished verify_data that upstream
            // uses as its channel binding, so the session id is bound to the
            // exporter output instead. See `SessionIdBinding`.
            tls_binding = Some(
                derive_session_id(SessionIdBinding::Exporter, &exporter, None)
                    .map_err(io_err)?,
            );
            Box::new(so)
        }
    };
    // in TLS mode sessionId = TLS channel binding; in plain mode it stays empty
    let session_id: Vec<u8> = tls_binding.unwrap_or_default();
    // --- phase 1: blocking handshake (drives the TLS handshake too) ---
    // per-engine stable ephemeral X25519 key (authPubKey in server hello)
    let eph = x25519_from_secret(st.lock().unwrap_or_else(|e| e.into_inner()).eph_secret);
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
                .and_then(|(_a, raw)| x25519_dh_checked(&eph.secret, &x25519_public(raw)).ok())
        }),
        server_eph_priv: Some(eph.secret),
        last_proxy: std::sync::Arc::new(std::sync::Mutex::new(None)),
        allow_local_proxy,
    };
    // strict v23 transport encryption (encryptBlock) — enabled only when client sent authPubKey
    let (mut s_snd, mut s_rcv) = if strict {
        // U-11/F-13: with strict=true the connection must fail CLOSED — a missing
        // authPubKey or a key-derivation error is a hard error, never a silent
        // downgrade to plaintext transport.
        match ctx.sess_secret {
            Some(sec) => match strict_keys(&session_id, &sec, false) {
                Ok((a, b)) => (Some(a), Some(b)),
                Err(e) => return Err(io_err(format!("strict mode: key derivation failed: {e}"))),
            },
            None => return Err(io_err("strict mode: client sent no authPubKey — refusing plaintext connection")),
        }
    } else { (None, None) };
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
            // Each push wire can be near BLOCK_SIZE (encrypted MSG body is padded), so a
            // batch of 2+ pushes overflows one block ("pad overflow") and used to kill the
            // connection via `?`. Fix: greedy chunk into as few blocks as fit, one wire
            // per block when large.
            let mut chunk: Vec<&Vec<u8>> = Vec::new();
            let mut chunk_len = 1usize; // count byte
            for w in &pushes {
                let wl = 2 + w.len(); // w_large
                if chunk_len + wl > BLOCK_SIZE - 2 && !chunk.is_empty() {
                    let owned: Vec<Vec<u8>> = chunk.iter().map(|v| (*v).clone()).collect();
                    let wr = write_push_block(&mut stream, s_snd.as_mut(), &owned);
                    if wr.is_err() { break; }
                    chunk.clear();
                    chunk_len = 1;
                }
                chunk_len += wl;
                chunk.push(w);
            }
            if !chunk.is_empty() {
                let owned: Vec<Vec<u8>> = chunk.iter().map(|v| (*v).clone()).collect();
                if write_push_block(&mut stream, s_snd.as_mut(), &owned).is_err() { break; }
            }
        }
        // one non-blocking read attempt
        match stream.read(&mut rbuf[rpos..]) {
            Ok(0) => break,
            Ok(n) => {
                rpos += n;
                if rpos == BLOCK_SIZE {
                    let wires = if let Some(k) = s_rcv.as_mut() {
                        match decrypt_block(k, &rbuf) {
                            Ok((nk, content)) => { *k = nk; match decode_block_raw(&content) { Ok(w) => w, Err(_) => { rpos = 0; continue; } } }
                            Err(_) => { rpos = 0; continue; }
                        }
                    } else {
                        match decode_block(&rbuf) { Ok(w) => w, Err(_) => { rpos = 0; continue; } }
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
                        // chunk responses into as many blocks as needed (a PKEY + a large
                        // PRES can overflow one block — used to kill the connection)
                        let mut start = 0usize;
                        while start < responses.len() {
                            let mut end = start;
                            let mut len = 1usize;
                            while end < responses.len() {
                                let wl = 2 + responses[end].len();
                                if len + wl > BLOCK_SIZE - 2 && end > start {
                                    break;
                                }
                                len += wl;
                                end += 1;
                            }
                            let out = encode_block(&responses[start..end]).map_err(io_err)?;
                            let wr = if let Some(k) = s_snd.as_mut() {
                                let raw = encode_block_raw(&responses[start..end]).map_err(io_err)?;
                                write_block_encrypted(&mut stream, k, &raw)
                            } else {
                                write_block(&mut stream, &out)
                            };
                            if wr.is_err() { break; }
                            start = end;
                        }
                    }
                    // v0.23: flush pushes that arrived while we were dispatching — otherwise a
                    // peer blocked in recv_block can starve (flaky "failed to fill whole buffer").
                    let mut late: Vec<Vec<u8>> = Vec::new();
                    while let Ok(w) = rx.try_recv() {
                        late.push(w);
                    }
                    // same chunked-write as the main push drain (pad overflow guard)
                    let mut chunk: Vec<&Vec<u8>> = Vec::new();
                    let mut chunk_len = 1usize;
                    for w in &late {
                        let wl = 2 + w.len();
                        if chunk_len + wl > BLOCK_SIZE - 2 && !chunk.is_empty() {
                            let owned: Vec<Vec<u8>> = chunk.iter().map(|v| (*v).clone()).collect();
                            if write_push_block(&mut stream, s_snd.as_mut(), &owned).is_err() { break; }
                            chunk.clear();
                            chunk_len = 1;
                        }
                        chunk_len += wl;
                        chunk.push(w);
                    }
                    if !chunk.is_empty() {
                        let owned: Vec<Vec<u8>> = chunk.iter().map(|v| (*v).clone()).collect();
                        if write_push_block(&mut stream, s_snd.as_mut(), &owned).is_err() { break; }
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
    /// Enable strict v23 transport block encryption for accepted connections.
    ///
    /// This is a per-engine property: it is set once at bind time and never read
    /// from the process environment. The `SMP_STRICT` variable is only consulted
    /// by the binaries as a default for this flag.
    pub strict: bool,
    /// Allow proxying to local/private destinations (SSRF guard opt-in).
    ///
    /// Per-engine for the same reason as `strict`: the previous implementation
    /// read `SMP_ALLOW_LOCAL_PROXY` from the environment on every request.
    pub allow_local_proxy: bool,
    /// U-13: live connection counter + cap; the accept loop drops excess connections.
    pub conns: Arc<std::sync::atomic::AtomicUsize>,
    pub max_conns: usize,
}

impl Engine {
    /// Bind a plain (non-TLS) engine.
    ///
    /// The strict mode and the local-proxy opt-in default to the values of
    /// `SMP_STRICT` / `SMP_ALLOW_LOCAL_PROXY` **at bind time**. They are then
    /// frozen into the engine, so a later change of the environment cannot alter
    /// the behaviour of an already-running server, and two engines in the same
    /// process can have different settings.
    pub fn bind_plain(addr: &str) -> std::io::Result<Engine> {
        let strict = std::env::var("SMP_STRICT").as_deref() == Ok("1");
        let allow_local_proxy = std::env::var_os("SMP_ALLOW_LOCAL_PROXY").is_some();
        Self::bind_plain_with_proxy_and_strict(addr, allow_local_proxy, strict)
    }

    /// Bind a plain engine with an explicit strict-mode setting.
    pub fn bind_plain_with_strict(addr: &str, strict: bool) -> std::io::Result<Engine> {
        Self::bind_plain_with_proxy_and_strict(addr, false, strict)
    }

    /// Bind a plain engine with explicit local-proxy and strict-mode settings.
    ///
    /// Neither value is read from the process environment: the two settings are
    /// frozen into the engine at bind time.
    pub fn bind_plain_with_proxy_and_strict(
        addr: &str,
        allow_local_proxy: bool,
        strict: bool,
    ) -> std::io::Result<Engine> {
        let listener = TcpListener::bind(addr)?;
        Ok(Engine {
            listener,
            state: new_state(),
            mode: Mode::Plain,
            identity: None,
            host: addr.to_string(),
            shutdown: Arc::new(AtomicBool::new(false)),
            strict,
            allow_local_proxy,
            conns: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            max_conns: MAX_CONNS,
        })
    }

    /// Bind a plain engine with a persistent store, taking the strict-mode and
    /// local-proxy defaults from the environment **once**, at bind time.
    pub fn bind_plain_store(addr: &str, store: Option<std::path::PathBuf>) -> std::io::Result<Engine> {
        let opts = StoreOpts::from_env().map_err(std::io::Error::other)?;
        Self::bind_plain_store_opts(addr, store, opts)
    }

    /// Bind a plain engine with a persistent store and explicit store options.
    ///
    /// P1-5: a store without an encryption key is refused unless opted in.
    pub fn bind_plain_store_opts(addr: &str, store: Option<std::path::PathBuf>, opts: StoreOpts) -> std::io::Result<Engine> {
        let strict = std::env::var("SMP_STRICT").as_deref() == Ok("1");
        let allow_local_proxy = std::env::var_os("SMP_ALLOW_LOCAL_PROXY").is_some();
        let mut engine = Self::bind_plain_with_proxy_and_strict(addr, allow_local_proxy, strict)?;
        if let Some(p) = store {
            ensure_store_encryption(&p, &opts).map_err(std::io::Error::other)?;
            engine.state = new_state_persist_with_key(p, opts.key_bytes()).map_err(std::io::Error::other)?;
        }
        Ok(engine)
    }

    /// Bind with TLS; generates a fresh router identity. `host` goes into the cert SAN
    /// and the printed smp:// address.
    pub fn bind_tls(addr: &str, host: &str) -> Result<Engine, String> {
        Self::bind_tls_store(addr, host, None)
    }

    pub fn bind_tls_store(addr: &str, host: &str, store: Option<std::path::PathBuf>) -> Result<Engine, String> {
        let opts = StoreOpts::from_env()?;
        Self::bind_tls_store_opts(addr, host, store, opts)
    }

    /// Bind with TLS and explicit store options.
    ///
    /// P0-4: when a store is configured, the router identity is taken from the store
    /// (or generated once and persisted immediately), so the `smp://` keyHash — and
    /// with it every pinned client address — survives a restart.
    pub fn bind_tls_store_opts(addr: &str, host: &str, store: Option<std::path::PathBuf>, opts: StoreOpts) -> Result<Engine, String> {
        let listener = TcpListener::bind(addr).map_err(|e| e.to_string())?;
        let key = opts.key_bytes();
        let (state, id) = match &store {
            Some(p) => {
                ensure_store_encryption(p, &opts)?;
                let st = new_state_persist_with_key(p.clone(), key)?;
                let id = {
                    let mut g = st.lock().unwrap();
                    match &g.identity {
                        Some(sid) => sid.to_router()?,
                        None => {
                            let id = RouterIdentity::generate(host)?;
                            g.identity = Some(crate::identity::StoredIdentity::from_router(&id));
                            g.persist_now();
                            id
                        }
                    }
                };
                (st, id)
            }
            None => (new_state(), RouterIdentity::generate(host)?),
        };
        let cfg = tls_server_config(&id).map_err(|e| e.to_string())?;
        Ok(Engine {
            listener,
            state,
            mode: Mode::Tls(Arc::new((*cfg).clone())),
            identity: Some(id),
            host: host.to_string(),
            shutdown: Arc::new(AtomicBool::new(false)),
            strict: std::env::var("SMP_STRICT").as_deref() == Ok("1"),
            allow_local_proxy: std::env::var_os("SMP_ALLOW_LOCAL_PROXY").is_some(),
            conns: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            max_conns: MAX_CONNS,
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
        let strict = self.strict;
        let allow_local_proxy = self.allow_local_proxy;
        // `shutdown` must interrupt a *blocking* accept(): with the original
        // code the flag was only checked after `incoming()` returned, i.e. after
        // the next client connected — so a server with no clients could never
        // be stopped.
        //
        // The listening socket stays blocking. Putting it into O_NONBLOCK
        // instead would be wrong on Linux: an accepted socket inherits the
        // listener's O_NONBLOCK, which would leak into every per-connection
        // read path and surface as spurious EAGAIN ("Resource temporarily
        // unavailable") on the client side.
        //
        // Instead a watcher thread polls the flag and, once it is set, opens a
        // throwaway connection to wake the accept loop. The loop then observes
        // the flag and exits.
        let shutdown_flag = self.shutdown.clone();
        let watcher_stop = std::sync::Arc::new(AtomicBool::new(false));
        let watcher_stop_thread = watcher_stop.clone();
        let watcher = self.listener.local_addr().ok().map(|addr| {
            thread::spawn(move || {
                while !watcher_stop_thread.load(Ordering::Relaxed) {
                    if shutdown_flag.load(Ordering::Relaxed) {
                        // Wake the accept loop with a connection it will drop.
                        let _ = std::net::TcpStream::connect(addr);
                        return;
                    }
                    thread::sleep(std::time::Duration::from_millis(50));
                }
            })
        });

        let result = loop {
            if self.shutdown.load(Ordering::Relaxed) {
                break Ok(());
            }
            let tcp = match self.listener.accept() {
                Ok((t, _peer)) => t,
                Err(e) => {
                    if self.shutdown.load(Ordering::Relaxed) {
                        break Ok(());
                    }
                    eprintln!("[engine] incoming: {e}");
                    continue;
                }
            };
            // The wake-up connection (or any connection arriving after the
            // flag was set) must not be served.
            if self.shutdown.load(Ordering::Relaxed) {
                break Ok(());
            };
            // U-13: connection cap — excess connections are dropped BEFORE any
            // thread/handshake work (slowloris / fd-exhaustion guard).
            let cur = self.conns.fetch_add(1, Ordering::Relaxed);
            if cur >= self.max_conns {
                self.conns.fetch_sub(1, Ordering::Relaxed);
                drop(tcp);
                continue;
            }
            let st = self.state.clone();
            let mode = self.mode.clone();
            let conns = self.conns.clone();
            match thread::Builder::new().name("smp-conn".into()).spawn(move || {
                let r = handle_conn(tcp, &mode, st, strict, allow_local_proxy);
                conns.fetch_sub(1, Ordering::Relaxed);
                if let Err(e) = r {
                    if std::env::var_os("SMP_DEBUG").is_some() {
                        eprintln!("[engine] conn error: {e}");
                    }
                }
            }) {
                Ok(_) => {}
                Err(e) => {
                    eprintln!("[engine] failed to spawn conn thread: {e}");
                    self.conns.fetch_sub(1, Ordering::Relaxed);
                }
            }
        };

        watcher_stop.store(true, Ordering::Relaxed);
        if let Some(w) = watcher {
            let _ = w.join();
        }
        result
    }
}

// The `serve` above re-accepts; provide a cleaner accept that uses the already-accepted stream.
// (Kept for clarity; tests use spawn_engine.)

/// Spawn the engine on a background thread. Returns (addr, state, shutdown, join).
pub fn spawn_engine(engine: Engine) -> (SocketAddr, Arc<Mutex<ServerState>>, Arc<AtomicBool>, thread::JoinHandle<()>) {
    let addr = engine.local_addr().unwrap_or_else(|_| SocketAddr::from(([127, 0, 0, 1], 0)));
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


/// U-10/F-08: true when the IP must never be a proxy destination — all non-global
/// ranges, written with explicit octets/segments (no std-helper version drift),
/// including IPv4-mapped IPv6 (::ffff:127.0.0.1 would otherwise reach loopback).
fn ip_is_forbidden(ip: std::net::IpAddr) -> bool {
    use std::net::IpAddr;
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_multicast()
                || v4.is_broadcast()
                || v4.is_unspecified()
                || o[0] == 0 // 0.0.0.0/8 "this host"
                || (o[0] == 100 && (o[1] & 0xC0) == 64) // 100.64.0.0/10 CGNAT
                || (o[0] == 192 && o[1] == 0 && o[2] == 0) // 192.0.0.0/24 IETF
                || (o[0] == 192 && o[1] == 0 && o[2] == 2) // 192.0.2.0/24 TEST-NET-1
                || (o[0] == 198 && (o[1] == 18 || o[1] == 19)) // 198.18.0.0/15 benchmark
                || (o[0] == 198 && o[1] == 51 && o[2] == 100) // 198.51.100.0/24 TEST-NET-2
                || (o[0] == 203 && o[1] == 0 && o[2] == 113) // 203.0.113.0/24 TEST-NET-3
                || (o[0] >= 240) // 240.0.0.0/4 reserved
        }
        IpAddr::V6(v6) => {
            // IPv4-mapped/compatible IPv6 must go through the IPv4 validator
            if let Some(v4) = v6.to_ipv4_mapped() {
                return ip_is_forbidden(IpAddr::V4(v4));
            }
            let s = v6.segments();
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || v6.is_unicast_link_local()
                || (s[0] & 0xFE00) == 0xFC00 // fc00::/7 ULA
                || (s[0] == 0x2001 && s[1] == 0x0DB8) // 2001:db8::/32 documentation
                || (s[0] == 0x2001 && s[1] == 0) // 2001::/32 Teredo
                || s[0] == 0x2002 // 2002::/16 6to4
                || (s[0] == 0x64 && s[1] == 0xFF9B) // 64:ff9b::/96 NAT64
                || (s[0] == 0 && s[1] == 0 && s[2] == 0 && s[3] == 0 && s[4] == 0 && s[5] == 0 && s[6] == 0 && s[7] == 0) // covered by unspecified
        }
    }
}

/// P1: proxy destination guard — only public routers on standard ports, no local/private targets (SSRF guard).
fn guard_proxy_dest(host: &str, port: u16, allow_local_proxy: bool) -> Result<(), String> {
    // local destinations are allowed only when the engine was explicitly opted in
    if allow_local_proxy {
        return Ok(());
    }
    let h = host.trim();
    if h.is_empty() { return Err("PROXY empty host".into()); }
    if !(port == 5223 || port == 443) { return Err("PROXY port not allowed".into()); }
    let lower = h.to_ascii_lowercase();
    if lower == "localhost" || lower.ends_with(".localhost") { return Err("PROXY local host".into()); }
    if let Ok(ip) = h.parse::<std::net::IpAddr>() {
        // U-10: full non-global coverage incl. IPv4-mapped IPv6 (see ip_is_forbidden)
        if ip_is_forbidden(ip) { return Err("PROXY non-public IP".into()); }
        return Ok(());
    }
    // hostname must look like a domain (no spaces/slashes); actual DNS happens in proxy layer
    if h.chars().any(|c| c.is_whitespace() || c == '/' || c == '\\') { return Err("PROXY bad host".into()); }
    Ok(())
}

/// P1: offline queue bound per recipient.
const MAX_QUEUE_MSGS: usize = 1000;

/// U-13: resource caps per engine — bound threads/memory against unauthenticated abuse.
pub const MAX_CONNS: usize = 1024;
pub const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);
/// U-19: store quotas.
pub const MAX_QUEUES: usize = 100_000;
pub const MAX_PROXIES: usize = 256;
pub const MAX_XFTP_PACKETS: usize = 1_000;
pub const MAX_XFTP_FILE_SIZE: u64 = 256 << 20; // 256 MiB per file
pub const MAX_XFTP_TOTAL: u64 = 1 << 30; // 1 GiB aggregate declared size
pub const MAX_XFTP_CHUNK: usize = 16_384; // one 16 KiB block worth
pub const MAX_XFTP_CHUNKS: usize = 65_536; // per file

#[cfg(test)]
mod proxy_guard_tests {
    use super::guard_proxy_dest;
    #[test]
    fn rejects_local_and_bad_ports() {
        assert!(guard_proxy_dest("127.0.0.1", 5223, false).is_err());
        assert!(guard_proxy_dest("10.0.0.5", 5223, false).is_err());
        assert!(guard_proxy_dest("::1", 5223, false).is_err());
        assert!(guard_proxy_dest("localhost", 5223, false).is_err());
        assert!(guard_proxy_dest("smp11.simplex.im", 22, false).is_err());
        // U-10 bypass vectors
        assert!(guard_proxy_dest("::ffff:127.0.0.1", 5223, false).is_err(), "IPv4-mapped loopback must be blocked");
        assert!(guard_proxy_dest("::ffff:169.254.169.254", 443, false).is_err(), "IPv4-mapped cloud metadata must be blocked");
        assert!(guard_proxy_dest("100.64.0.1", 5223, false).is_err(), "CGNAT must be blocked");
        assert!(guard_proxy_dest("0.0.0.0", 5223, false).is_err());
        assert!(guard_proxy_dest("198.18.0.1", 5223, false).is_err());
        assert!(guard_proxy_dest("240.0.0.1", 5223, false).is_err());
        assert!(guard_proxy_dest("64:ff9b::127.0.0.1", 5223, false).is_err(), "NAT64 must be blocked");
        assert!(guard_proxy_dest("2001:db8::1", 5223, false).is_err(), "doc range must be blocked");
        assert!(guard_proxy_dest("192.0.2.1", 5223, false).is_err());
        assert!(guard_proxy_dest("8.8.8.8", 5223, false).is_ok(), "public IP must pass");
        assert!(guard_proxy_dest("", 5223, false).is_err());
        assert!(guard_proxy_dest("smp11.simplex.im", 5223, false).is_ok());
    }
}
