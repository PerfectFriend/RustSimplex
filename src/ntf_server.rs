//! Local NTF (notifications) server — wire-compatible with simplexmq
//! `Simplex.Messaging.Notifications.Server`.
//!
//! Purpose: deterministic, network-free e2e coverage of the signed NTF command
//! cycle `TNEW -> IDTKN` / `SNEW -> IDSUB`. The public relays do not issue tokens
//! to third-party clients, so a local server is the only way to prove the full
//! cycle in CI.
//!
//! Reference (vendored Haskell etalon `simplexmq/`):
//! - `Notifications/Server.hs:807-841` — `verifyNtfTransmission`:
//!   * `TNEW` is authorized by the **verify key carried in the command itself**
//!     (`NewNtfTkn _ k _`), i.e. the client proves possession of the private key
//!     matching the public key it sends;
//!   * `SNEW` is authorized by the **token's verify key** (`tknVerifyKey`);
//!   * a failed check yields `NRErr AUTH`.
//! - `Notifications/Protocol.hs:332-336` — response encoding:
//!   `IDTKN <entId> <dhKey>`, `IDSUB <entId>`.
//! - `Notifications/Transport.hs:171-172` — on NTF v2+ the session id is implied by
//!   the TLS session and blocks carry batches.
//!
//! The server speaks the *plaintext* transport (no TLS) — the TLS layer is
//! exercised separately; the pinning check lives in [`crate::ntf::NtfClient::connect`].

use crate::crypto::{ed25519_verify, random_bytes};
use crate::encoding::{w_short, w_u16, Reader};
use crate::ntf::{
    encode_ntf_batch, ntf_authorized_bytes, pad_ntf_block, parse_ntf_batch, unpad_ntf_block,
    NtfResponseTag, NTF_BLOCK_SIZE,
};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Server-side error codes (subset of the Haskell `ErrorType`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NtfError {
    /// Signature verification failed.
    Auth,
    /// The command could not be parsed.
    Syntax,
}

impl NtfError {
    fn tag(&self) -> &'static [u8] {
        match self {
            NtfError::Auth => b"AUTH",
            NtfError::Syntax => b"SYNTAX",
        }
    }
}

/// A registered notification token.
#[derive(Debug, Clone)]
pub struct TokenRecord {
    /// The Ed25519 public verify key (raw 32 bytes) that authorizes token commands.
    pub verify_key: [u8; 32],
    /// The server's X25519 public key for this token (raw 32 bytes).
    pub dh_pub_key: [u8; 32],
}

/// A registered notification subscription.
#[derive(Debug, Clone)]
pub struct SubscriptionRecord {
    pub token_id: Vec<u8>,
    pub notifier_id: Vec<u8>,
    pub notifier_key: [u8; 32],
}

/// Mutable server state.
#[derive(Debug, Default)]
pub struct NtfState {
    /// Registered tokens, keyed by token id.
    pub tokens: HashMap<Vec<u8>, TokenRecord>,
    /// Registered subscriptions, keyed by subscription id.
    pub subscriptions: HashMap<Vec<u8>, SubscriptionRecord>,
}

impl NtfState {
    /// Number of registered tokens.
    pub fn token_count(&self) -> usize {
        self.tokens.len()
    }
    /// Number of registered subscriptions.
    pub fn subscription_count(&self) -> usize {
        self.subscriptions.len()
    }
}

/// The NTF server engine.
pub struct NtfEngine {
    pub listener: TcpListener,
    pub state: Arc<Mutex<NtfState>>,
    pub shutdown: Arc<AtomicBool>,
    /// Session id advertised in the handshake (32 bytes).
    pub session_id: Vec<u8>,
    /// The server's Ed25519 public auth key (raw 32 bytes) — authorizes token commands.
    pub auth_key: [u8; 32],
}

impl NtfEngine {
    /// Bind an NTF engine to `addr` with a fresh session id and auth key.
    pub fn bind_plain(addr: &str) -> std::io::Result<Self> {
        let listener = TcpListener::bind(addr)?;
        let mut session_id = random_bytes(32);
        // A session id must fit the 1-byte shortString length prefix.
        session_id.truncate(255);
        Ok(NtfEngine {
            listener,
            state: Arc::new(Mutex::new(NtfState::default())),
            shutdown: Arc::new(AtomicBool::new(false)),
            session_id,
            auth_key: random_bytes(32).try_into().unwrap_or([0u8; 32]),
        })
    }

    /// The address the engine listens on.
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Serve until the shutdown flag is set.
    pub fn serve(&self) -> std::io::Result<()> {
        // Wake-up connection pattern: a watcher thread polls the shutdown flag and
        // opens a throwaway connection so that a blocking `accept()` returns.
        // (Setting the listener non-blocking would leak O_NONBLOCK into accepted
        // sockets on Linux and break the per-connection read paths.)
        let shutdown_flag = self.shutdown.clone();
        let watcher_stop = Arc::new(AtomicBool::new(false));
        let watcher_stop_thread = watcher_stop.clone();
        let watcher = self.listener.local_addr().ok().map(|addr| {
            std::thread::spawn(move || {
                while !watcher_stop_thread.load(Ordering::Relaxed) {
                    if shutdown_flag.load(Ordering::Relaxed) {
                        let _ = TcpStream::connect(addr);
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
            })
        });

        let result = loop {
            if self.shutdown.load(Ordering::Relaxed) {
                break Ok(());
            }
            let (tcp, _) = match self.listener.accept() {
                Ok(v) => v,
                Err(e) => {
                    if self.shutdown.load(Ordering::Relaxed) {
                        break Ok(());
                    }
                    eprintln!("[ntf] accept: {e}");
                    continue;
                }
            };
            if self.shutdown.load(Ordering::Relaxed) {
                break Ok(());
            }
            let state = self.state.clone();
            let session_id = self.session_id.clone();
            let auth_key = self.auth_key;
            std::thread::spawn(move || {
                if let Err(e) = handle_conn(tcp, state, &session_id, auth_key) {
                    if std::env::var_os("SMP_DEBUG").is_some() {
                        eprintln!("[ntf] conn error: {e}");
                    }
                }
            });
        };

        watcher_stop.store(true, Ordering::Relaxed);
        if let Some(w) = watcher {
            let _ = w.join();
        }
        result
    }
}

/// Spawn the engine on a background thread. Returns (addr, state, shutdown, join).
pub fn spawn_engine(
    engine: NtfEngine,
) -> (
    SocketAddr,
    Arc<Mutex<NtfState>>,
    Arc<AtomicBool>,
    std::thread::JoinHandle<()>,
) {
    let addr = engine.local_addr().unwrap_or_else(|_| SocketAddr::from(([127, 0, 0, 1], 0)));
    let state = engine.state.clone();
    let shutdown = engine.shutdown.clone();
    let handle = std::thread::spawn(move || {
        let _ = engine.serve();
    });
    (addr, state, shutdown, handle)
}

/// Server handshake: `u16 minVersion + u16 maxVersion + short(sessionId) [ + Large(authPubKey) ]`.
///
/// Haskell `Notifications/Transport.hs:97-111`: the `authPubKey` field is present
/// when the maximum version is >= `authBatchCmdsNTFVersion` (2), and it is a
/// `C.SignedObject` => Large (u16 length) + DER.
fn server_handshake(session_id: &[u8], auth_key: &[u8; 32]) -> Vec<u8> {
    let mut v = Vec::new();
    w_u16(&mut v, crate::ntf::NTF_VERSION_INITIAL);
    w_u16(&mut v, crate::ntf::NTF_VERSION_SERVER_MAX);
    let _ = w_short(&mut v, session_id);
    // authPubKey: Large (u16 len) + SPKI DER of the server's Ed25519 auth key.
    let der = crate::crypto::spki_ed25519(auth_key);
    v.extend_from_slice(&(der.len() as u16).to_be_bytes());
    v.extend_from_slice(&der);
    v
}

/// Read one padded NTF block.
fn read_block(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut buf = vec![0u8; NTF_BLOCK_SIZE];
    stream.read_exact(&mut buf)?;
    Ok(buf)
}

/// Write one padded NTF block.
fn write_block(stream: &mut TcpStream, payload: &[u8]) -> std::io::Result<()> {
    let block = pad_ntf_block(payload).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    stream.write_all(&block)?;
    stream.flush()
}

fn handle_conn(
    mut stream: TcpStream,
    state: Arc<Mutex<NtfState>>,
    session_id: &[u8],
    auth_key: [u8; 32],
) -> std::io::Result<()> {
    // 1. Server speaks first: the handshake block.
    write_block(&mut stream, &server_handshake(session_id, &auth_key))?;

    // 2. Client handshake: `u16 ntfVersion + keyHash(35 bytes)`.
    let hs = read_block(&mut stream)?;
    let hs_payload = unpad_ntf_block(&hs).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    if hs_payload.len() < 2 {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "short client handshake"));
    }
    let client_version = u16::from_be_bytes([hs_payload[0], hs_payload[1]]);
    if !(crate::ntf::NTF_VERSION_INITIAL..=crate::ntf::NTF_VERSION_SERVER_MAX).contains(&client_version) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("unsupported NTF version {client_version}"),
        ));
    }

    // 3. Command loop.
    loop {
        let block = match read_block(&mut stream) {
            Ok(b) => b,
            Err(_) => return Ok(()),
        };
        let payload = match unpad_ntf_block(&block) {
            Ok(p) => p,
            Err(_) => return Ok(()),
        };
        let transmissions = match parse_ntf_batch(&payload) {
            Ok(t) => t,
            Err(_) => return Ok(()),
        };

        let mut responses = Vec::new();
        for tr in &transmissions {
            let (command_bytes, resp) = handle_transmission(tr, &state, session_id);
            let mut out = tr.clone();
            out.command = command_bytes;
            responses.push(out);
            let _ = resp;
        }
        let batch = encode_ntf_batch(&responses);
        write_block(&mut stream, &batch)?;
    }
}

/// Handle one transmission: verify the signature and execute the command.
///
/// Returns the response command bytes and the response tag.
fn handle_transmission(
    tr: &crate::ntf::NtfTransmission,
    state: &Arc<Mutex<NtfState>>,
    session_id: &[u8],
) -> (Vec<u8>, Option<NtfResponseTag>) {
    let corr_id = tr.corr_id.clone();
    let command = tr.command.clone();

    // The signed bytes are `sessionId || corrId || entityId || command`
    // (Haskell Protocol.hs:2347). The session id is implied by the TLS session
    // on NTF v2+ and is therefore not on the wire, but it IS signed.
    let authorized = match ntf_authorized_bytes(session_id, &tr.corr_id, &tr.entity_id, &command) {
        Ok(a) => a,
        Err(_) => return (error_response(&corr_id, NtfError::Syntax), None),
    };

    // Parse the command: `<TAG> <payload>`.
    let (tag, payload) = match command.iter().position(|&c| c == b' ') {
        Some(sp) => (&command[..sp], &command[sp + 1..]),
        None => (&command[..], &command[command.len()..]),
    };

    match tag {
        b"PING" => {
            let mut r = Vec::new();
            r.extend_from_slice(b"PONG");
            (r, Some(NtfResponseTag::Pong))
        }
        b"TNEW" => handle_tnew(tr, payload, &authorized, state),
        b"SNEW" => handle_snew(tr, payload, &authorized, state),
        _ => {
            let mut r = Vec::new();
            r.extend_from_slice(b"ERR ");
            r.extend_from_slice(NtfError::Syntax.tag());
            (r, Some(NtfResponseTag::Err))
        }
    }
}

/// `TNEW` — register a device token.
///
/// Haskell `Notifications/Server.hs:809-823`: the command carries the verify key
/// `k`, and the signature is checked against **that** key.
fn handle_tnew(
    tr: &crate::ntf::NtfTransmission,
    payload: &[u8],
    authorized: &[u8],
    state: &Arc<Mutex<NtfState>>,
) -> (Vec<u8>, Option<NtfResponseTag>) {
    let corr_id = tr.corr_id.clone();
    // NewNtfTkn = ('T', token, verifyKey, dhPubKey)
    let mut r = Reader::new(payload);
    let Some(entity_tag) = r.u8().ok() else {
        return (error_response(&corr_id, NtfError::Syntax), None);
    };
    if entity_tag != b'T' {
        return (error_response(&corr_id, NtfError::Syntax), None);
    }
    let Ok(_token) = r.short() else {
        return (error_response(&corr_id, NtfError::Syntax), None);
    };
    let Ok(verify_key_der) = r.short() else {
        return (error_response(&corr_id, NtfError::Syntax), None);
    };
    let Ok(dh_pub_key_der) = r.short() else {
        return (error_response(&corr_id, NtfError::Syntax), None);
    };

    // The signature must verify against the public key carried in the command.
    let Ok((alg, verify_key)) = crate::crypto::parse_spki(&verify_key_der) else {
        return (error_response(&corr_id, NtfError::Syntax), None);
    };
    if alg != crate::crypto::AuthAlg::Ed25519 {
        return (error_response(&corr_id, NtfError::Auth), None);
    }
    if tr.authenticator.len() != 64 {
        return (error_response(&corr_id, NtfError::Auth), None);
    }
    let mut sig = [0u8; 64];
    sig.copy_from_slice(&tr.authenticator);
    if !ed25519_verify(&verify_key, authorized, &sig) {
        return (error_response(&corr_id, NtfError::Auth), None);
    }
    let _ = dh_pub_key_der;

    // Register the token and answer `IDTKN <entId> <dhKey>`.
    let token_id = random_bytes(16);
    let dh_pub_key: [u8; 32] = random_bytes(32).try_into().unwrap_or([0u8; 32]);
    {
        // A poisoned lock means another thread panicked while holding it; the
        // state may be inconsistent, so the command is rejected instead of
        // unwinding the connection thread.
        let mut st = match state.lock() {
            Ok(st) => st,
            Err(_) => return (error_response(&corr_id, NtfError::Auth), None),
        };
        st.tokens.insert(
            token_id.clone(),
            TokenRecord { verify_key, dh_pub_key },
        );
    }

    let mut r = Vec::new();
    r.extend_from_slice(b"IDTKN ");
    let _ = w_short(&mut r, &token_id);
    let _ = w_short(&mut r, &crate::crypto::spki_x25519(&dh_pub_key));
    (r, Some(NtfResponseTag::IdTkn))
}

/// `SNEW` — create a subscription.
///
/// Haskell `Notifications/Server.hs:824-839`: the subscription is authorized by the
/// **token's** verify key (`tknVerifyKey`), not by a key carried in the command.
fn handle_snew(
    tr: &crate::ntf::NtfTransmission,
    payload: &[u8],
    authorized: &[u8],
    state: &Arc<Mutex<NtfState>>,
) -> (Vec<u8>, Option<NtfResponseTag>) {
    let corr_id = tr.corr_id.clone();
    // NewNtfSub = ('S', tknId, smpQueue, notifierKey)
    let mut r = Reader::new(payload);
    let Some(entity_tag) = r.u8().ok() else {
        return (error_response(&corr_id, NtfError::Syntax), None);
    };
    if entity_tag != b'S' {
        return (error_response(&corr_id, NtfError::Syntax), None);
    }
    let Ok(tkn_id) = r.short() else {
        return (error_response(&corr_id, NtfError::Syntax), None);
    };
    let Ok(_smp_server) = r.short() else {
        return (error_response(&corr_id, NtfError::Syntax), None);
    };
    let Ok(_notifier_id) = r.short() else {
        return (error_response(&corr_id, NtfError::Syntax), None);
    };
    let Ok(notifier_key_der) = r.short() else {
        return (error_response(&corr_id, NtfError::Syntax), None);
    };
    let Ok((alg, notifier_key)) = crate::crypto::parse_spki(&notifier_key_der) else {
        return (error_response(&corr_id, NtfError::Syntax), None);
    };
    if alg != crate::crypto::AuthAlg::Ed25519 {
        return (error_response(&corr_id, NtfError::Auth), None);
    }

    // The signature must verify against the token's verify key.
    let token = {
        let st = match state.lock() {
            Ok(st) => st,
            Err(_) => return (error_response(&corr_id, NtfError::Auth), None),
        };
        st.tokens.get(&tkn_id).cloned()
    };
    let Some(token) = token else {
        return (error_response(&corr_id, NtfError::Auth), None);
    };
    if tr.authenticator.len() != 64 {
        return (error_response(&corr_id, NtfError::Auth), None);
    }
    let mut sig = [0u8; 64];
    sig.copy_from_slice(&tr.authenticator);
    if !ed25519_verify(&token.verify_key, authorized, &sig) {
        return (error_response(&corr_id, NtfError::Auth), None);
    }

    // Register the subscription and answer `IDSUB <entId>`.
    let sub_id = random_bytes(16);
    {
        let mut st = match state.lock() {
            Ok(st) => st,
            Err(_) => return (error_response(&corr_id, NtfError::Auth), None),
        };
        st.subscriptions.insert(
            sub_id.clone(),
            SubscriptionRecord { token_id: tkn_id, notifier_id: _notifier_id, notifier_key },
        );
    }

    let mut r = Vec::new();
    r.extend_from_slice(b"IDSUB ");
    let _ = w_short(&mut r, &sub_id);
    (r, Some(NtfResponseTag::IdSub))
}

/// Build an `ERR <code>` response body.
fn error_response(_corr_id: &[u8], e: NtfError) -> Vec<u8> {
    let mut r = Vec::new();
    r.extend_from_slice(b"ERR ");
    r.extend_from_slice(e.tag());
    r
}
