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
    pub snd_auth: Option<[u8; 32]>,
    pub rcv_dh_secret: [u8; 32],
    pub messages: VecDeque<(Vec<u8>, Vec<u8>)>, // (msg_id, body)
    pub subscriber: Option<mpsc::Sender<Vec<u8>>>, // outbox of wire transmissions to push
}

pub struct ServerState {
    pub by_rcv: HashMap<Vec<u8>, Queue>,
    pub by_snd: HashMap<Vec<u8>, Vec<u8>>, // snd_id -> rcv_id
    pub persist: Option<std::path::PathBuf>,
}

impl ServerState {
    pub fn new() -> Self {
        ServerState { by_rcv: HashMap::new(), by_snd: HashMap::new(), persist: None }
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
fn err_resp(corr_id: Vec<u8>, entity_id: Vec<u8>, e: &str) -> Result<Transmission, EncodeError> {
    resp(corr_id, entity_id, BrokerMsg::Err(e.to_string()))
}

pub fn encrypt_for_recipient(rcv_dh_secret: &[u8; 32], msg_id: &[u8], body: &[u8]) -> Vec<u8> {
    let padded = crate::encoding::pad(body, MAX_RCV_MSG_LEN).expect("pad");
    secretbox_encrypt(rcv_dh_secret, &cb_nonce(msg_id), &padded)
}
pub fn decrypt_for_recipient(rcv_dh_secret: &[u8; 32], msg_id: &[u8], enc: &[u8]) -> Option<Vec<u8>> {
    let pt = secretbox_decrypt(rcv_dh_secret, &cb_nonce(msg_id), enc)?;
    crate::encoding::unpad(&pt).ok()
}

/// public wrapper for debug
pub fn hsalsa20_pub(key: &[u8; 32], nonce: &[u8; 16]) -> [u8; 32] {
    crate::crypto::hsalsa20_pub(key, nonce)
}

fn dispatch(
    t: &Transmission,
    st: &Arc<Mutex<ServerState>>,
    session_id: &[u8],
    outbox: &mpsc::Sender<Vec<u8>>,
) -> Vec<Transmission> {
    let cmd = match parse_command(&t.command) {
        Ok(c) => c,
        Err(e) => return vec![err_resp(t.corr_id.clone(), t.entity_id.clone(), &format!("CMD {e}")).unwrap()],
    };
    let dirty = matches!(
        cmd,
        Command::New { .. } | Command::Send { .. } | Command::Ack(_) | Command::Key(_) | Command::Skey(_) | Command::Del
    );
    let out = dispatch_cmd(cmd, t, st, session_id, outbox);
    if dirty {
        st.lock().unwrap().persist_now();
    }
    out
}

fn dispatch_cmd(
    cmd: Command,
    t: &Transmission,
    st: &Arc<Mutex<ServerState>>,
    session_id: &[u8],
    outbox: &mpsc::Sender<Vec<u8>>,
) -> Vec<Transmission> {
    match cmd {
        Command::New { rcv_auth_key, rcv_dh_key, .. } => {
            if !t.entity_id.is_empty() {
                return vec![err_resp(t.corr_id.clone(), vec![], "CMD HAS_AUTH").unwrap()];
            }
            let (alg, raw) = match parse_spki(&rcv_auth_key) {
                Ok(x) => x,
                Err(_) => return vec![err_resp(t.corr_id.clone(), vec![], "AUTH").unwrap()],
            };
            let ok = match alg {
                AuthAlg::Ed25519 => verify_sign(session_id, t, &raw),
                AuthAlg::X25519 => false, // needs router session key (TLS); not in plain mode
            };
            if !ok {
                return vec![err_resp(t.corr_id.clone(), vec![], "AUTH").unwrap()];
            }
            let (_dh_alg, dh_raw) = match parse_spki(&rcv_dh_key) {
                Ok(x) => x,
                Err(_) => return vec![err_resp(t.corr_id.clone(), vec![], "CMD SYNTAX").unwrap()],
            };
            let client_dh_pub = x25519_public(dh_raw);
            let srv = x25519_keypair();
            let rcv_dh_secret = x25519_dh(&srv.secret, &client_dh_pub);
            let rcv_id = random_bytes(16);
            let snd_id = random_bytes(24);
            let srv_dh_der = spki_x25519(&srv.public.to_bytes());
            {
                let mut s = st.lock().unwrap();
                s.by_rcv.insert(rcv_id.clone(), Queue {
                    rcv_id: rcv_id.clone(),
                    snd_id: snd_id.clone(),
                    rcv_auth_raw: raw,
                    snd_auth: None,
                    rcv_dh_secret,
                    messages: VecDeque::new(),
                    subscriber: None,
                });
                s.by_snd.insert(snd_id.clone(), rcv_id.clone());
            }
            vec![resp(t.corr_id.clone(), vec![], BrokerMsg::Ids {
                rcv_id, snd_id, rcv_dh_key: srv_dh_der,
                queue_mode: None, link_id: None, service_id: None, ntf_creds: None,
            }).unwrap()]
        }
        Command::Sub => {
            let rcv_id = t.entity_id.clone();
            let mut s = st.lock().unwrap();
            let Some(q) = s.by_rcv.get_mut(&rcv_id) else {
                return vec![err_resp(t.corr_id.clone(), rcv_id, "AUTH").unwrap()];
            };
            if !verify_sign(session_id, t, &q.rcv_auth_raw) {
                return vec![err_resp(t.corr_id.clone(), rcv_id, "AUTH").unwrap()];
            }
            q.subscriber = Some(outbox.clone());
            let mut out = vec![resp(t.corr_id.clone(), rcv_id.clone(), BrokerMsg::Sok(None)).unwrap()];
            while let Some((mid, body)) = q.messages.pop_front() {
                let enc = encrypt_for_recipient(&q.rcv_dh_secret, &mid, &body);
                out.push(resp(random_bytes(24), rcv_id.clone(), BrokerMsg::Msg { msg_id: mid, body: enc }).unwrap());
            }
            out
        }
        Command::Get => {
            let rcv_id = t.entity_id.clone();
            let mut s = st.lock().unwrap();
            let Some(q) = s.by_rcv.get_mut(&rcv_id) else {
                return vec![err_resp(t.corr_id.clone(), rcv_id, "AUTH").unwrap()];
            };
            if !verify_sign(session_id, t, &q.rcv_auth_raw) {
                return vec![err_resp(t.corr_id.clone(), rcv_id, "AUTH").unwrap()];
            }
            match q.messages.pop_front() {
                Some((mid, body)) => {
                    let enc = encrypt_for_recipient(&q.rcv_dh_secret, &mid, &body);
                    vec![resp(t.corr_id.clone(), rcv_id, BrokerMsg::Msg { msg_id: mid, body: enc }).unwrap()]
                }
                None => vec![resp(t.corr_id.clone(), rcv_id, BrokerMsg::Sok(None)).unwrap()],
            }
        }
        Command::Send { body, .. } => {
            let snd_id = t.entity_id.clone();
            let rcv_id = {
                let s = st.lock().unwrap();
                let Some(rcv_id) = s.by_snd.get(&snd_id).cloned() else {
                    return vec![err_resp(t.corr_id.clone(), snd_id, "AUTH").unwrap()];
                };
                rcv_id
            };
            let mut s = st.lock().unwrap();
            let Some(q) = s.by_rcv.get_mut(&rcv_id) else {
                return vec![err_resp(t.corr_id.clone(), snd_id, "AUTH").unwrap()];
            };
            if let Some(snd_raw) = &q.snd_auth {
                if !verify_sign(session_id, t, snd_raw) {
                    return vec![err_resp(t.corr_id.clone(), snd_id, "AUTH").unwrap()];
                }
            }
            let msg_id = random_bytes(16);
            q.messages.push_back((msg_id.clone(), body.clone()));
            if let Some(sub) = &q.subscriber {
                let enc = encrypt_for_recipient(&q.rcv_dh_secret, &msg_id, &body);
                if let Ok(msg_t) = resp(random_bytes(24), rcv_id.clone(), BrokerMsg::Msg { msg_id: msg_id.clone(), body: enc }) {
                    if let Ok(wire) = encode_transmission(&msg_t) {
                        let _ = sub.send(wire);
                    }
                }
            }
            vec![resp(t.corr_id.clone(), snd_id, BrokerMsg::Ok).unwrap()]
        }
        Command::Ack(msg_id) => {
            let rcv_id = t.entity_id.clone();
            let mut s = st.lock().unwrap();
            let Some(q) = s.by_rcv.get_mut(&rcv_id) else {
                return vec![err_resp(t.corr_id.clone(), rcv_id, "AUTH").unwrap()];
            };
            if !verify_sign(session_id, t, &q.rcv_auth_raw) {
                return vec![err_resp(t.corr_id.clone(), rcv_id, "AUTH").unwrap()];
            }
            q.messages.retain(|(m, _)| *m != msg_id);
            vec![resp(t.corr_id.clone(), rcv_id, BrokerMsg::Ok).unwrap()]
        }
        Command::Key(k) | Command::Skey(k) => {
            let rcv_id = t.entity_id.clone();
            let mut s = st.lock().unwrap();
            let Some(q) = s.by_rcv.get_mut(&rcv_id) else {
                return vec![err_resp(t.corr_id.clone(), rcv_id, "AUTH").unwrap()];
            };
            let is_recipient = tag_of(&t.command) == "KEY";
            let key_ok = if is_recipient {
                verify_sign(session_id, t, &q.rcv_auth_raw)
            } else {
                q.snd_auth.map(|r| verify_sign(session_id, t, &r)).unwrap_or(true)
            };
            if !key_ok {
                return vec![err_resp(t.corr_id.clone(), rcv_id, "AUTH").unwrap()];
            }
            if let Ok((_alg, raw)) = parse_spki(&k) {
                q.snd_auth = Some(raw);
            }
            vec![resp(t.corr_id.clone(), rcv_id, BrokerMsg::Ok).unwrap()]
        }
        Command::Del => {
            let rcv_id = t.entity_id.clone();
            let mut s = st.lock().unwrap();
            let Some(q) = s.by_rcv.get_mut(&rcv_id) else {
                return vec![err_resp(t.corr_id.clone(), rcv_id, "AUTH").unwrap()];
            };
            if !verify_sign(session_id, t, &q.rcv_auth_raw) {
                return vec![err_resp(t.corr_id.clone(), rcv_id, "AUTH").unwrap()];
            }
            let snd = q.snd_id.clone();
            s.by_rcv.remove(&rcv_id);
            s.by_snd.remove(&snd);
            vec![resp(t.corr_id.clone(), rcv_id, BrokerMsg::Deld).unwrap()]
        }
        Command::Off => vec![resp(t.corr_id.clone(), t.entity_id.clone(), BrokerMsg::Ok).unwrap()],
        Command::Ping => vec![resp(t.corr_id.clone(), vec![], BrokerMsg::Pong).unwrap()],
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
    let hello = server_hello_block(SMP_VERSION, SMP_VERSION, &session_id).map_err(io_err)?;
    write_block(&mut stream, &hello)?;
    let ch = read_block(&mut stream)?;
    let (v, _kh, _proxy) = parse_client_hello(&ch).map_err(io_err)?;
    if v != SMP_VERSION {
        return Err(io_err(format!("version {v} != {SMP_VERSION}")));
    }
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
                        for r in dispatch(&t, &st, &session_id, &tx) {
                            if let Ok(enc) = encode_transmission(&r) {
                                responses.push(enc);
                            }
                        }
                    }
                    if !responses.is_empty() {
                        let out = encode_block(&responses).map_err(io_err)?;
                        if write_block(&mut stream, &out).is_err() {
                            break;
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
