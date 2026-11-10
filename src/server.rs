//! SMP router (server). In-memory queue store, command dispatch, and
//! authorization verification (Ed25519 signature authenticators; X25519
//! crypto_box authenticators supported where a router session key exists).
//!
//! Plain-TCP transport: sessionId = "" and no router session key, so the
//! Ed25519 signature authenticator path is the one exercised here.

use std::collections::{HashMap, VecDeque};
use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};

use crate::crypto::*;
use crate::encoding::{w_short, EncodeError};
use crate::protocol::*;
use crate::transport::*;

type Writer = Arc<Mutex<TcpStream>>;

pub struct Queue {
    pub rcv_id: Vec<u8>,
    pub snd_id: Vec<u8>,
    pub rcv_auth_raw: [u8; 32],
    pub snd_auth: Option<[u8; 32]>,
    pub rcv_dh_secret: [u8; 32], // DH(server dh priv, client rcv dh pub)
    pub messages: VecDeque<(Vec<u8>, Vec<u8>)>, // (msg_id, body)
    pub subscriber: Option<Writer>,
}

pub struct ServerState {
    pub by_rcv: HashMap<Vec<u8>, Queue>,
    pub by_snd: HashMap<Vec<u8>, Vec<u8>>, // snd_id -> rcv_id
}

pub fn new_state() -> Arc<Mutex<ServerState>> {
    Arc::new(Mutex::new(ServerState {
        by_rcv: HashMap::new(),
        by_snd: HashMap::new(),
    }))
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

/// Encrypt a stored message body for delivery to the recipient (MSG body):
/// secretbox(rcvDhSecret, cbNonce(msgId), pad(body, MAX_RCV_MSG_LEN))
pub fn encrypt_for_recipient(rcv_dh_secret: &[u8; 32], msg_id: &[u8], body: &[u8]) -> Vec<u8> {
    let padded = crate::encoding::pad(body, MAX_RCV_MSG_LEN).expect("pad");
    secretbox_encrypt(rcv_dh_secret, &cb_nonce(msg_id), &padded)
}

pub fn decrypt_for_recipient(rcv_dh_secret: &[u8; 32], msg_id: &[u8], enc: &[u8]) -> Option<Vec<u8>> {
    let pt = secretbox_decrypt(rcv_dh_secret, &cb_nonce(msg_id), enc)?;
    crate::encoding::unpad(&pt).ok()
}

fn dispatch(t: &Transmission, st: &Arc<Mutex<ServerState>>, session_id: &[u8], writer: &Writer) -> Vec<Transmission> {
    let cmd = match parse_command(&t.command) {
        Ok(c) => c,
        Err(e) => return vec![err_resp(t.corr_id.clone(), t.entity_id.clone(), &format!("CMD {e}")).unwrap()],
    };
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
                AuthAlg::X25519 => false, // needs router session key; not in plain mode
            };
            if !ok {
                return vec![err_resp(t.corr_id.clone(), vec![], "AUTH").unwrap()];
            }
            // client rcv dh pub
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
            q.subscriber = Some(writer.clone());
            let mut out = vec![resp(t.corr_id.clone(), rcv_id.clone(), BrokerMsg::Sok(None)).unwrap()];
            // deliver pending messages
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
            let s = st.lock().unwrap();
            let Some(rcv_id) = s.by_snd.get(&snd_id).cloned() else {
                return vec![err_resp(t.corr_id.clone(), snd_id, "AUTH").unwrap()];
            };
            drop(s);
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
            // push to subscriber if present
            if let Some(sub) = &q.subscriber {
                let enc = encrypt_for_recipient(&q.rcv_dh_secret, &msg_id, &body);
                let msg_t = resp(random_bytes(24), rcv_id.clone(), BrokerMsg::Msg { msg_id: msg_id.clone(), body: enc }).unwrap();
                let wire = encode_transmission(&msg_t).unwrap();
                let blk = encode_block(&[wire]).unwrap();
                let _ = sub.lock().unwrap().write_all(&blk);
                let _ = sub.lock().unwrap().flush();
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
            // KEY is sent by recipient (verify with rcv key); SKEY by sender.
            let is_recipient = tag_of(&t.command) == "KEY";
            let key_ok = if is_recipient { verify_sign(session_id, t, &q.rcv_auth_raw) } else {
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

pub fn handle_conn(stream: TcpStream, st: Arc<Mutex<ServerState>>) -> std::io::Result<()> {
    let mut reader = stream.try_clone()?;
    let writer: Writer = Arc::new(Mutex::new(stream));
    // server hello first
    let hello = server_hello_block(SMP_VERSION, SMP_VERSION, b"").map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.0))?;
    write_block(&mut *writer.lock().unwrap(), &hello)?;
    // client hello
    let ch = read_block(&mut reader)?;
    let (v, _kh, _proxy) = parse_client_hello(&ch).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.0))?;
    if v != SMP_VERSION {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, format!("version {v} != {SMP_VERSION}")));
    }
    let session_id: Vec<u8> = Vec::new(); // plain TCP
    loop {
        let blk = match read_block(&mut reader) {
            Ok(b) => b,
            Err(_) => break,
        };
        let wires = match decode_block(&blk) {
            Ok(w) => w,
            Err(_) => continue,
        };
        let mut responses: Vec<Vec<u8>> = Vec::new();
        for w in &wires {
            let t = match decode_transmission(w) {
                Ok(t) => t,
                Err(_) => continue,
            };
            for r in dispatch(&t, &st, &session_id, &writer) {
                if let Ok(enc) = encode_transmission(&r) {
                    responses.push(enc);
                }
            }
        }
        if responses.is_empty() {
            continue;
        }
        let out = match encode_block(&responses) {
            Ok(b) => b,
            Err(_) => continue,
        };
        if write_block(&mut *writer.lock().unwrap(), &out).is_err() {
            break;
        }
    }
    Ok(())
}

pub fn run(addr: &str) -> std::io::Result<()> {
    let st = new_state();
    let listener = TcpListener::bind(addr)?;
    eprintln!("[smp-server] listening on {addr} (SMP v{SMP_VERSION})");
    serve_listener(listener, st)
}

/// Accept loop on an existing listener (used by tests with an ephemeral port).
pub fn serve_listener(listener: TcpListener, st: Arc<Mutex<ServerState>>) -> std::io::Result<()> {
    for conn in listener.incoming() {
        match conn {
            Ok(stream) => {
                let st = st.clone();
                std::thread::spawn(move || {
                    let _ = handle_conn(stream, st);
                });
            }
            Err(e) => eprintln!("accept error: {e}"),
        }
    }
    Ok(())
}

// keep EncodeError/w_short imports used
#[allow(dead_code)]
fn _u() -> Result<(), EncodeError> {
    let mut v = Vec::new();
    w_short(&mut v, b"x")
}
