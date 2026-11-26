//! SMP Agent Protocol (subset) on top of our SMP queues — duplex connections and agent messages.
//!
//! Wire format (spec/agent-protocol.md):
//!   decryptedAgentMessage = "I" connInfo | "D" smpQueues connInfo | "R" ratchetInfo | "M" agentMsgHeader aMessage
//!   agentMsgHeader = agentMsgId(8B BE) prevMsgHash(shortString)
//!   aMessage = "H" | "M" userMsgBody | "V" msgReceipts | "E" agentMsgId | ...
//!
//! The MSG body delivered by the router is already E2E-encrypted at the SMP layer
//! (crypto_box with the queue DH secret); the agent message is the decrypted body.
//!
//! Duplex procedure (simplified, no PQDR yet):
//!   initiator: NEW queue (contact mode 'C') -> link smp://keyHash@host:port#rcv_id?snd_id&dh=...
//!   joiner:    NEW own reply queue -> SEND to initiator's snd_id: agent msg "D" [ownQueue] connInfoReply(JSON)
//!   initiator: reads MSG, parses "D", sends "H" (HELLO) to joiner's queue
//!   joiner:    reads "H" -> sends "H" back; both sides established, then A_MSG "M" <body> + A_RCVD "V".

use serde::{Deserialize, Serialize};

use crate::client::Client;
use crate::reconnect::SmpTransport;
use crate::crypto::*;
use crate::encoding::*;
use crate::protocol::*;
use crate::server::decrypt_for_recipient;

// ---------- agent message encoding ----------

#[derive(Debug, Clone, PartialEq)]
pub enum AgentMsg {
    ConnInfo(Vec<u8>),                    // "I" connInfo
    ConnInfoReply(Vec<QueueInfo>, Vec<u8>), // "D" smpQueues connInfo
    Msg { msg_id: i64, prev_hash: Vec<u8>, body: Vec<u8> }, // "M" header + "M" aMessage
    Hello { msg_id: i64, prev_hash: Vec<u8> },              // "M" header + "H"
    Rcvd { msg_id: i64, prev_hash: Vec<u8>, receipts: Vec<Receipt> }, // "V"
    Eready { msg_id: i64, prev_hash: Vec<u8>, last: i64 },  // "E"
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QueueInfo {
    pub version_min: u16,
    pub version_max: u16,
    pub host: String,
    pub port: u16,
    pub key_hash: Vec<u8>,
    pub sender_id: Vec<u8>,
    pub dh_pub: Vec<u8>, // SPKI DER
    pub queue_mode: u8,  // b'M' | b'C'
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Receipt {
    pub agent_msg_id: i64,
    pub msg_hash: Vec<u8>,
    pub rcpt_info: Vec<u8>,
}

/// JSON connInfo / connInfoReply payload (opaque to the protocol, we use JSON for profiles).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConnInfo {
    pub profile: String,
    #[serde(default)]
    pub pq_support: bool,
    /// e2eRatchetParams wire bytes (spec/agent-protocol.md), when PQ is negotiated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub e2e: Option<Vec<u8>>,
    /// Our X448 public key (SPKI DER) — the official agent ratchet uses X448,
    /// so the key travels in the invitation and yields a shared secret.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x448_spki: Option<Vec<u8>>,
}

/// Our e2e params blob: magic + PQDR params + optional X448 SPKI.
/// Legacy blobs (raw PQDR params, no magic) are still accepted by `unpack_e2e_blob`.
pub fn pack_e2e_blob(pq_params: &[u8], x448_spki: Option<&[u8]>) -> Vec<u8> {
    let mut o = Vec::with_capacity(pq_params.len() + 80);
    o.extend_from_slice(b"SMPR1");
    o.extend_from_slice(&(pq_params.len() as u16).to_be_bytes());
    o.extend_from_slice(pq_params);
    match x448_spki {
        Some(k) => {
            o.push(1);
            o.extend_from_slice(&(k.len() as u16).to_be_bytes());
            o.extend_from_slice(k);
        }
        None => o.push(0),
    }
    o
}

/// Inverse of `pack_e2e_blob`; returns (pq_params, x448_spki).
pub fn unpack_e2e_blob(blob: &[u8]) -> Result<(Vec<u8>, Option<Vec<u8>>), String> {
    if blob.len() < 5 || &blob[..5] != b"SMPR1" {
        return Ok((blob.to_vec(), None));
    }
    let b = &blob[5..];
    if b.len() < 2 {
        return Err("e2e blob truncated".into());
    }
    let pq_len = u16::from_be_bytes([b[0], b[1]]) as usize;
    if b.len() < 2 + pq_len + 1 {
        return Err("e2e blob truncated".into());
    }
    let pq = b[2..2 + pq_len].to_vec();
    let mut i = 2 + pq_len;
    let has = b[i];
    i += 1;
    let x = if has == 1 {
        if b.len() < i + 2 {
            return Err("e2e blob truncated".into());
        }
        let l = u16::from_be_bytes([b[i], b[i + 1]]) as usize;
        i += 2;
        if b.len() < i + l {
            return Err("e2e blob truncated".into());
        }
        Some(b[i..i + l].to_vec())
    } else {
        None
    };
    Ok((pq, x))
}

pub fn encode_agent(m: &AgentMsg, msg_id: i64, prev_hash: &[u8]) -> Vec<u8> {
    let mut o = Vec::new();
    match m {
        AgentMsg::ConnInfo(ci) => {
            o.push(b'I');
            o.extend_from_slice(ci);
        }
        AgentMsg::ConnInfoReply(qs, ci) => {
            o.push(b'D');
            w_short(&mut o, (qs.len() as u8).to_be_bytes().as_ref()).ok();
            // smpQueues = length 1*newQueueInfo ; length = 1 byte count
            o.clear();
            o.push(b'D');
            o.push(qs.len() as u8);
            for q in qs {
                w_u16(&mut o, q.version_min);
                w_u16(&mut o, q.version_max);
                w_short(&mut o, q.host.as_bytes()).ok();
                w_short(&mut o, q.port.to_string().as_bytes()).ok();
                w_short(&mut o, &q.key_hash).ok();
                w_short(&mut o, &q.sender_id).ok();
                w_short(&mut o, &q.dh_pub).ok();
                o.push(q.queue_mode);
            }
            o.extend_from_slice(ci);
        }
        AgentMsg::Hello { .. } => {
            o.push(b'M');
            o.extend_from_slice(&msg_id.to_be_bytes());
            w_short(&mut o, prev_hash).ok();
            o.push(b'H');
        }
        AgentMsg::Msg { body, .. } => {
            o.push(b'M');
            o.extend_from_slice(&msg_id.to_be_bytes());
            w_short(&mut o, prev_hash).ok();
            o.push(b'M');
            o.extend_from_slice(body);
        }
        AgentMsg::Rcvd { receipts, .. } => {
            o.push(b'M');
            o.extend_from_slice(&msg_id.to_be_bytes());
            w_short(&mut o, prev_hash).ok();
            o.push(b'V');
            o.push(receipts.len() as u8);
            for r in receipts {
                o.extend_from_slice(&r.agent_msg_id.to_be_bytes());
                w_short(&mut o, &r.msg_hash).ok();
                o.extend_from_slice(&(r.rcpt_info.len() as u16).to_be_bytes());
                o.extend_from_slice(&r.rcpt_info);
            }
        }
        AgentMsg::Eready { last, .. } => {
            o.push(b'M');
            o.extend_from_slice(&msg_id.to_be_bytes());
            w_short(&mut o, prev_hash).ok();
            o.push(b'E');
            o.extend_from_slice(&last.to_be_bytes());
        }
    }
    o
}

/// Unwrap the official agent envelope (agentVersion + type) if present and return
/// the inner agent frame. Legacy raw frames ("I"/"D"/"M" without version prefix)
/// are returned unchanged — back-compat with pre-G13 peers.
pub fn unwrap_envelope(pt: &[u8]) -> Vec<u8> {
    match crate::agent_envelope::decode(pt) {
        Ok((_v, crate::agent_envelope::Envelope::Msg { enc_agent_msg })) => enc_agent_msg,
        Ok((_v, crate::agent_envelope::Envelope::Confirmation { enc_conn_info, .. })) => enc_conn_info,
        _ => pt.to_vec(),
    }
}

pub fn parse_agent(buf: &[u8]) -> Result<AgentMsg, String> {
    if buf.is_empty() {
        return Err("empty agent message".into());
    }
    let mut r = Reader::new(buf);
    match r.u8().map_err(|e| e.to_string())? {
        b'I' => Ok(AgentMsg::ConnInfo(r.rest().to_vec())),
        b'D' => {
            let n = r.u8().map_err(|e| e.to_string())? as usize;
            let mut qs = Vec::new();
            for _ in 0..n {
                let version_min = r.u16().map_err(|e| e.to_string())?;
                let version_max = r.u16().map_err(|e| e.to_string())?;
                let host = r.short().map_err(|e| e.to_string())?;
                let port = r.short().map_err(|e| e.to_string())?;
                let key_hash = r.short().map_err(|e| e.to_string())?;
                let sender_id = r.short().map_err(|e| e.to_string())?;
                let dh_pub = r.short().map_err(|e| e.to_string())?;
                let queue_mode = r.u8().map_err(|e| e.to_string())?;
                qs.push(QueueInfo {
                    version_min,
                    version_max,
                    host: String::from_utf8_lossy(&host).to_string(),
                    port: String::from_utf8_lossy(&port).parse().unwrap_or(0),
                    key_hash,
                    sender_id,
                    dh_pub,
                    queue_mode,
                });
            }
            Ok(AgentMsg::ConnInfoReply(qs, r.rest().to_vec()))
        }
        b'M' => {
            let msg_id = i64::from_be_bytes(r.take(8).map_err(|e| e.to_string())?.try_into().map_err(|_| "bad msg_id".to_string())?);
            let prev_hash = r.short().map_err(|e| e.to_string())?;
            match r.u8().map_err(|e| e.to_string())? {
                b'H' => Ok(AgentMsg::Hello { msg_id, prev_hash }),
                b'M' => Ok(AgentMsg::Msg { msg_id, prev_hash, body: r.rest().to_vec() }),
                b'V' => {
                    let n = r.u8().map_err(|e| e.to_string())? as usize;
                    let mut receipts = Vec::new();
                    for _ in 0..n {
                        let agent_msg_id = i64::from_be_bytes(r.take(8).map_err(|e| e.to_string())?.try_into().map_err(|_| "bad agent_msg_id".to_string())?);
                        let msg_hash = r.short().map_err(|e| e.to_string())?;
                        let rl = r.u16().map_err(|e| e.to_string())? as usize;
                        let rcpt_info = r.take(rl).map_err(|e| e.to_string())?.to_vec();
                        receipts.push(Receipt { agent_msg_id, msg_hash, rcpt_info });
                    }
                    Ok(AgentMsg::Rcvd { msg_id, prev_hash, receipts })
                }
                b'E' => {
                    let last = i64::from_be_bytes(r.take(8).map_err(|e| e.to_string())?.try_into().map_err(|_| "bad last".to_string())?);
                    Ok(AgentMsg::Eready { msg_id, prev_hash, last })
                }
                t => Err(format!("unknown aMessage tag {t}")),
            }
        }
        t => Err(format!("unknown agent message tag {t}")),
    }
}

/// Check a broker response to a SEND: an `ERR` must surface as an error instead of
/// a silently lost message (audited 2026-11-23, P0-6).
fn check_send_ok(resp: &[BrokerMsg]) -> Result<(), String> {
    for m in resp {
        if let BrokerMsg::Err(e) = m {
            return Err(format!("SEND rejected by the server: {e}"));
        }
    }
    Ok(())
}

// ---------- duplex connection over SMP ----------

pub struct Agent<T: SmpTransport = Client> {
    pub client: T,
    pub rcv_auth: Ed25519Keypair,
    pub rcv_dh: X25519Keypair,
    pub rcv_id: Vec<u8>,
    pub snd_id: Vec<u8>,
    pub srv_dh: Vec<u8>, // SPKI DER
    pub peer_snd_id: Option<Vec<u8>>, // where to send peer messages
    pub msg_counter: i64,
    pub prev_hash: Vec<u8>,
    pub host: String,
    pub port: u16,
    pub key_hash: Vec<u8>,
    /// SNTRUP761 KEM keypair for PQDR (Some when pq negotiated).
    pub kem: Option<crate::pq::KemKeypair>,
    /// E2E PQDR ratchet (Some once negotiated) — Msg bodies go through it.
    pub ratchet: Option<crate::pqdr::PqdrRatchet>,
    /// raw initiator connInfo ("I" payload) for the joiner side; used to auto-init E2E.
    pub init_ci: Vec<u8>,
    /// true for the link creator (initiator), false for the joiner
    pub initiator: bool,
    /// E2E: joiner buffers outgoing A_MSG until the first inbound ratchet frame establishes ckr
    pub outbox: Vec<(i64, Vec<u8>)>,
    /// E2E PQDR on by default; set false for legacy plaintext tests. No env reads in lib (FFI-safe).
    pub e2e: bool,
    /// Our X448 identity (official-compat E2E ratchet key).
    pub x448_kp: Option<crate::x448::X448Keypair>,
    /// Peer's X448 public key (SPKI DER), once exchanged.
    pub peer_x448_spki: Option<Vec<u8>>,
    /// X448 shared secret (official ratchet seed), once both keys are known.
    pub x448_shared: Option<[u8; 56]>,
    /// Messages decoded from a broker block that were not returned to the caller yet.
    ///
    /// (Audited 2026-11-23, P0-6: a block may carry several MSG frames. The old code
    /// ACKed all of them but returned only the first — the rest were removed from the
    /// queue and silently dropped.)
    pub pending_msgs: std::collections::VecDeque<(Vec<u8>, AgentMsg)>,
}

impl<T: SmpTransport> Agent<T> {
    fn dh_secret(&self) -> Result<[u8; 32], String> {
        let srv_raw = parse_spki(&self.srv_dh).map_err(|e| e.to_string())?.1;
        x25519_dh_checked(&self.rcv_dh.secret, &x25519_public(srv_raw))
    }

    /// Initiator: create a contact queue and produce a connection link.
    pub fn create_contact(mut client: T, host: &str, port: u16, key_hash: &[u8], profile: &str) -> Result<(Agent<T>, String), String> {
        let rcv_auth = ed25519_keypair();
        let rcv_dh = x25519_keypair();
        let r = client
            .request(
                Command::New {
                    rcv_auth_key: spki_ed25519(&rcv_auth.verifying.to_bytes()),
                    rcv_dh_key: spki_x25519(&rcv_dh.public.to_bytes()),
                    basic_auth: None,
                    sub_mode: b'C',
                    queue_req_data: None,
                    ntf_creds: None,
                },
                vec![],
                Some(&rcv_auth),
            )
            .map_err(|e| e.to_string())?;
        let (rcv_id, snd_id, srv_dh) = match r.first().ok_or("empty response, expected IDS")? {
            BrokerMsg::Ids { rcv_id, snd_id, rcv_dh_key, .. } => (rcv_id.clone(), snd_id.clone(), rcv_dh_key.clone()),
            other => return Err(format!("expected IDS, got {other:?}")),
        };
        // PQDR: generate SNTRUP761 keypair, advertise kemParams "P" (public key only)
        let kem = crate::pq::kem_keypair();
        let e2e = {
            let mut o = Vec::new();
            crate::pq::encode_e2e_ratchet_params(
                &mut o,
                &crate::pq::E2eRatchetParams {
                    v_min: SMP_VERSION,
                    v_max: SMP_VERSION,
                    snd_dh_spki: spki_x25519(&rcv_dh.public.to_bytes()),
                    rcv_dh_spki: spki_x25519(&rcv_dh.public.to_bytes()),
                    kem: crate::pq::KemParams::Pk(kem.ek.as_ref().to_vec()),
                },
            )
            .map_err(|e| e.to_string())?;
            o
        };
        // Official-compat X448 identity: the key travels in the invitation (e2e blob)
        // and yields the shared secret with the peer's X448 key.
        let x448_kp = crate::x448::keypair();
        let x448_spki = crate::x448::spki_x448(&x448_kp.public);
        let e2e_blob = pack_e2e_blob(&e2e, Some(&x448_spki));
        let conn_info = serde_json::to_vec(&ConnInfo {
            profile: profile.into(),
            pq_support: true,
            e2e: Some(e2e_blob.clone()),
            x448_spki: Some(x448_spki.clone()),
        })
        .map_err(|e| e.to_string())?;
        // subscribe immediately so the joiner's confirmation MSG is not missed
        let sub = client.request(Command::Sub, rcv_id.clone(), Some(&rcv_auth)).map_err(|e| e.to_string())?;
        if !matches!(sub[0], BrokerMsg::Sok(_)) {
            return Err(format!("SUB failed: {:?}", sub[0]));
        }
        // Official link shape (simplexmq 7.0.1.0, Agent/Protocol.hs:1132-1146):
        //   simplex:/invitation#/?v=<agentVRange>&smp=<urlencoded queueUri>&e2e=..&data=..
        // The queue URI carries the SENDER queue id (where the peer sends) and the
        // recipient DH public key, exactly as the reference client expects.
        // e2e= holds OUR PQDR params (binary, base64url) - see the compatibility note
        // in agent_link.rs / docs: a stock client parses the link but will not
        // understand these params, which is why full mobile interop still needs the
        // official agent envelope + X448 ratchet. data= carries the profile.
        let queue = crate::agent_link::QueueUri {
            key_hash: key_hash.to_vec(),
            host: host.to_string(),
            port,
            sender_id: snd_id.clone(),
            dh_pub: spki_x25519(&rcv_dh.public.to_bytes()),
            v_min: SMP_VERSION,
            v_max: SMP_VERSION,
            queue_mode: Some('c'),
        };
        let link = crate::agent_link::AgentLink {
            mode: "invitation".into(),
            v_min: 1,
            v_max: 1,
            queues: vec![queue],
            e2e: Some(crate::crypto::base64url_nopad(&e2e_blob)),
            client_data: Some(profile.to_string()),
        }
        .encode();
        Ok((
            Agent {
                client,
                rcv_auth,
                rcv_dh,
                rcv_id,
                snd_id,
                srv_dh,
                peer_snd_id: None,
                msg_counter: 0,
                prev_hash: vec![0u8; 32],
                host: host.to_string(),
                port,
                key_hash: key_hash.to_vec(),
                kem: Some(kem),
                ratchet: None,
                init_ci: conn_info.clone(),
                initiator: true,
                outbox: Vec::new(),
                e2e: true,
                x448_kp: Some(x448_kp),
                peer_x448_spki: None,
                x448_shared: None,
                pending_msgs: std::collections::VecDeque::new(),
            },
            link,
        ))
    }

    /// Joiner: parse link, create reply queue, send "D" confirmation to the initiator.
    pub fn join_contact(mut client: T, link: &str) -> Result<Agent<T>, String> {
        // Two accepted shapes, reduced to the same five inputs:
        //   * official: simplex:/invitation#/?v=..&smp=<urlencoded queueUri>&e2e=..&data=..
        //   * legacy:   smp://keyHash@host:port#rcv_id?snd=..&ci=..
        let mut peer_x448_from_link: Option<Vec<u8>> = None;
        let (host, port, key_hash, init_snd, init_ci): (String, u16, Vec<u8>, Vec<u8>, Vec<u8>) =
            if link.starts_with("simplex:/") || link.starts_with("https://") {
                let al = crate::agent_link::AgentLink::parse(link)?;
                let q = al.queues.first().ok_or("link has no queue")?;
                let e2e_raw = match &al.e2e {
                    Some(e) => Some(crate::agent_link::b64url_decode(e)?),
                    None => None,
                };
                let peer_x448 = match &e2e_raw {
                    Some(b) => unpack_e2e_blob(b)?.1,
                    None => None,
                };
                let ci = ConnInfo {
                    profile: al.client_data.clone().unwrap_or_default(),
                    pq_support: e2e_raw.is_some(),
                    e2e: e2e_raw.clone(),
                    x448_spki: peer_x448.clone(),
                };
                peer_x448_from_link = peer_x448;
                (q.host.clone(), q.port, q.key_hash.clone(), q.sender_id.clone(), serde_json::to_vec(&ci).map_err(|e| e.to_string())?)
            } else {
                let rest = link.strip_prefix("smp://").ok_or("bad link scheme")?;
                let (kh_host, frag) = rest.split_once('#').ok_or("bad link frag")?;
                let (kh, hostport) = kh_host.split_once('@').ok_or("bad link authority")?;
                let (host, port_s) = hostport.split_once(':').ok_or("bad hostport")?;
                let (_rcv_hex, params) = frag.split_once('?').ok_or("bad link params")?;
                let mut init_snd = Vec::new();
                let mut init_ci = Vec::new();
                for kv in params.split('&') {
                    if let Some(v) = kv.strip_prefix("snd=") {
                        init_snd = crate::xftp::unhex(v).ok_or("bad snd hex")?;
                    } else if let Some(v) = kv.strip_prefix("ci=") {
                        init_ci = crate::xftp::unhex(v).ok_or("bad ci hex")?;
                    }
                }
                if init_snd.is_empty() {
                    return Err("link has no snd param".into());
                }
                (host.to_string(), port_s.parse().map_err(|_| "bad port")?, crate::xftp::unhex(kh).ok_or("bad keyhash hex")?, init_snd, init_ci)
            };

        let rcv_auth = ed25519_keypair();
        let rcv_dh = x25519_keypair();
        let r = client
            .request(
                Command::New {
                    rcv_auth_key: spki_ed25519(&rcv_auth.verifying.to_bytes()),
                    rcv_dh_key: spki_x25519(&rcv_dh.public.to_bytes()),
                    basic_auth: None,
                    sub_mode: b'C',
                    queue_req_data: None,
                    ntf_creds: None,
                },
                vec![],
                Some(&rcv_auth),
            )
            .map_err(|e| e.to_string())?;
        let (my_rcv, my_snd, srv_dh) = match r.first().ok_or("empty response, expected IDS")? {
            BrokerMsg::Ids { rcv_id, snd_id, rcv_dh_key, .. } => (rcv_id.clone(), snd_id.clone(), rcv_dh_key.clone()),
            other => return Err(format!("expected IDS, got {other:?}")),
        };
        let qi = QueueInfo {
            version_min: SMP_VERSION,
            version_max: SMP_VERSION,
            host: host.to_string(),
            port,
            key_hash: key_hash.clone(),
            sender_id: my_snd.clone(),
            dh_pub: spki_x25519(&rcv_dh.public.to_bytes()),
            queue_mode: b'C',
        };
        let kem = crate::pq::kem_keypair();
        let e2e_reply = {
            let mut o = Vec::new();
            crate::pq::encode_e2e_ratchet_params(
                &mut o,
                &crate::pq::E2eRatchetParams {
                    v_min: SMP_VERSION,
                    v_max: SMP_VERSION,
                    snd_dh_spki: spki_x25519(&rcv_dh.public.to_bytes()),
                    rcv_dh_spki: spki_x25519(&rcv_dh.public.to_bytes()),
                    kem: crate::pq::KemParams::Pk(kem.ek.as_ref().to_vec()),
                },
            )
            .map_err(|e| e.to_string())?;
            o
        };
        // Our X448 identity + the shared secret with the initiator (from the invitation).
        let x448_kp = crate::x448::keypair();
        let x448_spki = crate::x448::spki_x448(&x448_kp.public);
        let x448_shared = peer_x448_from_link
            .as_deref()
            .and_then(crate::x448::parse_spki_x448)
            .and_then(|peer_pub| crate::x448::dh(&x448_kp.secret, &peer_pub));
        let e2e_reply_blob = pack_e2e_blob(&e2e_reply, Some(&x448_spki));
        let ci_reply = serde_json::to_vec(&ConnInfo {
            profile: "joiner".into(),
            pq_support: true,
            e2e: Some(e2e_reply_blob),
            x448_spki: Some(x448_spki.clone()),
        })
        .map_err(|e| e.to_string())?;
        let frame = encode_agent(&AgentMsg::ConnInfoReply(vec![qi], ci_reply), 1, &[0u8; 32]);
        // G13: the confirmation goes out as agentConfirmation envelope:
        // agentVersion + "C" + "1" + sndE2EParams + encConnInfo
        let body = crate::agent_envelope::encode(&crate::agent_envelope::Envelope::Confirmation {
            pq: true,
            e2e_params: e2e_reply.clone(),
            enc_conn_info: frame,
        });
        client
            .request(Command::Send { flags: false, body }, init_snd.clone(), None)
            .map_err(|e| e.to_string())?;
        // subscribe immediately so the initiator's HELLO is not missed
        let sub = client.request(Command::Sub, my_rcv.clone(), Some(&rcv_auth)).map_err(|e| e.to_string())?;
        if !matches!(sub[0], BrokerMsg::Sok(_)) {
            return Err(format!("SUB failed: {:?}", sub[0]));
        }
        Ok(Agent {
            client,
            rcv_auth,
            rcv_dh,
            rcv_id: my_rcv,
            snd_id: my_snd,
            srv_dh,
            peer_snd_id: Some(init_snd),
            msg_counter: 0,
            prev_hash: vec![0u8; 32],
            host: host.to_string(),
            port,
            key_hash,
            kem: Some(kem),
            ratchet: None,
            init_ci,
            x448_kp: Some(x448_kp),
            peer_x448_spki: peer_x448_from_link,
            x448_shared,
            initiator: false,
            outbox: Vec::new(),
            e2e: true,
            pending_msgs: std::collections::VecDeque::new(),
        })
    }

    /// Initiator: wait for the joiner's "D" confirmation, extract peer snd_id, send HELLO.
    /// (queue already subscribed in create_contact)
    pub fn accept_contact(&mut self) -> Result<(), String> {
        let msgs = self.client.recv_block().map_err(|e| e.to_string())?;
        let secret = self.dh_secret()?;
        for m in &msgs {
            if let BrokerMsg::Msg { msg_id, body } = m {
                let pt = decrypt_for_recipient(&secret, msg_id, body).ok_or("decrypt failed")?;
                if let AgentMsg::ConnInfoReply(qs, ci) = parse_agent(&unwrap_envelope(&pt))? {
                    let Some(q0) = qs.first() else { return Err("empty smpQueues in D".into()) };
                    let peer = q0.sender_id.clone();
                    self.peer_snd_id = Some(peer);
                    // auto-negotiate E2E: SK = DH(our rcv_dh, joiner rcv_dh from queue info)
                    let peer_dh_raw = parse_spki(&q0.dh_pub).map_err(|e| e.to_string())?.1;
                    let sk = x25519_dh_checked(&self.rcv_dh.secret, &x25519_public(peer_dh_raw))?;
                    let peer_ci: Option<ConnInfo> = serde_json::from_slice(&ci).ok();
                    let peer_kem = (|| {
                        let e2e = peer_ci.as_ref()?.e2e.as_ref()?;
                        let (pq_params, _) = unpack_e2e_blob(e2e).ok()?;
                        let mut r = Reader::new(&pq_params);
                        match crate::pq::decode_e2e_ratchet_params(&mut r).ok()?.kem {
                            crate::pq::KemParams::Pk(pk) | crate::pq::KemParams::CtPk(_, pk) => Some(pk),
                            _ => None,
                        }
                    })();
                    // Official-compat X448: the joiner's key arrives in its connInfo;
                    // both sides now derive the same shared secret.
                    if let Some(peer_spki) = peer_ci.as_ref().and_then(|c| c.x448_spki.clone()) {
                        self.peer_x448_spki = Some(peer_spki.clone());
                        self.x448_shared = match (self.x448_kp.as_ref(), crate::x448::parse_spki_x448(&peer_spki)) {
                            (Some(kp), Some(peer_pub)) => crate::x448::dh(&kp.secret, &peer_pub),
                            _ => None,
                        };
                    }
                    self.msg_counter += 1;
                    let hello = encode_agent(&AgentMsg::Hello { msg_id: 0, prev_hash: vec![] }, self.msg_counter, &self.prev_hash);
                    // pre-ratchet handshake frame: sent raw (no envelope) until the PQDR
                    // session exists — recv side treats raw frames as plaintext by definition.
                    self.client
                        .request(Command::Send { flags: false, body: hello }, self.peer_snd_id.clone().ok_or("no peer")?, None)
                        .map_err(|e| e.to_string())?;
                    // init E2E only AFTER HELLO is sent (before any A_MSG); fail-closed:
                    // with e2e on, a missing/malformed peer KEM key is an error, never plaintext.
                    if self.e2e {
                        let kem = peer_kem
                            .filter(|k| k.len() == crate::pq::KEM_PK_LEN)
                            .ok_or("E2E on: missing or malformed peer KEM key in connInfo")?;
                        self.init_e2e_sender(&sk, peer_dh_raw, kem)?;
                    }
                    return Ok(());
                }
            }
        }
        Err("no confirmation MSG".into())
    }

    /// Official-compat X448 shared secret (once both X448 keys are known).
    pub fn x448_shared_secret(&self) -> Option<[u8; 56]> {
        self.x448_shared
    }

    /// Our X448 public key in SPKI DER (travels in the invitation).
    pub fn x448_public_spki(&self) -> Option<Vec<u8>> {
        self.x448_kp.as_ref().map(|kp| crate::x448::spki_x448(&kp.public))
    }

    /// Joiner: wait for HELLO on own queue, reply HELLO. (queue already subscribed in join_contact)
    pub fn await_hello(&mut self) -> Result<(), String> {
        let msgs = self.client.recv_block().map_err(|e| e.to_string())?;
        let secret = self.dh_secret()?;
        for m in &msgs {
            if let BrokerMsg::Msg { msg_id, body } = m {
                let pt = decrypt_for_recipient(&secret, msg_id, body).ok_or("decrypt failed")?;
                if matches!(parse_agent(&unwrap_envelope(&pt))?, AgentMsg::Hello { .. }) {
                    self.msg_counter += 1;
                    let hello = encode_agent(&AgentMsg::Hello { msg_id: 0, prev_hash: vec![] }, self.msg_counter, &self.prev_hash);
                    // pre-ratchet handshake frame: sent raw (no envelope) until the PQDR
                    // session exists — recv side treats raw frames as plaintext by definition.
                    self.client
                        .request(Command::Send { flags: false, body: hello }, self.peer_snd_id.clone().ok_or("no peer")?, None)
                        .map_err(|e| e.to_string())?;
                    // init E2E only AFTER HELLO reply is sent; fail-closed: with e2e on,
                    // unparsable e2e params in the link are an error, never a silent downgrade.
                    if self.e2e {
                        if self.init_ci.is_empty() {
                            return Err("E2E on: empty init_ci, cannot negotiate".into());
                        }
                        let ci: ConnInfo = serde_json::from_slice(&self.init_ci).map_err(|e| format!("init_ci: {e}"))?;
                        let e2e = ci.e2e.ok_or("E2E on: no e2e params in init_ci")?;
                        let (pq_params, peer_x448) = unpack_e2e_blob(&e2e)?;
                        if self.peer_x448_spki.is_none() {
                            self.peer_x448_spki = peer_x448;
                        }
                        if self.x448_shared.is_none() {
                            self.x448_shared = match (self.x448_kp.as_ref(), self.peer_x448_spki.as_deref()) {
                                (Some(kp), Some(spki)) => crate::x448::parse_spki_x448(spki)
                                    .and_then(|peer_pub| crate::x448::dh(&kp.secret, &peer_pub)),
                                _ => None,
                            };
                        }
                        let params = crate::pq::decode_e2e_ratchet_params(&mut Reader::new(&pq_params))
                            .map_err(|e| format!("e2e params: {e}"))?;
                        let (_, dh_raw) = parse_spki(&params.snd_dh_spki).map_err(|e| e.to_string())?;
                        let sk = x25519_dh_checked(&self.rcv_dh.secret, &x25519_public(dh_raw))?;
                        self.init_e2e_receiver(&sk, dh_raw)?;
                    }
                    return Ok(());
                }
            }
        }
        Err("no HELLO".into())
    }

    /// Send an application message (A_MSG). Returns the agent msg id used.
    /// Negotiate E2E as the sender (initiator): peer DH raw + peer KEM pk from connInfo.
    pub fn init_e2e_sender(&mut self, sk: &[u8; 32], peer_dh_raw: [u8; 32], peer_kem_pk: Vec<u8>) -> Result<(), String> {
        self.ratchet = Some(crate::pqdr::PqdrRatchet::init_sender(
            sk,
            self.rcv_id.clone(),
            x25519_public(peer_dh_raw),
            peer_kem_pk,
        )?);
        Ok(())
    }

    /// Negotiate E2E as the receiver (joiner): uses own DH + KEM from the link exchange.
    pub fn init_e2e_receiver(&mut self, sk: &[u8; 32], peer_dh_raw: [u8; 32]) -> Result<(), String> {
        let kem = self.kem.clone().ok_or("no kem")?;
        let mut r = crate::pqdr::PqdrRatchet::init_receiver(
            sk,
            self.rcv_id.clone(),
            self.rcv_dh.clone(),
            kem,
            Vec::new(),
        );
        r.dh_r = crate::pqdr::DhPub::X25519(x25519_public(peer_dh_raw));
        self.ratchet = Some(r);
        Ok(())
    }

    /// Encrypt a whole agent frame with the PQDR ratchet when a session exists.
    /// (G13: the envelope payload is the ratchet ciphertext, not just the Msg body.)
    fn encrypt_frame(&mut self, frame: Vec<u8>) -> Result<Vec<u8>, String> {
        match &mut self.ratchet {
            // FAIL-CLOSED: an AEAD failure must abort the send, never emit a
            // zero-filled "ciphertext" (audited 2026-11-23).
            Some(r) => r.encrypt(&frame),
            None => Ok(frame),
        }
    }

    pub fn send_msg(&mut self, body: &[u8]) -> Result<i64, String> {
        // fail-closed: E2E is on by default — never send plaintext just because the
        // ratchet is not negotiated yet (that was a silent downgrade).
        if self.e2e && self.ratchet.is_none() {
            return Err("E2E on but ratchet not negotiated — refusing plaintext send".into());
        }
        self.msg_counter += 1;
        let id = self.msg_counter;
        // E2E: a fresh receiver has no ckr yet — buffer the PLAINTEXT until the first
        // inbound frame (double-ratchet rule); encrypt at flush time, in order.
        if let Some(r) = &self.ratchet {
            if !self.initiator && r.ckr.is_none() {
                self.outbox.push((id, body.to_vec()));
                return Ok(id);
            }
        }
        // G13: the inner agentMessage frame is built with the PLAINTEXT body, then the
        // whole frame is PQDR-encrypted and placed as the envelope payload
        // (agentMsgEnvelope = agentVersion + "M" + encAgentMessage).
        let frame = encode_agent(&AgentMsg::Msg { msg_id: id, prev_hash: self.prev_hash.clone(), body: body.to_vec() }, id, &self.prev_hash);
        let hash = sha256(&frame);
        let enc = self.encrypt_frame(frame)?;
        let wire = crate::agent_envelope::encode(&crate::agent_envelope::Envelope::Msg { enc_agent_msg: enc });
        let resp = self
            .client
            .request(Command::Send { flags: false, body: wire }, self.peer_snd_id.clone().ok_or("no peer")?, None)
            .map_err(|e| e.to_string())?;
        // FAIL-CLOSED (audited 2026-11-23, P0-6): the broker may answer SEND with
        // ERR (AUTH / LARGE_MSG / QUOTA / ...). The old code ignored the response and
        // returned Ok(id) — the caller believed the message was delivered.
        check_send_ok(&resp)?;
        self.prev_hash = hash.to_vec();
        Ok(id)
    }

    /// Flush buffered E2E sends once the receiving chain exists (encrypt in original order).
    pub fn flush_outbox(&mut self) -> Result<(), String> {
        if self.outbox.is_empty() {
            return Ok(());
        }
        if self.e2e && self.ratchet.is_none() {
            return Err("E2E on but ratchet not negotiated — outbox would go plaintext".into());
        }
        if !self.ratchet.as_ref().map(|r| r.ckr.is_some()).unwrap_or(false) {
            return Ok(());
        }
        let peer = self.peer_snd_id.clone().ok_or("no peer")?;
        let pending: Vec<(i64, Vec<u8>)> = std::mem::take(&mut self.outbox);
        for (id, plain) in pending {
            let frame = encode_agent(&AgentMsg::Msg { msg_id: id, prev_hash: self.prev_hash.clone(), body: plain }, id, &self.prev_hash);
            let hash = sha256(&frame);
            let enc = self.encrypt_frame(frame)?;
            let wire = crate::agent_envelope::encode(&crate::agent_envelope::Envelope::Msg { enc_agent_msg: enc });
            let resp = self.client.request(Command::Send { flags: false, body: wire }, peer.clone(), None).map_err(|e| e.to_string())?;
            check_send_ok(&resp)?;
            self.prev_hash = hash.to_vec();
        }
        Ok(())
    }

    /// Decode one transport-decrypted SMP payload into an agent message.
    ///
    /// Fail-closed (external audit #3, U-01/C1): once an E2E ratchet exists, ONLY
    /// `Envelope::Msg` frames that decrypt AND parse are accepted. Raw legacy frames
    /// and C/I/R envelopes arriving in an established session are forged (a real peer
    /// would have encrypted them) → `Ok(None)`. Ratchet decrypt failures are
    /// transactional since P0-1 (no state corruption), so dropping is safe.
    /// Callers ACK and drop `None` frames, so an injected frame can neither be read
    /// as plaintext nor wedge the queue (U-12/H6).
    fn decode_incoming(&mut self, pt: &[u8]) -> Result<Option<AgentMsg>, String> {
        let established = self.ratchet.is_some();
        let mut authentic_msg = false;
        let payload: Vec<u8> = match crate::agent_envelope::decode(pt) {
            Ok((_v, crate::agent_envelope::Envelope::Msg { enc_agent_msg })) => match &mut self.ratchet {
                Some(r) => match r.decrypt(&enc_agent_msg) {
                    Ok(f) => {
                        authentic_msg = true;
                        f
                    }
                    Err(_) if established => return Ok(None), // forged/corrupt frame: drop
                    Err(e) => return Err(e.to_string()),
                },
                None => enc_agent_msg,
            },
            Ok((_v, crate::agent_envelope::Envelope::Confirmation { enc_conn_info, .. })) => enc_conn_info,
            _ => pt.to_vec(), // raw legacy frame (handshake HELLO etc. travel raw pre-session)
        };
        let am = match parse_agent(&payload) {
            Ok(am) => am,
            Err(e) if established => {
                let _ = e;
                return Ok(None); // authenticated channel, unparseable frame: drop, don't wedge
            }
            Err(e) => return Err(e),
        };
        // U-01/C1 fail-closed: in an established E2E session, message-carrying frames
        // (Msg/Rcvd) are accepted ONLY from a successfully decrypted Envelope::Msg.
        // A raw frame or C/I envelope carrying Msg/Rcvd is a downgrade/forgery attempt
        // (anyone knowing snd_id can SEND) → drop. Handshake types (Hello/ConnInfo/
        // ConnInfoReply) stay raw by design and are not state-changing in recv_agent.
        if established && !authentic_msg && matches!(am, AgentMsg::Msg { .. } | AgentMsg::Rcvd { .. }) {
            return Ok(None);
        }
        Ok(Some(am))
    }

    /// Receive agent messages: reads blocks until one carries a MSG (skips stale
    /// response blocks, e.g. ACK Ok replies left by send_only). ACKs EVERY delivered
    /// MSG (queue cleanup, no QUEUE_FULL / redelivery) and returns the first parsed one.
    pub fn recv_agent(&mut self) -> Result<(Vec<u8>, AgentMsg), String> {
        // return a message that was already decoded from an earlier block first
        if let Some(m) = self.pending_msgs.pop_front() {
            return Ok(m);
        }
        loop {
            let msgs = self.client.recv_block().map_err(|e| e.to_string())?;
            let secret = self.dh_secret()?;
            let mut first: Option<(Vec<u8>, AgentMsg)> = None;
            for m in &msgs {
                if let BrokerMsg::Msg { msg_id, body } = m {
                    // Transport-decrypt failure = permanently invalid payload: ACK + drop,
                    // never wedge the queue on garbage (audit #3, U-12/H6).
                    let pt = match decrypt_for_recipient(&secret, msg_id, body) {
                        Some(pt) => pt,
                        None => {
                            self.client
                                .send_only(Command::Ack(msg_id.clone()), self.rcv_id.clone(), Some(&self.rcv_auth))
                                .map_err(|e| e.to_string())?;
                            continue;
                        }
                    };
                    // U-01/C1: fail-closed decode — in an established E2E session only
                    // Envelope::Msg frames that decrypt+parse are accepted.
                    let am = match self.decode_incoming(&pt)? {
                        Some(am) => am,
                        None => {
                            // forged frame (raw/confirmation/undecryptable): ACK + drop
                            self.client
                                .send_only(Command::Ack(msg_id.clone()), self.rcv_id.clone(), Some(&self.rcv_auth))
                                .map_err(|e| e.to_string())?;
                            continue;
                        }
                    };
                    // ACK the broker message so it is removed from the queue.
                    // send_only: request() here would swallow a concurrently pushed MSG.
                    self.client
                        .send_only(Command::Ack(msg_id.clone()), self.rcv_id.clone(), Some(&self.rcv_auth))
                        .map_err(|e| e.to_string())?;
                    // Keep EVERY decoded message: a block may carry several MSG
                    // frames and the old code ACKed them all but returned only the
                    // first — the rest were dropped (audited 2026-11-23, P0-6).
                    self.pending_msgs.push_back((msg_id.clone(), am));
                    if first.is_none() {
                        first = self.pending_msgs.pop_front();
                    }
                }
            }
            let _ = self.flush_outbox();
            if let Some(f) = first {
                return Ok(f);
            }
            // block carried no MSG (e.g. stale Ok response) — read the next one
        }
    }

    /// Receive ALL pending agent messages: the ones already decoded from earlier
    /// blocks plus every MSG of the next block (audited 2026-11-23, P0-6).
    pub fn recv_agent_all(&mut self) -> Result<Vec<(Vec<u8>, AgentMsg)>, String> {
        let mut out: Vec<(Vec<u8>, AgentMsg)> = self.pending_msgs.drain(..).collect();
        loop {
            let msgs = self.client.recv_block().map_err(|e| e.to_string())?;
            let secret = self.dh_secret()?;
            let mut found = false;
            for m in &msgs {
                if let BrokerMsg::Msg { msg_id, body } = m {
                    let pt = match decrypt_for_recipient(&secret, msg_id, body) {
                        Some(pt) => pt,
                        None => {
                            self.client
                                .send_only(Command::Ack(msg_id.clone()), self.rcv_id.clone(), Some(&self.rcv_auth))
                                .map_err(|e| e.to_string())?;
                            continue;
                        }
                    };
                    let am = match self.decode_incoming(&pt)? {
                        Some(am) => am,
                        None => {
                            self.client
                                .send_only(Command::Ack(msg_id.clone()), self.rcv_id.clone(), Some(&self.rcv_auth))
                                .map_err(|e| e.to_string())?;
                            continue;
                        }
                    };
                    self.client
                        .send_only(Command::Ack(msg_id.clone()), self.rcv_id.clone(), Some(&self.rcv_auth))
                        .map_err(|e| e.to_string())?;
                    out.push((msg_id.clone(), am));
                    found = true;
                }
            }
            let _ = self.flush_outbox();
            if found || out.is_empty() {
                if out.is_empty() {
                    // no MSG in this block: keep reading (stale OK responses)
                    continue;
                }
                return Ok(out);
            }
        }
    }

    /// Send A_RCVD for a received agent msg id.
    pub fn send_rcvd(&mut self, agent_msg_id: i64, msg_hash: &[u8]) -> Result<(), String> {
        self.msg_counter += 1;
        let frame = encode_agent(
            &AgentMsg::Rcvd { msg_id: 0, prev_hash: vec![], receipts: vec![Receipt { agent_msg_id, msg_hash: msg_hash.to_vec(), rcpt_info: b"ok".to_vec() }] },
            self.msg_counter,
            &self.prev_hash,
        );
        let enc = self.encrypt_frame(frame)?;
        let wire = crate::agent_envelope::encode(&crate::agent_envelope::Envelope::Msg { enc_agent_msg: enc });
        self.client
            .request(Command::Send { flags: false, body: wire }, self.peer_snd_id.clone().ok_or("no peer")?, None)
            .map_err(|e| e.to_string())?;
        Ok(())
    }
}