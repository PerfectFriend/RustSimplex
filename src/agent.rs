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

// ---------- duplex connection over SMP ----------

pub struct Agent {
    pub client: Client,
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
}

impl Agent {
    fn dh_secret(&self) -> Result<[u8; 32], String> {
        let srv_raw = parse_spki(&self.srv_dh).map_err(|e| e.to_string())?.1;
        Ok(x25519_dh(&self.rcv_dh.secret, &x25519_public(srv_raw)))
    }

    /// Initiator: create a contact queue and produce a connection link.
    pub fn create_contact(mut client: Client, host: &str, port: u16, key_hash: &[u8], profile: &str) -> Result<(Agent, String), String> {
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
        let (rcv_id, snd_id, srv_dh) = match &r[0] {
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
        let conn_info = serde_json::to_vec(&ConnInfo { profile: profile.into(), pq_support: true, e2e: Some(e2e) }).map_err(|e| e.to_string())?;
        // subscribe immediately so the joiner's confirmation MSG is not missed
        let sub = client.request(Command::Sub, rcv_id.clone(), Some(&rcv_auth)).map_err(|e| e.to_string())?;
        if !matches!(sub[0], BrokerMsg::Sok(_)) {
            return Err(format!("SUB failed: {:?}", sub[0]));
        }
        // link carries the initiator's connInfo ("I" message) as URI-escaped param
        let link = format!(
            "smp://{}@{}:{}#{}?snd={}&ci={}",
            crate::xftp::hex(key_hash),
            host,
            port,
            crate::xftp::hex(&rcv_id),
            crate::xftp::hex(&snd_id),
            crate::xftp::hex(&conn_info)
        );
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
            },
            link,
        ))
    }

    /// Joiner: parse link, create reply queue, send "D" confirmation to the initiator.
    pub fn join_contact(mut client: Client, link: &str) -> Result<Agent, String> {
        // smp://keyHash@host:port#rcv_id?snd=..&ci=..
        let rest = link.strip_prefix("smp://").ok_or("bad link scheme")?;
        let (kh_host, frag) = rest.split_once('#').ok_or("bad link frag")?;
        let (kh, hostport) = kh_host.split_once('@').ok_or("bad link authority")?;
        let (host, port) = hostport.split_once(':').ok_or("bad hostport")?;
        let (rcv_hex, params) = frag.split_once('?').ok_or("bad link params")?;
        let _rcv_id = crate::xftp::unhex(rcv_hex).ok_or("bad rcv hex")?;
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
        let key_hash = crate::xftp::unhex(kh).ok_or("bad keyhash hex")?;
        let port: u16 = port.parse().map_err(|_| "bad port")?;

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
        let (my_rcv, my_snd, srv_dh) = match &r[0] {
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
        let ci_reply = serde_json::to_vec(&ConnInfo { profile: "joiner".into(), pq_support: true, e2e: Some(e2e_reply) }).map_err(|e| e.to_string())?;
        let body = encode_agent(&AgentMsg::ConnInfoReply(vec![qi], ci_reply), 1, &[0u8; 32]);
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
            initiator: false,
            outbox: Vec::new(),
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
                if let AgentMsg::ConnInfoReply(qs, ci) = parse_agent(&pt)? {
                    let peer = qs[0].sender_id.clone();
                    self.peer_snd_id = Some(peer);
                    // auto-negotiate E2E: SK = DH(our rcv_dh, joiner rcv_dh from queue info)
                    let peer_dh_raw = parse_spki(&qs[0].dh_pub).map_err(|e| e.to_string())?.1;
                    let sk = x25519_dh(&self.rcv_dh.secret, &x25519_public(peer_dh_raw));
                    let peer_kem = (|| {
                        let ci: ConnInfo = serde_json::from_slice(&ci).ok()?;
                        let e2e = ci.e2e?;
                        let mut r = Reader::new(&e2e);
                        match crate::pq::decode_e2e_ratchet_params(&mut r).ok()?.kem {
                            crate::pq::KemParams::Pk(pk) | crate::pq::KemParams::CtPk(_, pk) => Some(pk),
                            _ => None,
                        }
                    })().unwrap_or_default();
                    self.msg_counter += 1;
                    let hello = encode_agent(&AgentMsg::Hello { msg_id: 0, prev_hash: vec![] }, self.msg_counter, &self.prev_hash);
                    self.client
                        .request(Command::Send { flags: false, body: hello }, self.peer_snd_id.clone().ok_or("no peer")?, None)
                        .map_err(|e| e.to_string())?;
                    // init E2E only AFTER HELLO is sent (before any A_MSG)
                    if std::env::var("SMP_E2E").as_deref() == Ok("1") { self.init_e2e_sender(&sk, peer_dh_raw, peer_kem); }
                    return Ok(());
                }
            }
        }
        Err("no confirmation MSG".into())
    }

    /// Joiner: wait for HELLO on own queue, reply HELLO. (queue already subscribed in join_contact)
    pub fn await_hello(&mut self) -> Result<(), String> {
        let msgs = self.client.recv_block().map_err(|e| e.to_string())?;
        let secret = self.dh_secret()?;
        for m in &msgs {
            if let BrokerMsg::Msg { msg_id, body } = m {
                let pt = decrypt_for_recipient(&secret, msg_id, body).ok_or("decrypt failed")?;
                if matches!(parse_agent(&pt)?, AgentMsg::Hello { .. }) {
                    if !self.init_ci.is_empty() {
                        if let Ok(ci) = serde_json::from_slice::<ConnInfo>(&self.init_ci) {
                            if let Some(e2e) = ci.e2e {
                                if let Ok(params) = crate::pq::decode_e2e_ratchet_params(&mut Reader::new(&e2e)) {
                                    if let Ok((_, dh_raw)) = parse_spki(&params.snd_dh_spki) {
                                        let sk = x25519_dh(&self.rcv_dh.secret, &x25519_public(dh_raw));
                                    }
                                }
                            }
                        }
                    }
                    self.msg_counter += 1;
                    let hello = encode_agent(&AgentMsg::Hello { msg_id: 0, prev_hash: vec![] }, self.msg_counter, &self.prev_hash);
                    self.client
                        .request(Command::Send { flags: false, body: hello }, self.peer_snd_id.clone().ok_or("no peer")?, None)
                        .map_err(|e| e.to_string())?;
                    // init E2E only AFTER HELLO reply is sent
                    if !self.init_ci.is_empty() {
                        if let Ok(ci) = serde_json::from_slice::<ConnInfo>(&self.init_ci) {
                            if let Some(e2e) = ci.e2e {
                                if let Ok(params) = crate::pq::decode_e2e_ratchet_params(&mut Reader::new(&e2e)) {
                                    if let Ok((_, dh_raw)) = parse_spki(&params.snd_dh_spki) {
                                        let sk = x25519_dh(&self.rcv_dh.secret, &x25519_public(dh_raw));
                                        if std::env::var("SMP_E2E").as_deref() == Ok("1") { self.init_e2e_receiver(&sk, dh_raw)?; }
                                    }
                                }
                            }
                        }
                    }
                    return Ok(());
                }
            }
        }
        Err("no HELLO".into())
    }

    /// Send an application message (A_MSG). Returns the agent msg id used.
    /// Negotiate E2E as the sender (initiator): peer DH raw + peer KEM pk from connInfo.
    pub fn init_e2e_sender(&mut self, sk: &[u8; 32], peer_dh_raw: [u8; 32], peer_kem_pk: Vec<u8>) {
        self.ratchet = Some(crate::pqdr::PqdrRatchet::init_sender(
            sk,
            self.rcv_id.clone(),
            x25519_public(peer_dh_raw),
            peer_kem_pk,
        ));
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
        r.dh_r = x25519_public(peer_dh_raw);
        self.ratchet = Some(r);
        Ok(())
    }

    pub fn send_msg(&mut self, body: &[u8]) -> Result<i64, String> {
        self.msg_counter += 1;
        let id = self.msg_counter;
        let payload = match &mut self.ratchet {
            Some(r) => r.encrypt(body),
            None => body.to_vec(),
        };
        let hash = sha256(&encode_agent(&AgentMsg::Msg { msg_id: id, prev_hash: self.prev_hash.clone(), body: payload.clone() }, id, &self.prev_hash));
        let wire = encode_agent(&AgentMsg::Msg { msg_id: id, prev_hash: self.prev_hash.clone(), body: payload }, id, &self.prev_hash);
        // E2E: a fresh receiver has no ckr yet — buffer until the first inbound frame (double-ratchet rule)
        if let Some(r) = &self.ratchet {
            if !self.initiator && r.ckr.is_none() {
                self.outbox.push((id, wire));
                self.prev_hash = hash.to_vec();
                return Ok(id);
            }
        }
        self.client
            .request(Command::Send { flags: false, body: wire }, self.peer_snd_id.clone().ok_or("no peer")?, None)
            .map_err(|e| e.to_string())?;
        self.prev_hash = hash.to_vec();
        Ok(id)
    }

    /// Flush buffered E2E sends once the receiving chain exists.
    pub fn flush_outbox(&mut self) -> Result<(), String> {
        if self.outbox.is_empty() || !self.ratchet.as_ref().map(|r| r.ckr.is_some()).unwrap_or(false) {
            return Ok(());
        }
        let peer = self.peer_snd_id.clone().ok_or("no peer")?;
        for (_, w) in self.outbox.drain(..) {
            self.client.request(Command::Send { flags: false, body: w }, peer.clone(), None).map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    /// Receive one agent message (blocks on one block). Returns parsed message + raw msg_id.
    pub fn recv_agent(&mut self) -> Result<(Vec<u8>, AgentMsg), String> {
        let msgs = self.client.recv_block().map_err(|e| e.to_string())?;
        let secret = self.dh_secret()?;
        for m in &msgs {
            if let BrokerMsg::Msg { msg_id, body } = m {
                let pt = decrypt_for_recipient(&secret, msg_id, body).ok_or("decrypt failed")?;
                let mut am = parse_agent(&pt)?;
                if let AgentMsg::Msg { msg_id: mid, prev_hash: ph, body } = &am {
                    if let Some(r) = &mut self.ratchet {
                        let plain = r.decrypt(body)?;
                        am = AgentMsg::Msg { msg_id: *mid, prev_hash: ph.clone(), body: plain };
                    }
                }
                let _ = self.flush_outbox();
                return Ok((msg_id.clone(), am));
            }
        }
        Err("no MSG in block".into())
    }

    /// Send A_RCVD for a received agent msg id.
    pub fn send_rcvd(&mut self, agent_msg_id: i64, msg_hash: &[u8]) -> Result<(), String> {
        self.msg_counter += 1;
        let wire = encode_agent(
            &AgentMsg::Rcvd { msg_id: 0, prev_hash: vec![], receipts: vec![Receipt { agent_msg_id, msg_hash: msg_hash.to_vec(), rcpt_info: b"ok".to_vec() }] },
            self.msg_counter,
            &self.prev_hash,
        );
        self.client
            .request(Command::Send { flags: false, body: wire }, self.peer_snd_id.clone().ok_or("no peer")?, None)
            .map_err(|e| e.to_string())?;
        Ok(())
    }
}
