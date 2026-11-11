//! SMP protocol: commands, broker messages, transmission & transport-block codec.
//! Negotiated version: 17 (newNtfCredsSMPVersion) — the "full" form where all
//! optional IDS/NEW fields are present as Maybe ("0"/"1").
//!
//! Wire layout (v >= 7, implySessId = true; sessionId is bound into the
//! authenticator but NOT sent on the wire):
//!   transmission = shortString(authenticator) shortString(corrId) shortString(entityId) command
//!   authorized   = shortString(sessionId) <> shortString(corrId) <> shortString(entityId) <> command
//!   block        = pad( countByte <> concat( largeString(transmission) ), 16384 )

use crate::crypto::*;
use crate::encoding::*;

pub const SMP_VERSION: u16 = 17;
pub const MAX_RCV_MSG_LEN: usize = 16104; // MaxMessageLen(16088) + 16

#[derive(Debug, Clone)]
pub enum Command {
    New {
        rcv_auth_key: Vec<u8>, // SPKI DER
        rcv_dh_key: Vec<u8>,   // SPKI DER (X25519)
        basic_auth: Option<Vec<u8>>,
        sub_mode: u8, // b'S' subscribe | b'C' only-create
        queue_req_data: Option<Vec<u8>>,
        ntf_creds: Option<Vec<u8>>,
    },
    Sub,
    Key(Vec<u8>),
    Skey(Vec<u8>),
    Send { flags: bool, body: Vec<u8> },
    Ping,
    Get,
    Ack(Vec<u8>),
    Off,
    Del,
    /// NKEY <notifierKey SPKI> <recipientNtfDhKey SPKI> — enable notifications (recipient-signed)
    Nkey { ntf_key: Vec<u8>, rcv_ntf_dh_key: Vec<u8> },
    /// NSUB — subscribe to NMSG pushes on the notifier queue (notifier-key-signed, entity = ntf_id)
    Nsub,
    /// NDEL — disable notifications (recipient-signed)
    Ndel,
}

#[derive(Debug, Clone)]
pub enum BrokerMsg {
    Ids {
        rcv_id: Vec<u8>,
        snd_id: Vec<u8>,
        rcv_dh_key: Vec<u8>, // SPKI DER
        queue_mode: Option<Vec<u8>>,
        link_id: Option<Vec<u8>>,
        service_id: Option<Vec<u8>>,
        ntf_creds: Option<Vec<u8>>,
    },
    Sok(Option<Vec<u8>>),
    Msg { msg_id: Vec<u8>, body: Vec<u8> },
    /// NID <ntfId> <srvNtfDhPub SPKI>
    Nid { ntf_id: Vec<u8>, srv_ntf_dh: Vec<u8> },
    /// NMSG <nonce 24B raw> <encMeta shortString>
    Nmsg { nonce: Vec<u8>, enc_meta: Vec<u8> },
    Ok,
    Err(String),
    Pong,
    End,
    Deld,
}

pub fn encode_command(c: &Command) -> Result<Vec<u8>, EncodeError> {
    let mut o = Vec::new();
    match c {
        Command::New { rcv_auth_key, rcv_dh_key, basic_auth, sub_mode, queue_req_data, ntf_creds } => {
            o.extend_from_slice(b"NEW ");
            w_short(&mut o, rcv_auth_key)?;
            w_short(&mut o, rcv_dh_key)?;
            w_maybe(&mut o, basic_auth.as_deref())?;
            o.push(*sub_mode);
            w_maybe(&mut o, queue_req_data.as_deref())?;
            w_maybe(&mut o, ntf_creds.as_deref())?;
        }
        Command::Sub => o.extend_from_slice(b"SUB"),
        Command::Key(k) => { o.extend_from_slice(b"KEY "); w_short(&mut o, k)?; }
        Command::Skey(k) => { o.extend_from_slice(b"SKEY "); w_short(&mut o, k)?; }
        Command::Send { flags, body } => {
            o.extend_from_slice(b"SEND ");
            w_bool(&mut o, *flags);
            o.push(b' ');
            o.extend_from_slice(body); // Tail — raw, no length prefix
        }
        Command::Ping => o.extend_from_slice(b"PING"),
        Command::Get => o.extend_from_slice(b"GET"),
        Command::Ack(m) => { o.extend_from_slice(b"ACK "); w_short(&mut o, m)?; }
        Command::Off => o.extend_from_slice(b"OFF"),
        Command::Del => o.extend_from_slice(b"DEL"),
        Command::Nkey { ntf_key, rcv_ntf_dh_key } => {
            o.extend_from_slice(b"NKEY ");
            w_short(&mut o, ntf_key)?;
            w_short(&mut o, rcv_ntf_dh_key)?;
        }
        Command::Nsub => o.extend_from_slice(b"NSUB"),
        Command::Ndel => o.extend_from_slice(b"NDEL"),
    }
    Ok(o)
}

pub fn encode_broker(m: &BrokerMsg) -> Result<Vec<u8>, EncodeError> {
    let mut o = Vec::new();
    match m {
        BrokerMsg::Ids { rcv_id, snd_id, rcv_dh_key, queue_mode, link_id, service_id, ntf_creds } => {
            o.extend_from_slice(b"IDS ");
            w_short(&mut o, rcv_id)?;
            w_short(&mut o, snd_id)?;
            w_short(&mut o, rcv_dh_key)?;
            w_maybe(&mut o, queue_mode.as_deref())?;
            w_maybe(&mut o, link_id.as_deref())?;
            w_maybe(&mut o, service_id.as_deref())?;
            w_maybe(&mut o, ntf_creds.as_deref())?;
        }
        BrokerMsg::Sok(s) => { o.extend_from_slice(b"SOK "); w_maybe(&mut o, s.as_deref())?; }
        BrokerMsg::Msg { msg_id, body } => {
            o.extend_from_slice(b"MSG ");
            w_short(&mut o, msg_id)?;
            o.extend_from_slice(body); // Tail
        }
        BrokerMsg::Ok => o.extend_from_slice(b"OK"),
        BrokerMsg::Nid { ntf_id, srv_ntf_dh } => {
            o.extend_from_slice(b"NID ");
            w_short(&mut o, ntf_id)?;
            w_short(&mut o, srv_ntf_dh)?;
        }
        BrokerMsg::Nmsg { nonce, enc_meta } => {
            o.extend_from_slice(b"NMSG ");
            o.extend_from_slice(nonce); // 24-byte raw nonce, no length prefix
            w_short(&mut o, enc_meta)?;
        }
        BrokerMsg::Err(e) => { o.extend_from_slice(b"ERR "); o.extend_from_slice(e.as_bytes()); }
        BrokerMsg::Pong => o.extend_from_slice(b"PONG"),
        BrokerMsg::End => o.extend_from_slice(b"END"),
        BrokerMsg::Deld => o.extend_from_slice(b"DLED"),
    }
    Ok(o)
}

/// Raw command/broker bytes -> tag string (first token).
pub fn tag_of(cmd: &[u8]) -> String {
    let end = cmd.iter().position(|&c| c == b' ').unwrap_or(cmd.len());
    String::from_utf8_lossy(&cmd[..end]).to_string()
}

fn read_tag<'a>(r: &mut Reader<'a>, cmd: &'a [u8]) -> Vec<u8> {
    let mut t = Vec::new();
    while r.pos < cmd.len() && cmd[r.pos] != b' ' {
        t.push(cmd[r.pos]);
        r.pos += 1;
    }
    if r.pos < cmd.len() {
        r.pos += 1; // skip space
    }
    t
}

fn read_maybe_vec(r: &mut Reader) -> Result<Option<Vec<u8>>, EncodeError> {
    if r.maybe_marker()? {
        // a maybe-encoded value here is itself a shortString for our fields
        Ok(Some(r.short()?))
    } else {
        Ok(None)
    }
}

pub fn parse_broker(cmd: &[u8]) -> Result<BrokerMsg, EncodeError> {
    let mut r = Reader::new(cmd);
    let tag = read_tag(&mut r, cmd);
    match tag.as_slice() {
        b"IDS" => Ok(BrokerMsg::Ids {
            rcv_id: r.short()?,
            snd_id: r.short()?,
            rcv_dh_key: r.short()?,
            queue_mode: read_maybe_vec(&mut r)?,
            link_id: read_maybe_vec(&mut r)?,
            service_id: read_maybe_vec(&mut r)?,
            ntf_creds: read_maybe_vec(&mut r)?,
        }),
        b"SOK" => Ok(BrokerMsg::Sok(read_maybe_vec(&mut r)?)),
        b"MSG" => {
            let msg_id = r.short()?;
            let body = r.rest().to_vec();
            Ok(BrokerMsg::Msg { msg_id, body })
        }
        b"OK" => Ok(BrokerMsg::Ok),
        b"NID" => Ok(BrokerMsg::Nid { ntf_id: r.short()?, srv_ntf_dh: r.short()? }),
        b"NMSG" => {
            let nonce = r.take(24)?.to_vec();
            let enc_meta = r.short()?;
            Ok(BrokerMsg::Nmsg { nonce, enc_meta })
        }
        b"ERR" => Ok(BrokerMsg::Err(String::from_utf8_lossy(r.rest()).to_string())),
        b"PONG" => Ok(BrokerMsg::Pong),
        b"END" => Ok(BrokerMsg::End),
        b"DLED" => Ok(BrokerMsg::Deld),
        _ => Err(EncodeError(format!(
            "parse_broker: unhandled tag {:?}",
            String::from_utf8_lossy(&tag)
        ))),
    }
}

pub fn parse_command(cmd: &[u8]) -> Result<Command, EncodeError> {
    let mut r = Reader::new(cmd);
    let tag = read_tag(&mut r, cmd);
    match tag.as_slice() {
        b"NEW" => {
            let rcv_auth_key = r.short()?;
            let rcv_dh_key = r.short()?;
            let basic_auth = read_maybe_vec(&mut r)?;
            let sub_mode = r.u8()?;
            let queue_req_data = read_maybe_vec(&mut r)?;
            let ntf_creds = read_maybe_vec(&mut r)?;
            Ok(Command::New { rcv_auth_key, rcv_dh_key, basic_auth, sub_mode, queue_req_data, ntf_creds })
        }
        b"SUB" => Ok(Command::Sub),
        b"KEY" => Ok(Command::Key(r.short()?)),
        b"SKEY" => Ok(Command::Skey(r.short()?)),
        b"SEND" => {
            let flags = r.bool()?;
            r.u8()?; // space
            let body = r.rest().to_vec();
            Ok(Command::Send { flags, body })
        }
        b"PING" => Ok(Command::Ping),
        b"GET" => Ok(Command::Get),
        b"ACK" => Ok(Command::Ack(r.short()?)),
        b"OFF" => Ok(Command::Off),
        b"DEL" => Ok(Command::Del),
        b"NKEY" => Ok(Command::Nkey { ntf_key: r.short()?, rcv_ntf_dh_key: r.short()? }),
        b"NSUB" => Ok(Command::Nsub),
        b"NDEL" => Ok(Command::Ndel),
        _ => Err(EncodeError(format!(
            "parse_command: unhandled tag {:?}",
            String::from_utf8_lossy(&tag)
        ))),
    }
}

// ---------- Transmission ----------

#[derive(Debug, Clone)]
pub struct Transmission {
    pub authenticator: Vec<u8>,
    pub corr_id: Vec<u8>,
    pub entity_id: Vec<u8>,
    pub command: Vec<u8>, // raw command/broker bytes
}

/// authorized bytes that get signed / crypto_box'd:
/// shortString(sessionId) <> shortString(corrId) <> shortString(entityId) <> command
pub fn authorized_bytes(session_id: &[u8], t: &Transmission) -> Result<Vec<u8>, EncodeError> {
    let mut o = Vec::new();
    w_short(&mut o, session_id)?;
    w_short(&mut o, &t.corr_id)?;
    w_short(&mut o, &t.entity_id)?;
    o.extend_from_slice(&t.command);
    Ok(o)
}

/// wire bytes of a transmission (v>=7, normal client):
///   authenticator(shortString) [<> '0' serviceSig if authenticator non-empty] <> corrId <> entityId <> command(Tail)
/// serviceSig (Maybe) is read by the peer only when the authenticator is non-empty (serviceAuth connections).
pub fn encode_transmission(t: &Transmission) -> Result<Vec<u8>, EncodeError> {
    let mut o = Vec::new();
    w_short(&mut o, &t.authenticator)?;
    if !t.authenticator.is_empty() {
        o.push(b'0'); // serviceSig = Nothing (read only when authenticator non-empty)
    }
    w_short(&mut o, &t.corr_id)?;
    w_short(&mut o, &t.entity_id)?;
    o.extend_from_slice(&t.command);
    Ok(o)
}

pub fn decode_transmission(b: &[u8]) -> Result<Transmission, EncodeError> {
    let mut r = Reader::new(b);
    let authenticator = r.short()?;
    if !authenticator.is_empty() {
        let _service_sig = r.u8()?; // '0'/'1' Maybe tag (we only support Nothing)
    }
    let corr_id = r.short()?;
    let entity_id = r.short()?;
    let command = r.rest().to_vec();
    Ok(Transmission { authenticator, corr_id, entity_id, command })
}

/// Ed25519 signature authenticator over the authorized bytes.
pub fn auth_sign(session_id: &[u8], t: &mut Transmission, kp: &Ed25519Keypair) -> Result<(), EncodeError> {
    let a = authorized_bytes(session_id, t)?;
    t.authenticator = ed25519_sign(kp, &a).to_vec();
    Ok(())
}

/// X25519 crypto_box authenticator: secretbox(dhSecret, cb_nonce(corrId), sha512(authorized))
/// => 16-byte MAC + 64-byte ciphertext = 80 bytes.
pub fn auth_box(session_id: &[u8], t: &mut Transmission, dh_secret: &[u8; 32]) -> Result<(), EncodeError> {
    let a = authorized_bytes(session_id, t)?;
    let h = sha512(&a);
    let nonce = cb_nonce(&t.corr_id);
    t.authenticator = secretbox_encrypt(dh_secret, &nonce, &h);
    Ok(())
}

pub fn verify_sign(session_id: &[u8], t: &Transmission, pub_raw: &[u8; 32]) -> bool {
    let Ok(a) = authorized_bytes(session_id, t) else { return false };
    if t.authenticator.len() != SIG_LEN { return false; }
    let mut sig = [0u8; SIG_LEN];
    sig.copy_from_slice(&t.authenticator);
    ed25519_verify(pub_raw, &a, &sig)
}

pub fn verify_box(session_id: &[u8], t: &Transmission, dh_secret: &[u8; 32]) -> bool {
    let Ok(a) = authorized_bytes(session_id, t) else { return false };
    let h = sha512(&a);
    let nonce = cb_nonce(&t.corr_id);
    secretbox_decrypt(dh_secret, &nonce, &t.authenticator).map(|m| m == h).unwrap_or(false)
}

// ---------- Transport block ----------

/// Encode a set of wire-transmissions into one padded 16384-byte block.
pub fn encode_block(transmissions: &[Vec<u8>]) -> Result<Vec<u8>, EncodeError> {
    if transmissions.is_empty() || transmissions.len() > 255 {
        return Err(EncodeError("bad transmission count".into()));
    }
    let mut content = Vec::new();
    content.push(transmissions.len() as u8);
    for t in transmissions {
        w_large(&mut content, t)?;
    }
    pad(&content, BLOCK_SIZE)
}

/// Decode a 16384-byte block into wire-transmissions.
pub fn decode_block(block: &[u8]) -> Result<Vec<Vec<u8>>, EncodeError> {
    if block.len() != BLOCK_SIZE {
        return Err(EncodeError(format!("block len {} != {}", block.len(), BLOCK_SIZE)));
    }
    let content = unpad(block)?;
    let mut r = Reader::new(&content);
    let count = r.u8()? as usize;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        out.push(r.large()?);
    }
    Ok(out)
}
