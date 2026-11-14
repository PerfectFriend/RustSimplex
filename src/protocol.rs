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

pub const SMP_VERSION: u16 = 23; // currentServerSMPRelayVersion (server range 15..23)
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
    /// PRXY <host> <port> [basicAuth] — ask router to open a proxied session to another router
    Proxy { host: Vec<u8>, port: Vec<u8>, auth: Option<Vec<u8>> },
    /// PFWD <smpVersion u16> <commandKey SPKI> <tail: enc transmission padded to 16226>
    Pfwd { version: u16, command_key: Vec<u8>, enc: Vec<u8> },
    /// RFWD <tail: enc fwdTransmission> — proxy router -> destination router
    Rfwd { enc: Vec<u8> },
    /// FNEW <size u64> <digest 32B> <senderKey SPKI> — register a new XFTP data packet (sender-signed)
    Fnew { size: u64, digest: Vec<u8>, sender_key: Vec<u8> },
    /// FPUT <packetId> <offset u32> <largeString: nonce24||secretbox(chunk)> — upload one encrypted chunk
    Fput { packet_id: Vec<u8>, offset: u32, chunk: Vec<u8> },
    /// FGET <packetId> <offset u32> — download chunks starting at offset (as many as fit one block)
    Fget { packet_id: Vec<u8>, offset: u32 },
    /// FDEL <packetId> — delete packet (sender-signed)
    Fdel { packet_id: Vec<u8> },
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
    /// PKEY <sessionId> <vMin u16> <vMax u16> <certChain+signedKey blob shortString>
    Pkey { session_id: Vec<u8>, v_min: u16, v_max: u16, cert_key: Vec<u8> },
    /// PRES <tail: enc response>
    Pres { enc: Vec<u8> },
    /// RRES <tail: enc fwd response>
    Rres { enc: Vec<u8> },
    /// FID <packetId> — packet registered
    Fid { packet_id: Vec<u8> },
    /// FDATA <offset u32> <largeString: chunk> — one chunk of a packet (several per block)
    Fdata { offset: u32, chunk: Vec<u8> },
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
            // v>=17 ntfCreds = Maybe NewNtfCreds; Some carries the pre-encoded Large(auth SPKI)+Large(dh SPKI)
            match ntf_creds {
                None => o.push(b'0'),
                Some(blob) => { o.push(b'1'); o.extend_from_slice(blob); }
            }
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
        Command::Proxy { host, port, auth } => {
            o.extend_from_slice(b"PRXY ");
            w_short(&mut o, host)?;
            w_short(&mut o, port)?;
            w_maybe(&mut o, auth.as_deref())?;
        }
        Command::Pfwd { version, command_key, enc } => {
            o.extend_from_slice(b"PFWD ");
            w_u16(&mut o, *version);
            o.push(b' ');
            w_short(&mut o, command_key)?;
            o.extend_from_slice(enc); // Tail
        }
        Command::Rfwd { enc } => {
            o.extend_from_slice(b"RFWD ");
            o.extend_from_slice(enc); // Tail
        }
        Command::Fnew { size, digest, sender_key } => {
            o.extend_from_slice(b"FNEW ");
            w_u64(&mut o, *size);
            o.push(b' ');
            w_short(&mut o, digest)?;
            o.push(b' ');
            w_short(&mut o, sender_key)?;
        }
        Command::Fput { packet_id, offset, chunk } => {
            o.extend_from_slice(b"FPUT ");
            w_short(&mut o, packet_id)?;
            o.push(b' ');
            w_u32(&mut o, *offset);
            o.push(b' ');
            w_large(&mut o, chunk)?;
        }
        Command::Fget { packet_id, offset } => {
            o.extend_from_slice(b"FGET ");
            w_short(&mut o, packet_id)?;
            o.push(b' ');
            w_u32(&mut o, *offset);
        }
        Command::Fdel { packet_id } => {
            o.extend_from_slice(b"FDEL ");
            w_short(&mut o, packet_id)?;
        }
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
        BrokerMsg::Pkey { session_id, v_min, v_max, cert_key } => {
            o.extend_from_slice(b"PKEY ");
            w_short(&mut o, session_id)?;
            w_u16(&mut o, *v_min);
            w_u16(&mut o, *v_max);
            w_short(&mut o, cert_key)?;
        }
        BrokerMsg::Pres { enc } => { o.extend_from_slice(b"PRES "); o.extend_from_slice(enc); }
        BrokerMsg::Rres { enc } => { o.extend_from_slice(b"RRES "); o.extend_from_slice(enc); }
        BrokerMsg::Fid { packet_id } => {
            o.extend_from_slice(b"FID ");
            w_short(&mut o, packet_id)?;
        }
        BrokerMsg::Fdata { offset, chunk } => {
            o.extend_from_slice(b"FDATA ");
            w_u32(&mut o, *offset);
            o.push(b' ');
            w_large(&mut o, chunk)?;
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
        b"PKEY" => {
            let session_id = r.short()?;
            let v_min = r.u16()?;
            let v_max = r.u16()?;
            let cert_key = r.short()?;
            Ok(BrokerMsg::Pkey { session_id, v_min, v_max, cert_key })
        }
        b"PRES" => Ok(BrokerMsg::Pres { enc: r.rest().to_vec() }),
        b"RRES" => Ok(BrokerMsg::Rres { enc: r.rest().to_vec() }),
        b"FID" => Ok(BrokerMsg::Fid { packet_id: r.short()? }),
        b"FDATA" => {
            let offset = r.u32()?;
            r.u8()?;
            let chunk = r.large()?;
            Ok(BrokerMsg::Fdata { offset, chunk })
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
        b"PRXY" => {
            let host = r.short()?;
            let port = r.short()?;
            let auth = read_maybe_vec(&mut r)?;
            Ok(Command::Proxy { host, port, auth })
        }
        b"PFWD" => {
            let version = r.u16()?;
            r.u8()?; // space
            let command_key = r.short()?;
            let enc = r.rest().to_vec();
            Ok(Command::Pfwd { version, command_key, enc })
        }
        b"RFWD" => Ok(Command::Rfwd { enc: r.rest().to_vec() }),
        b"FNEW" => {
            let size = r.u64()?;
            r.u8()?;
            let digest = r.short()?;
            r.u8()?;
            let sender_key = r.short()?;
            Ok(Command::Fnew { size, digest, sender_key })
        }
        b"FPUT" => {
            let packet_id = r.short()?;
            r.u8()?;
            let offset = r.u32()?;
            r.u8()?;
            let chunk = r.large()?;
            Ok(Command::Fput { packet_id, offset, chunk })
        }
        b"FGET" => {
            let packet_id = r.short()?;
            r.u8()?;
            let offset = r.u32()?;
            Ok(Command::Fget { packet_id, offset })
        }
        b"FDEL" => Ok(Command::Fdel { packet_id: r.short()? }),
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

/// Unpadded block content (count + large transmissions) — used as plaintext input for strict block encryption.
pub fn encode_block_raw(transmissions: &[Vec<u8>]) -> Result<Vec<u8>, EncodeError> {
    if transmissions.is_empty() || transmissions.len() > 255 {
        return Err(EncodeError("bad transmission count".into()));
    }
    let mut content = Vec::new();
    content.push(transmissions.len() as u8);
    for t in transmissions {
        w_large(&mut content, t)?;
    }
    Ok(content)
}

/// Decode strict (decrypted, unpadded) block content into wire-transmissions.
pub fn decode_block_raw(content: &[u8]) -> Result<Vec<Vec<u8>>, EncodeError> {
    let mut r = Reader::new(content);
    let count = r.u8()? as usize;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        out.push(r.large()?);
    }
    Ok(out)
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
