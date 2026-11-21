//! NTF (notifications server) transport — wire-compatible with simplexmq
//! `Simplex.Messaging.Notifications.Transport`.
//!
//! NTF is a *separate* protocol from SMP (the earlier assumption was wrong):
//! - block size is **512** bytes (`ntfBlockSize = 512`), not 16384;
//! - the server handshake is `NtfServerHandshake`:
//!   `u16 minVersion + u16 maxVersion + sessionId(short=32) [+ authPubKey Large(DER)]`;
//! - the client handshake is `NtfClientHandshake`: `u16 ntfVersion + keyHash`,
//!   where `KeyHash` is a Haskell `ByteString` => 1-byte length prefix (0x20) + 32 bytes
//!   (35 bytes total; no proxy flag, no authPubKey);
//! - NTF versions are 1..3 (`initialNTFVersion = 1`, `currentServerNTFVersion = 3`),
//!   and `authBatchCmdsNTFVersion = 2` gates the batch/auth commands;
//! - `keyHash` is the **fingerprint of the CA certificate** (SHA-256 over the CA cert DER),
//!   not the leaf SPKI — verified against the official relay address
//!   `smp11=1OwYGt-...` / `ntf=FB-Uop7...`.
//!
//! Reference: simplexmq/src/Simplex/Messaging/Notifications/Transport.hs,
//! Simplex/Messaging/Notifications/Server/Env.hs (`serverIdentity = C.KeyHash fp`).

use crate::crypto::sha256;
use crate::encoding::{w_short, w_u16, Reader};
use ed25519_dalek::{Signer, SigningKey};
use std::io::{Read, Write};

pub const NTF_BLOCK_SIZE: usize = 512;
pub const NTF_VERSION_INITIAL: u16 = 1;
pub const NTF_VERSION_SERVER_MAX: u16 = 3;
pub const NTF_VERSION_CLIENT_MAX: u16 = 3;
/// Commands with batch auth are enabled from this NTF version on.
pub const NTF_VERSION_AUTH_BATCH: u16 = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtfServerHandshake {
    pub min_version: u16,
    pub max_version: u16,
    pub session_id: Vec<u8>,
    /// DER of the server's signed X25519 public key (present when max_version >= 2).
    pub auth_pub_key: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtfClientHandshake {
    pub ntf_version: u16,
    pub key_hash: [u8; 32],
}

/// Parse an NTF server handshake block payload (without the u16 length prefix).
pub fn parse_ntf_server_handshake(payload: &[u8]) -> Result<NtfServerHandshake, String> {
    let mut r = Reader::new(payload);
    let min_version = r.u16().map_err(|e| e.to_string())?;
    let max_version = r.u16().map_err(|e| e.to_string())?;
    let session_id = r.short().map_err(|e| e.to_string())?;
    let auth_pub_key = if max_version >= NTF_VERSION_AUTH_BATCH {
        // `C.SignedObject` = Large (u16 len) + DER
        let der = r.large().map_err(|e| e.to_string())?;
        Some(der)
    } else {
        None
    };
    Ok(NtfServerHandshake { min_version, max_version, session_id, auth_pub_key })
}

/// Encode an NTF client handshake: `u16 ntfVersion + 32B keyHash`.
pub fn encode_ntf_client_handshake(hs: &NtfClientHandshake) -> Vec<u8> {
    let mut v = Vec::with_capacity(35);
    w_u16(&mut v, hs.ntf_version);
    // Haskell `KeyHash` uses the ByteString encoding: 1-byte length prefix + bytes
    w_short(&mut v, &hs.key_hash).expect("fixed-size");
    v
}

/// Pad an NTF block: `u16 BE len + payload + '#'` to exactly `NTF_BLOCK_SIZE`.
pub fn pad_ntf_block(payload: &[u8]) -> Result<Vec<u8>, String> {
    if payload.len() + 2 > NTF_BLOCK_SIZE {
        return Err(format!("ntf payload too large: {}", payload.len()));
    }
    let mut v = Vec::with_capacity(NTF_BLOCK_SIZE);
    v.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    v.extend_from_slice(payload);
    v.resize(NTF_BLOCK_SIZE, b'#');
    Ok(v)
}

/// Unpad an NTF block: strip the `u16 BE len` prefix and trailing '#' padding.
pub fn unpad_ntf_block(block: &[u8]) -> Result<Vec<u8>, String> {
    if block.len() < 2 {
        return Err("ntf block too short".into());
    }
    let len = u16::from_be_bytes([block[0], block[1]]) as usize;
    if len + 2 > block.len() {
        return Err(format!("ntf block len {len} exceeds block size {}", block.len()));
    }
    Ok(block[2..2 + len].to_vec())
}

/// keyHash = SHA-256 over the DER of the **CA certificate** that signs the server chain.
pub fn key_hash_from_ca_der(ca_der: &[u8]) -> [u8; 32] {
    sha256(ca_der)
}

/// Pick the negotiated NTF version for a client given the server's range.
pub fn negotiate_ntf_version(server: &NtfServerHandshake) -> Result<u16, String> {
    if server.max_version < NTF_VERSION_INITIAL || server.min_version > NTF_VERSION_CLIENT_MAX {
        return Err(format!("incompatible NTF version range {}..{}", server.min_version, server.max_version));
    }
    Ok(server.max_version.min(NTF_VERSION_CLIENT_MAX))
}

// ---------------------------------------------------------------------------
// NTF commands and responses (simplexmq Notifications/Protocol.hs)
// ---------------------------------------------------------------------------

/// NTF entity kinds: token commands vs subscription commands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NtfEntity {
    Token,
    Subscription,
}

/// NTF command tags (`NtfCommandTag`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NtfCommandTag {
    Tnew,
    Tvfy,
    Tchk,
    Trpl,
    Tdel,
    Tcrn,
    Snew,
    Schk,
    Sdel,
    Ping,
}

impl NtfCommandTag {
    pub fn tag_bytes(&self) -> &'static [u8] {
        match self {
            NtfCommandTag::Tnew => b"TNEW",
            NtfCommandTag::Tvfy => b"TVFY",
            NtfCommandTag::Tchk => b"TCHK",
            NtfCommandTag::Trpl => b"TRPL",
            NtfCommandTag::Tdel => b"TDEL",
            NtfCommandTag::Tcrn => b"TCRN",
            NtfCommandTag::Snew => b"SNEW",
            NtfCommandTag::Schk => b"SCHK",
            NtfCommandTag::Sdel => b"SDEL",
            NtfCommandTag::Ping => b"PING",
        }
    }

    pub fn entity(&self) -> NtfEntity {
        match self {
            NtfCommandTag::Tnew | NtfCommandTag::Tvfy | NtfCommandTag::Tchk | NtfCommandTag::Trpl
            | NtfCommandTag::Tdel | NtfCommandTag::Tcrn => NtfEntity::Token,
            NtfCommandTag::Snew | NtfCommandTag::Schk | NtfCommandTag::Sdel | NtfCommandTag::Ping => {
                NtfEntity::Subscription
            }
        }
    }
}

/// NTF command: tag + optional payload (already-encoded inner bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtfCommand {
    pub tag: NtfCommandTag,
    pub payload: Vec<u8>,
}

impl NtfCommand {
    pub fn new(tag: NtfCommandTag) -> Self {
        NtfCommand { tag, payload: Vec::new() }
    }

    pub fn with_payload(tag: NtfCommandTag, payload: Vec<u8>) -> Self {
        NtfCommand { tag, payload }
    }

    /// Encode: `tag` + ' ' + payload (commands without payload are just the tag).
    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(self.tag.tag_bytes());
        if !self.payload.is_empty() {
            v.push(b' ');
            v.extend_from_slice(&self.payload);
        }
        v
    }
}

// ---------------------------------------------------------------------------
// NTF signed commands (TNEW / SNEW) — W2, Task 2.1 + 2.2
//
// Reference (vendored Haskell-etalon `simplexmq/`):
//
//   Notifications/Protocol.hs:168-172
//     instance Encoding (NewNtfEntity e) where
//       NewNtfTkn tkn verifyKey dhPubKey -> smpEncode ('T', tkn, verifyKey, dhPubKey)
//       NewNtfSub tknId smpQueue notifierKey -> smpEncode ('S', tknId, smpQueue, notifierKey)
//
//   Notifications/Protocol.hs:248-249
//     TNEW {} -> sigNoEntity ; SNEW {} -> sigNoEntity
//     (i.e. entityId is empty for these two commands)
//
//   Protocol.hs:2343-2349
//     tForAuth = smpEncode sessionId <> t'
//     t'       = encodeTransmission_ v t
//     encodeTransmission_ v (CorrId corrId, queueId, command) =
//       smpEncode (corrId, queueId) <> encodeProtocol v command
//
//   Protocol.hs:1744-1757 (server side)
//     authorized' = if implySessId then smpEncode sessionId <> authorized else authorized
//     => on NTF v2+ the sessionId is NOT on the wire but IS part of the signed bytes.
//
//   Encoding.hs:102-104 — a Haskell `ByteString` encodes as a 1-byte length prefix
//   ("shortString"): `smpEncode s = B.cons (lenEncode $ B.length s) s`.
// ---------------------------------------------------------------------------

/// The `authorized` bytes of an NTF command — the exact byte string that is signed.
///
/// Haskell `Protocol.hs:2347`: `tForAuth = smpEncode sessionId <> t'` where
/// `t' = smpEncode (corrId, queueId) <> command`.
///
/// Every component is a Haskell `ByteString` and therefore carries a 1-byte length prefix.
///
/// `entity_id` is empty for `TNEW`/`SNEW` (Haskell `sigNoEntity`) and carries the
/// subscription/token id for the other commands.
pub fn ntf_authorized_bytes(
    session_id: &[u8],
    corr_id: &[u8],
    entity_id: &[u8],
    command: &[u8],
) -> Result<Vec<u8>, String> {
    let mut v = Vec::new();
    w_short(&mut v, session_id).map_err(|e| e.to_string())?;
    w_short(&mut v, corr_id).map_err(|e| e.to_string())?;
    w_short(&mut v, entity_id).map_err(|e| e.to_string())?;
    v.extend_from_slice(command);
    Ok(v)
}

/// Sign an NTF command with Ed25519 over [`ntf_authorized_bytes`].
///
/// This is the NTF counterpart of `protocol::auth_sign`: the signature replaces the
/// `authenticator` field of the transmission.
pub fn sign_ntf_command(
    session_id: &[u8],
    corr_id: &[u8],
    entity_id: &[u8],
    command: &[u8],
    sk: &ed25519_dalek::SigningKey,
) -> [u8; 64] {
    let msg = ntf_authorized_bytes(session_id, corr_id, entity_id, command)
        .expect("ntf_authorized_bytes: lengths are bounded by the 1-byte shortString limit");
    sk.sign(&msg).to_bytes()
}

/// Verify an NTF command signature against the `authorized` bytes.
pub fn verify_ntf_command(
    session_id: &[u8],
    corr_id: &[u8],
    entity_id: &[u8],
    command: &[u8],
    pub_raw: &[u8; 32],
    signature: &[u8],
) -> bool {
    if signature.len() != 64 {
        return false;
    }
    let Ok(msg) = ntf_authorized_bytes(session_id, corr_id, entity_id, command) else {
        return false;
    };
    let mut sig = [0u8; 64];
    sig.copy_from_slice(signature);
    crate::crypto::ed25519_verify(pub_raw, &msg, &sig)
}

/// Wire encoding of `NewNtfEntity 'Token`.
///
/// Haskell: `smpEncode ('T', tkn, verifyKey, dhPubKey)` — a `Char` is one byte
/// (`Encoding.hs:54-56`), and each `ByteString` gets a 1-byte length prefix.
///
/// * `token` — the device token (`DeviceToken`);
/// * `verify_key` — the Ed25519 public auth key as SPKI DER;
/// * `dh_pub_key` — the X25519 public key as SPKI DER.
pub fn encode_new_ntf_token(
    token: &[u8],
    verify_key: &[u8],
    dh_pub_key: &[u8],
) -> Result<Vec<u8>, String> {
    let mut v = Vec::with_capacity(1 + token.len() + verify_key.len() + dh_pub_key.len() + 3);
    v.push(b'T');
    w_short(&mut v, token).map_err(|e| e.to_string())?;
    w_short(&mut v, verify_key).map_err(|e| e.to_string())?;
    w_short(&mut v, dh_pub_key).map_err(|e| e.to_string())?;
    Ok(v)
}

/// Wire encoding of `NewNtfEntity 'Subscription`.
///
/// Haskell: `smpEncode ('S', tknId, smpQueue, notifierKey)` where
/// `SMPQueueNtf` = `smpEncode (smpServer, notifierId)`
/// (`Notifications/Protocol.hs:384-395`).
///
/// * `tkn_id` — the notification token id;
/// * `smp_server` — the SMP server address of the subscription;
/// * `notifier_id` — the notifier (queue) id of the subscription;
/// * `notifier_key` — the Ed25519 public auth key of the notifier, as SPKI DER.
pub fn encode_new_ntf_sub(
    tkn_id: &[u8],
    smp_server: &[u8],
    notifier_id: &[u8],
    notifier_key: &[u8],
) -> Result<Vec<u8>, String> {
    let mut v = Vec::with_capacity(1 + tkn_id.len() + smp_server.len() + notifier_id.len() + notifier_key.len() + 4);
    v.push(b'S');
    w_short(&mut v, tkn_id).map_err(|e| e.to_string())?;
    // SMPQueueNtf = smpEncode (smpServer, notifierId)
    w_short(&mut v, smp_server).map_err(|e| e.to_string())?;
    w_short(&mut v, notifier_id).map_err(|e| e.to_string())?;
    w_short(&mut v, notifier_key).map_err(|e| e.to_string())?;
    Ok(v)
}

/// Build the full `TNEW` command bytes: `TNEW ` + encoded `NewNtfEntity 'Token`.
///
/// Haskell: `e (TNEW_, ' ', newTkn)` (`Notifications/Protocol.hs:198`).
pub fn build_tnew(token: &[u8], verify_key: &[u8], dh_pub_key: &[u8]) -> Result<Vec<u8>, String> {
    let mut v = b"TNEW ".to_vec();
    v.extend_from_slice(&encode_new_ntf_token(token, verify_key, dh_pub_key)?);
    Ok(v)
}

/// Build the full `SNEW` command bytes: `SNEW ` + encoded `NewNtfEntity 'Subscription`.
///
/// Haskell: `e (SNEW_, ' ', newSub)` (`Notifications/Protocol.hs:210`).
pub fn build_snew(
    tkn_id: &[u8],
    smp_server: &[u8],
    notifier_id: &[u8],
    notifier_key: &[u8],
) -> Result<Vec<u8>, String> {
    let mut v = b"SNEW ".to_vec();
    v.extend_from_slice(&encode_new_ntf_sub(tkn_id, smp_server, notifier_id, notifier_key)?);
    Ok(v)
}

// ---------------------------------------------------------------------------
// NTF transmissions (simplexmq Protocol.hs `encodeTransmission` / `batchTransmissions_`)
// ---------------------------------------------------------------------------

/// A raw NTF transmission: `authenticator | corrId | entityId | command`.
///
/// On NTF v>=2 (`implySessId = True`) the sessionId is **not** on the wire — it is implied by
/// the TLS session — and blocks carry **batches**: `u8 count` followed by `count` transmissions,
/// each wrapped in `Large` (u16 length + bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtfTransmission {
    /// Raw authenticator bytes (empty for unauthenticated commands such as PING).
    pub authenticator: Vec<u8>,
    pub corr_id: Vec<u8>,
    pub entity_id: Vec<u8>,
    /// Encoded command bytes (tail).
    pub command: Vec<u8>,
}

impl NtfTransmission {
    /// Encode a transmission body (without the batch/`Large` wrapper).
    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::new();
        // authenticator: Haskell ByteString encoding = 1-byte length + bytes
        v.push(self.authenticator.len() as u8);
        v.extend_from_slice(&self.authenticator);
        // corrId: ByteString (1-byte length)
        v.push(self.corr_id.len() as u8);
        v.extend_from_slice(&self.corr_id);
        // entityId: ByteString (1-byte length)
        v.push(self.entity_id.len() as u8);
        v.extend_from_slice(&self.entity_id);
        // command: Tail (raw)
        v.extend_from_slice(&self.command);
        v
    }

    /// Wrap the transmission in `Large` (u16 length + bytes) — used inside batches.
    pub fn encode_large(&self) -> Vec<u8> {
        let body = self.encode();
        let mut v = Vec::with_capacity(body.len() + 2);
        v.extend_from_slice(&(body.len() as u16).to_be_bytes());
        v.extend_from_slice(&body);
        v
    }

    /// Parse a transmission body (without the `Large` wrapper).
    pub fn parse(body: &[u8]) -> Result<NtfTransmission, String> {
        let mut r = Reader::new(body);
        let authenticator = r.short().map_err(|e| e.to_string())?;
        let corr_id = r.short().map_err(|e| e.to_string())?;
        let entity_id = r.short().map_err(|e| e.to_string())?;
        let command = r.rest().to_vec();
        Ok(NtfTransmission { authenticator, corr_id, entity_id, command })
    }
}

/// Wrap transmissions into an NTF batch payload: `u8 count` + `Large` per transmission.
pub fn encode_ntf_batch(transmissions: &[NtfTransmission]) -> Vec<u8> {
    let mut v = Vec::new();
    v.push(transmissions.len() as u8);
    for t in transmissions {
        v.extend_from_slice(&t.encode_large());
    }
    v
}

/// Parse an NTF batch payload into its transmissions.
pub fn parse_ntf_batch(payload: &[u8]) -> Result<Vec<NtfTransmission>, String> {
    let mut r = Reader::new(payload);
    let count = r.u8().map_err(|e| e.to_string())?;
    let mut out = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let body = r.large().map_err(|e| e.to_string())?;
        out.push(NtfTransmission::parse(&body)?);
    }
    Ok(out)
}

/// NTF response tags (`NtfResponseTag`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NtfResponseTag {
    IdTkn,
    IdSub,
    Ok,
    Err,
    Tkn,
    Sub,
    Pong,
}

impl NtfResponseTag {
    pub fn tag_bytes(&self) -> &'static [u8] {
        match self {
            NtfResponseTag::IdTkn => b"IDTKN",
            NtfResponseTag::IdSub => b"IDSUB",
            NtfResponseTag::Ok => b"OK",
            NtfResponseTag::Err => b"ERR",
            NtfResponseTag::Tkn => b"TKN",
            NtfResponseTag::Sub => b"SUB",
            NtfResponseTag::Pong => b"PONG",
        }
    }

    pub fn parse(tag: &[u8]) -> Option<NtfResponseTag> {
        match tag {
            b"IDTKN" => Some(NtfResponseTag::IdTkn),
            b"IDSUB" => Some(NtfResponseTag::IdSub),
            b"OK" => Some(NtfResponseTag::Ok),
            b"ERR" => Some(NtfResponseTag::Err),
            b"TKN" => Some(NtfResponseTag::Tkn),
            b"SUB" => Some(NtfResponseTag::Sub),
            b"PONG" => Some(NtfResponseTag::Pong),
            _ => None,
        }
    }
}

/// Split an NTF response payload into (tag, rest).
pub fn split_ntf_response(payload: &[u8]) -> Option<(NtfResponseTag, &[u8])> {
    match payload.iter().position(|&c| c == b' ') {
        Some(space) => {
            let tag = NtfResponseTag::parse(&payload[..space])?;
            Some((tag, &payload[space + 1..]))
        }
        None => {
            let tag = NtfResponseTag::parse(payload)?;
            Some((tag, &payload[payload.len()..]))
        }
    }
}

// ---------------------------------------------------------------------------
// NtfClient
// ---------------------------------------------------------------------------

/// A response received from the NTF server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtfResponse {
    pub corr_id: Vec<u8>,
    pub entity_id: Vec<u8>,
    pub tag: NtfResponseTag,
    /// Payload after the tag (e.g. the error code or the new entity id).
    pub payload: Vec<u8>,
}

/// NTF client over any byte stream (typically a TLS 1.3 stream with ALPN `ntf/1`).
pub struct NtfClient<S: Read + Write> {
    stream: S,
    session_id: Vec<u8>,
    version: u16,
    /// Expected CA fingerprint (SHA-256 over the CA certificate DER) — pinning is mandatory.
    expected_key_hash: [u8; 32],
}

impl<S: Read + Write> NtfClient<S> {
    /// Perform the NTF handshake over `stream`.
    ///
    /// `ca_der` must be the DER of the **CA certificate** from the TLS chain; its SHA-256 must
    /// equal `expected_key_hash`, otherwise the handshake is refused (fail-closed, before any
    /// bytes are read or written).
    pub fn connect(stream: S, ca_der: &[u8], expected_key_hash: [u8; 32]) -> Result<Self, String> {
        let served = key_hash_from_ca_der(ca_der);
        if served != expected_key_hash {
            return Err(format!(
                "ntf pin failure: served CA fingerprint {} != expected {}",
                hex::encode(served),
                hex::encode(expected_key_hash)
            ));
        }
        let mut c = NtfClient { stream, session_id: Vec::new(), version: 0, expected_key_hash };
        // server speaks first
        let sh_block = c.read_block()?;
        let sh_payload = unpad_ntf_block(&sh_block)?;
        let sh = parse_ntf_server_handshake(&sh_payload)?;
        let version = negotiate_ntf_version(&sh)?;
        let ch = encode_ntf_client_handshake(&NtfClientHandshake { ntf_version: version, key_hash: expected_key_hash });
        c.write_block(&ch)?;
        c.session_id = sh.session_id;
        c.version = version;
        Ok(c)
    }

    pub fn session_id(&self) -> &[u8] {
        &self.session_id
    }

    pub fn version(&self) -> u16 {
        self.version
    }

    pub fn expected_key_hash(&self) -> [u8; 32] {
        self.expected_key_hash
    }

    /// Send one command and wait for its response.
    pub fn request(&mut self, command: &NtfCommand, entity_id: &[u8], authenticator: &[u8]) -> Result<NtfResponse, String> {
        let corr_id: Vec<u8> = (0u8..24).collect();
        self.request_with_corr(command, entity_id, authenticator, &corr_id)
    }

    /// Send one command with an explicit correlation id and wait for its response.
    pub fn request_with_corr(
        &mut self,
        command: &NtfCommand,
        entity_id: &[u8],
        authenticator: &[u8],
        corr_id: &[u8],
    ) -> Result<NtfResponse, String> {
        let t = NtfTransmission {
            authenticator: authenticator.to_vec(),
            corr_id: corr_id.to_vec(),
            entity_id: entity_id.to_vec(),
            command: command.encode(),
        };
        let batch = encode_ntf_batch(std::slice::from_ref(&t));
        self.write_block(&batch)?;
        let payload = unpad_ntf_block(&self.read_block()?)?;
        let transmissions = parse_ntf_batch(&payload)?;
        let mut last_err = None;
        for tr in transmissions {
            if let Some((tag, rest)) = split_ntf_response(&tr.command) {
                if tr.corr_id == corr_id || tag == NtfResponseTag::Pong {
                    return Ok(NtfResponse { corr_id: tr.corr_id, entity_id: tr.entity_id, tag, payload: rest.to_vec() });
                }
                last_err = Some(format!("unexpected response {tag:?} for corrId {}", hex::encode(&tr.corr_id)));
            }
        }
        Err(last_err.unwrap_or_else(|| "no NTF response".into()))
    }

    /// PING → PONG (unauthenticated, no entity id).
    pub fn ping(&mut self) -> Result<NtfResponse, String> {
        self.request(&NtfCommand::new(NtfCommandTag::Ping), &[], &[])
    }

    fn read_block(&mut self) -> Result<Vec<u8>, String> {
        let mut buf = vec![0u8; NTF_BLOCK_SIZE];
        self.stream.read_exact(&mut buf).map_err(|e| format!("ntf read: {e}"))?;
        Ok(buf)
    }

    fn write_block(&mut self, payload: &[u8]) -> Result<(), String> {
        let block = pad_ntf_block(payload)?;
        self.stream.write_all(&block).map_err(|e| format!("ntf write: {e}"))?;
        self.stream.flush().map_err(|e| format!("ntf flush: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::w_large;

    #[test]
    fn client_handshake_layout() {
        let hs = NtfClientHandshake { ntf_version: 3, key_hash: [0xAB; 32] };
        let enc = encode_ntf_client_handshake(&hs);
        assert_eq!(enc.len(), 35); // u16 version + u8 len + 32B keyHash
        assert_eq!(&enc[..2], &[0x00, 0x03]);
        assert_eq!(enc[2], 32);
        assert_eq!(&enc[3..], &[0xAB; 32]);
    }

    #[test]
    fn block_padding_roundtrip() {
        let payload = b"hello ntf";
        let block = pad_ntf_block(payload).unwrap();
        assert_eq!(block.len(), NTF_BLOCK_SIZE);
        assert_eq!(&block[..2], &(payload.len() as u16).to_be_bytes());
        assert!(block[2 + payload.len()..].iter().all(|&c| c == b'#'));
        assert_eq!(unpad_ntf_block(&block).unwrap(), payload);
    }

    #[test]
    fn server_handshake_parse() {
        let mut v = Vec::new();
        w_u16(&mut v, 1);
        w_u16(&mut v, 3);
        w_short(&mut v, &[0x11; 32]).unwrap();
        let der = vec![0x30u8; 173];
        w_large(&mut v, &der).unwrap();
        let hs = parse_ntf_server_handshake(&v).unwrap();
        assert_eq!(hs.min_version, 1);
        assert_eq!(hs.max_version, 3);
        assert_eq!(hs.session_id.len(), 32);
        assert_eq!(hs.auth_pub_key.as_ref().unwrap().len(), 173);
        assert_eq!(negotiate_ntf_version(&hs).unwrap(), 3);
    }

    #[test]
    fn server_handshake_legacy_no_auth_key() {
        let mut v = Vec::new();
        w_u16(&mut v, 1);
        w_u16(&mut v, 1);
        w_short(&mut v, &[0x22; 32]).unwrap();
        let hs = parse_ntf_server_handshake(&v).unwrap();
        assert!(hs.auth_pub_key.is_none());
        assert_eq!(negotiate_ntf_version(&hs).unwrap(), 1);
    }

    #[test]
    fn oversized_block_rejected() {
        assert!(pad_ntf_block(&vec![0u8; NTF_BLOCK_SIZE]).is_err());
    }

    #[test]
    fn command_tags_match_reference() {
        assert_eq!(NtfCommand::new(NtfCommandTag::Ping).encode(), b"PING");
        assert_eq!(NtfCommand::new(NtfCommandTag::Snew).encode(), b"SNEW");
        assert_eq!(NtfCommand::new(NtfCommandTag::Tnew).encode(), b"TNEW");
        assert_eq!(
            NtfCommand::with_payload(NtfCommandTag::Tcrn, vec![0x00, 0x14]).encode(),
            b"TCRN \x00\x14"
        );
        assert_eq!(NtfCommandTag::Ping.entity(), NtfEntity::Subscription);
        assert_eq!(NtfCommandTag::Tchk.entity(), NtfEntity::Token);
    }

    #[test]
    fn response_tags_parse() {
        assert_eq!(split_ntf_response(b"PONG").unwrap().0, NtfResponseTag::Pong);
        assert_eq!(split_ntf_response(b"OK").unwrap().0, NtfResponseTag::Ok);
        let (tag, rest) = split_ntf_response(b"IDSUB 0123456789abcdef").unwrap();
        assert_eq!(tag, NtfResponseTag::IdSub);
        assert_eq!(rest, b"0123456789abcdef");
        assert!(split_ntf_response(b"UNKNOWN").is_none());
    }

    #[test]
    fn transmission_layout_and_roundtrip() {
        let t = NtfTransmission {
            authenticator: Vec::new(),
            corr_id: vec![0xAA; 24],
            entity_id: Vec::new(),
            command: b"PING".to_vec(),
        };
        let enc = t.encode();
        // authenticator (u8 len 0) | corrId (u8 len 24 + 24B) | entityId (u8 len 0) | command tail
        assert_eq!(enc[0], 0);
        assert_eq!(enc[1], 24);
        assert_eq!(&enc[2..26], &[0xAA; 24]);
        assert_eq!(enc[26], 0);
        assert_eq!(&enc[27..], b"PING");
        assert_eq!(NtfTransmission::parse(&enc).unwrap(), t);
    }

    #[test]
    fn batch_layout() {
        let t = NtfTransmission {
            authenticator: Vec::new(),
            corr_id: vec![1u8; 24],
            entity_id: Vec::new(),
            command: b"PING".to_vec(),
        };
        let batch = encode_ntf_batch(std::slice::from_ref(&t));
        assert_eq!(batch[0], 1); // count
        let body_len = u16::from_be_bytes([batch[1], batch[2]]) as usize;
        assert_eq!(body_len + 3, batch.len());
        let parsed = parse_ntf_batch(&batch).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0], t);
    }

    #[test]
    fn batch_parse_rejects_truncated() {
        assert!(parse_ntf_batch(&[1, 0, 10]).is_err());
        assert!(parse_ntf_batch(&[0]).unwrap().is_empty());
    }

    /// The client must refuse to talk to a server whose CA fingerprint does not match the pin.
    #[test]
    fn connect_rejects_wrong_pin_before_any_io() {
        // A stream that panics on read/write proves nothing is sent before the pin check.
        struct PanicStream;
        impl Read for PanicStream {
            fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
                panic!("must not read before the pin check");
            }
        }
        impl Write for PanicStream {
            fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
                panic!("must not write before the pin check");
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let ca = vec![0xAAu8; 100];
        let err = match NtfClient::connect(PanicStream, &ca, [0x00; 32]) {
            Ok(_) => panic!("connect must fail on a pin mismatch"),
            Err(e) => e,
        };
        assert!(err.contains("pin failure"), "unexpected error: {err}");
    }
}
