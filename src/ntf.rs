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
}
