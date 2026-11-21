//! Golden wire vectors for NTF commands/broker messages (encode -> parse round-trip + exact bytes).

use smp_rs::protocol::*;

#[test]
fn nkey_wire_roundtrip() {
    let ntf_key = vec![0x30u8; 44]; // SPKI DER placeholder
    let dh_key = vec![0x31u8; 44];
    let c = Command::Nkey { ntf_key: ntf_key.clone(), rcv_ntf_dh_key: dh_key.clone() };
    let enc = encode_command(&c).unwrap();
    assert!(enc.starts_with(b"NKEY "));
    match parse_command(&enc).unwrap() {
        Command::Nkey { ntf_key: a, rcv_ntf_dh_key: b } => {
            assert_eq!(a, ntf_key);
            assert_eq!(b, dh_key);
        }
        other => panic!("got {other:?}"),
    }
}

#[test]
fn nsub_ndel_wire() {
    assert_eq!(encode_command(&Command::Nsub).unwrap(), b"NSUB");
    assert!(matches!(parse_command(b"NSUB").unwrap(), Command::Nsub));
    assert_eq!(encode_command(&Command::Ndel).unwrap(), b"NDEL");
    assert!(matches!(parse_command(b"NDEL").unwrap(), Command::Ndel));
}

#[test]
fn nid_wire_roundtrip() {
    let ntf_id = vec![7u8; 16];
    let srv_dh = vec![9u8; 44];
    let m = BrokerMsg::Nid { ntf_id: ntf_id.clone(), srv_ntf_dh: srv_dh.clone() };
    let enc = encode_broker(&m).unwrap();
    assert!(enc.starts_with(b"NID "));
    match parse_broker(&enc).unwrap() {
        BrokerMsg::Nid { ntf_id: a, srv_ntf_dh: b } => {
            assert_eq!(a, ntf_id);
            assert_eq!(b, srv_dh);
        }
        other => panic!("got {other:?}"),
    }
}

#[test]
fn nmsg_wire_layout() {
    let nonce = vec![0xABu8; 24];
    let enc_meta = vec![0xCDu8; 144]; // 128 padded + 16 MAC
    let m = BrokerMsg::Nmsg { nonce: nonce.clone(), enc_meta: enc_meta.clone() };
    let enc = encode_broker(&m).unwrap();
    // NMSG SP <24 raw nonce bytes> <shortString enc_meta>
    assert_eq!(&enc[..5], b"NMSG ");
    assert_eq!(&enc[5..29], &nonce[..]);
    assert_eq!(enc[29], 144, "shortString length byte");
    assert_eq!(&enc[30..], &enc_meta[..]);
    match parse_broker(&enc).unwrap() {
        BrokerMsg::Nmsg { nonce: n, enc_meta: e } => {
            assert_eq!(n, nonce);
            assert_eq!(e, enc_meta);
        }
        other => panic!("got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// W2 — NTF signed commands (TNEW / SNEW), Task 2.1 + 2.2
//
// Reference (vendored Haskell-etalon `simplexmq/`):
//   Notifications/Protocol.hs:168-172
//     instance Encoding (NewNtfEntity e) where
//       NewNtfTkn tkn verifyKey dhPubKey -> smpEncode ('T', tkn, verifyKey, dhPubKey)
//       NewNtfSub tknId smpQueue notifierKey -> smpEncode ('S', tknId, smpQueue, notifierKey)
//   Notifications/Protocol.hs:248-249
//     TNEW {} -> sigNoEntity ; SNEW {} -> sigNoEntity
//   Protocol.hs:2343-2349
//     tForAuth = smpEncode sessionId <> t'
//     t'       = encodeTransmission_ v t
//     encodeTransmission_ v (CorrId corrId, queueId, command) =
//       smpEncode (corrId, queueId) <> encodeProtocol v command
//   Protocol.hs:1744-1757 (server side)
//     authorized' = if implySessId then smpEncode sessionId <> authorized else authorized
//   Encoding.hs:102-104 — Haskell ByteString = 1-byte length prefix ("shortString").
// ---------------------------------------------------------------------------

use smp_rs::crypto::{ed25519_keypair, ed25519_verify, spki_ed25519, spki_x25519};
use smp_rs::ntf::*;

/// `authorized` bytes that are signed for an NTF command.
///
/// Haskell `Protocol.hs:2347`: `tForAuth = smpEncode sessionId <> t'` where
/// `t' = smpEncode (corrId, queueId) <> command`.
///
/// Every component is a Haskell `ByteString` => 1-byte length prefix.
fn ntf_authorized(session_id: &[u8], corr_id: &[u8], entity_id: &[u8], command: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.push(session_id.len() as u8);
    v.extend_from_slice(session_id);
    v.push(corr_id.len() as u8);
    v.extend_from_slice(corr_id);
    v.push(entity_id.len() as u8);
    v.extend_from_slice(entity_id);
    v.extend_from_slice(command);
    v
}

/// Task 2.1 — the signed bytes must be exactly `sessionId||corrId||entityId||command`
/// with Haskell shortString length prefixes, and the signature must verify.
#[test]
fn ntf_command_signature_over_authorized_bytes() {
    let kp = ed25519_keypair();
    let session_id = [0x11u8; 32];
    let corr_id = [0x22u8; 24];
    let entity_id: [u8; 0] = []; // TNEW/SNEW -> sigNoEntity
    let command = b"TNEW \x54";

    let msg = ntf_authorized(&session_id, &corr_id, &entity_id, command);
    // Explicit layout check: 1-byte shortString length prefixes.
    assert_eq!(msg[0], 32, "sessionId shortString length");
    assert_eq!(&msg[1..33], &session_id[..]);
    assert_eq!(msg[33], 24, "corrId shortString length");
    assert_eq!(&msg[34..58], &corr_id[..]);
    assert_eq!(msg[58], 0, "entityId must be empty for TNEW/SNEW (sigNoEntity)");
    assert_eq!(&msg[59..], command);

    let sig = sign_ntf_command(&session_id, &corr_id, &entity_id, command, &kp.signing);
    let pub_raw = kp.verifying.to_bytes();
    assert!(ed25519_verify(&pub_raw, &msg, &sig), "signature must verify over authorized bytes");
    // A single flipped byte in the command must break verification.
    let mut bad = msg.clone();
    let last = bad.len() - 1;
    bad[last] ^= 1;
    assert!(!ed25519_verify(&pub_raw, &bad, &sig));
}

/// The signature must not verify over the *wire* bytes (which omit sessionId on NTF v2+).
#[test]
fn ntf_signature_is_not_over_wire_bytes() {
    let kp = ed25519_keypair();
    let session_id = [0x11u8; 32];
    let corr_id = [0x22u8; 24];
    let command = b"TNEW \x54";
    let sig = sign_ntf_command(&session_id, &corr_id, &[], command, &kp.signing);
    let pub_raw = kp.verifying.to_bytes();

    // wire bytes on NTF v2+: authenticator || corrId || entityId || command (no sessionId)
    let mut wire = Vec::new();
    wire.push(corr_id.len() as u8);
    wire.extend_from_slice(&corr_id);
    wire.push(0u8); // empty entityId
    wire.extend_from_slice(command);
    assert!(!ed25519_verify(&pub_raw, &wire, &sig), "must not verify over wire bytes");
}

/// Task 2.2 — `NewNtfEntity` wire encoding.
///
/// Haskell: `smpEncode ('T', tkn, verifyKey, dhPubKey)` — a `Char` encodes as a single
/// byte (`Encoding.hs:54-56`), and each `ByteString` gets a 1-byte length prefix.
#[test]
fn new_ntf_token_wire_encoding() {
    let token = vec![0xABu8; 32];
    let verify_key = spki_ed25519(&[0x01u8; 32]); // 44-byte SPKI DER
    let dh_pub_key = spki_x25519(&[0x02u8; 32]); // 44-byte SPKI DER

    let enc = encode_new_ntf_token(&token, &verify_key, &dh_pub_key).unwrap();
    assert_eq!(enc[0], b'T', "entity tag 'T'");
    assert_eq!(enc[1], 32, "token shortString length");
    assert_eq!(&enc[2..34], &token[..]);
    assert_eq!(enc[34], 44, "verifyKey SPKI shortString length");
    assert_eq!(&enc[35..79], &verify_key[..]);
    assert_eq!(enc[79], 44, "dhPubKey SPKI shortString length");
    assert_eq!(&enc[80..124], &dh_pub_key[..]);
    assert_eq!(enc.len(), 124);
}

/// Task 2.2 — `NewNtfSub` wire encoding.
///
/// Haskell: `smpEncode ('S', tknId, smpQueue, notifierKey)` where
/// `SMPQueueNtf` = `smpEncode (smpServer, notifierId)`.
#[test]
fn new_ntf_sub_wire_encoding() {
    let tkn_id = vec![0xCDu8; 16];
    let notifier_id = vec![0xEFu8; 16];
    let smp_server = vec![0x5Au8; 4]; // SMP server address
    let notifier_key = spki_ed25519(&[0x03u8; 32]);

    let enc = encode_new_ntf_sub(&tkn_id, &smp_server, &notifier_id, &notifier_key).unwrap();
    assert_eq!(enc[0], b'S', "entity tag 'S'");
    assert_eq!(enc[1], 16, "tknId shortString length");
    assert_eq!(&enc[2..18], &tkn_id[..]);
    // SMPQueueNtf = smpEncode (smpServer, notifierId)
    assert_eq!(enc[18], smp_server.len() as u8, "smpServer shortString length");
    assert_eq!(&enc[19..23], &smp_server[..]);
    assert_eq!(enc[23], notifier_id.len() as u8, "notifierId shortString length");
    assert_eq!(&enc[24..40], &notifier_id[..]);
    assert_eq!(enc[40], 44, "notifierKey SPKI shortString length");
    assert_eq!(&enc[41..85], &notifier_key[..]);
    assert_eq!(enc.len(), 85);
}

/// Task 2.3 — `TNEW` command bytes are `TNEW ` + encoded NewNtfEntity.
#[test]
fn tnew_command_bytes() {
    let token = vec![0xABu8; 32];
    let verify_key = spki_ed25519(&[0x01u8; 32]);
    let dh_pub_key = spki_x25519(&[0x02u8; 32]);

    let cmd = build_tnew(&token, &verify_key, &dh_pub_key).unwrap();
    assert_eq!(&cmd[..5], b"TNEW ");
    assert_eq!(&cmd[5..], &encode_new_ntf_token(&token, &verify_key, &dh_pub_key).unwrap()[..]);
}

/// Task 2.3 — `SNEW` command bytes are `SNEW ` + encoded NewNtfEntity.
#[test]
fn snew_command_bytes() {
    let tkn_id = vec![0xCDu8; 16];
    let notifier_id = vec![0xEFu8; 16];
    let smp_server = vec![0x5Au8; 4];
    let notifier_key = spki_ed25519(&[0x03u8; 32]);

    let cmd = build_snew(&tkn_id, &smp_server, &notifier_id, &notifier_key).unwrap();
    assert_eq!(&cmd[..5], b"SNEW ");
    assert_eq!(&cmd[5..], &encode_new_ntf_sub(&tkn_id, &smp_server, &notifier_id, &notifier_key).unwrap()[..]);
}
