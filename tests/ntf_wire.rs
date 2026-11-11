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
