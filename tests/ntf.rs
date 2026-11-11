//! NTF: NKEY -> NID, NSUB -> SOK, SEND(notify) -> NMSG pushed to notifier, decrypt NMsgMeta.

use std::net::SocketAddr;

use smp_rs::client::Client;
use smp_rs::crypto::*;
use smp_rs::protocol::*;
use smp_rs::server::{spawn_engine, Engine};

fn start() -> SocketAddr {
    let e = Engine::bind_plain("127.0.0.1:0").unwrap();
    spawn_engine(e).0
}

#[test]
fn ntf_notification_flow() {
    let addr = start();
    let kh = [0xCDu8; 32];
    let mut rcv = Client::connect_plain(addr, &kh).unwrap();
    let mut snd = Client::connect_plain(addr, &kh).unwrap();
    let mut ntf = Client::connect_plain(addr, &kh).unwrap();

    let rcv_auth = ed25519_keypair();
    let rcv_dh = x25519_keypair();
    let resp = rcv
        .request(
            Command::New {
                rcv_auth_key: spki_ed25519(&rcv_auth.verifying.to_bytes()),
                rcv_dh_key: spki_x25519(&rcv_dh.public.to_bytes()),
                basic_auth: None,
                sub_mode: b'S',
                queue_req_data: None,
                ntf_creds: None,
            },
            vec![],
            Some(&rcv_auth),
        )
        .expect("NEW");
    let (rcv_id, snd_id, _srv_dh) = match &resp[0] {
        BrokerMsg::Ids { rcv_id, snd_id, rcv_dh_key, .. } => (rcv_id.clone(), snd_id.clone(), rcv_dh_key.clone()),
        other => panic!("expected IDS, got {other:?}"),
    };

    // NKEY: recipient enables notifications with a notifier Ed25519 key + recipient ntf DH key
    let ntf_auth = ed25519_keypair();
    let rcv_ntf_dh = x25519_keypair();
    let nkey = rcv
        .request(
            Command::Nkey {
                ntf_key: spki_ed25519(&ntf_auth.verifying.to_bytes()),
                rcv_ntf_dh_key: spki_x25519(&rcv_ntf_dh.public.to_bytes()),
            },
            rcv_id.clone(),
            Some(&rcv_auth),
        )
        .expect("NKEY");
    let (ntf_id, srv_ntf_dh_der) = match &nkey[0] {
        BrokerMsg::Nid { ntf_id, srv_ntf_dh } => (ntf_id.clone(), srv_ntf_dh.clone()),
        other => panic!("expected NID, got {other:?}"),
    };

    // NSUB on a separate connection, signed with the notifier key, entity = ntf_id
    let nsub = ntf.request(Command::Nsub, ntf_id.clone(), Some(&ntf_auth)).expect("NSUB");
    assert!(matches!(nsub[0], BrokerMsg::Sok(_)), "got {nsub:?}");

    // SEND with notify flag -> OK, and NMSG pushed to the notifier connection
    let body = b"notify me".to_vec();
    let r = snd.request(Command::Send { flags: true, body }, snd_id.clone(), None).expect("SEND");
    assert!(matches!(r[0], BrokerMsg::Ok), "got {r:?}");

    let msgs = ntf.recv_block().expect("recv NMSG");
    let (nonce, enc_meta) = match &msgs[0] {
        BrokerMsg::Nmsg { nonce, enc_meta } => (nonce.clone(), enc_meta.clone()),
        other => panic!("expected NMSG, got {other:?}"),
    };
    assert_eq!(nonce.len(), 24);
    assert_eq!(enc_meta.len(), 144, "128 padded meta + 16 MAC");

    // recipient decrypts NMsgMeta with DH(rcv_ntf_dh_priv, srv_ntf_dh_pub)
    let srv_raw = parse_spki(&srv_ntf_dh_der).unwrap().1;
    let ntf_secret = x25519_dh(&rcv_ntf_dh.secret, &x25519_public(srv_raw));
    let mut n24 = [0u8; 24];
    n24.copy_from_slice(&nonce);
    let meta = secretbox_decrypt(&ntf_secret, &n24, &enc_meta).expect("decrypt NMsgMeta");
    let meta = smp_rs::encoding::unpad(&meta).expect("unpad");
    // NMsgMeta = shortString(msgId) <> Int64 BE ts
    let mid_len = meta[0] as usize;
    let mid = &meta[1..1 + mid_len];
    let ts = i64::from_be_bytes(meta[1 + mid_len..1 + mid_len + 8].try_into().unwrap());
    assert!(ts > 1_700_000_000, "sane epoch ts {ts}");
    // msg_id matches the MSG the recipient would get — just check length here (16)
    assert_eq!(mid.len(), 16);

    // NDEL disables notifications
    let ndel = rcv.request(Command::Ndel, rcv_id.clone(), Some(&rcv_auth)).expect("NDEL");
    assert!(matches!(ndel[0], BrokerMsg::Ok), "got {ndel:?}");
}
