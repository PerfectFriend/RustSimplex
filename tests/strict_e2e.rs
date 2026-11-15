//! Strict v23 block-chain e2e (local): SMP_STRICT=1 makes both peers use 16384B ciphertext blocks.
use std::net::SocketAddr;

use smp_rs::client::Client;
use smp_rs::crypto::*;
use smp_rs::protocol::*;
use smp_rs::server::{decrypt_for_recipient, spawn_engine, Engine};

fn start_plain() -> SocketAddr {
    let e = Engine::bind_plain("127.0.0.1:0").unwrap();
    spawn_engine(e).0
}

#[test]
fn strict_block_e2e_ping_new() {
    std::env::set_var("SMP_STRICT", "1");
    let addr = start_plain();
    let mut c = Client::connect_plain(addr, &[0u8; 32]).expect("connect");
    let p = c.request(Command::Ping, vec![], None).expect("PING over strict blocks");
    assert!(matches!(p[0], BrokerMsg::Pong), "got {p:?}");

    let rcv_auth = ed25519_keypair();
    let rcv_dh = x25519_keypair();
    let r = c
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
        .expect("NEW over strict blocks");
    let (rcv_id, snd_id, secret) = match &r[0] {
        BrokerMsg::Ids { rcv_id, snd_id, rcv_dh_key, .. } => {
            let (_a, srv_raw) = parse_spki(rcv_dh_key).unwrap();
            (rcv_id.clone(), snd_id.clone(), x25519_dh(&rcv_dh.secret, &x25519_public(srv_raw)))
        }
        other => panic!("expected IDS, got {other:?}"),
    };

    let s = c.request(Command::Sub, rcv_id.clone(), Some(&rcv_auth)).expect("SUB over strict blocks");
    assert!(matches!(s[0], BrokerMsg::Sok(_)), "got {s:?}");

    let mut snd = Client::connect_plain(addr, &[0u8; 32]).expect("sender connect");
    let body = b"hello strict block-chain".to_vec();
    let sr = snd.request(Command::Send { flags: false, body: body.clone() }, snd_id.clone(), None).expect("SEND");
    assert!(matches!(sr[0], BrokerMsg::Ok), "got {sr:?}");

    let msgs = c.recv_block().expect("recv MSG over strict blocks");
    let (msg_id, enc_body) = match &msgs[0] {
        BrokerMsg::Msg { msg_id, body } => (msg_id.clone(), body.clone()),
        other => panic!("expected MSG, got {other:?}"),
    };
    let plain = decrypt_for_recipient(&secret, &msg_id, &enc_body).expect("decrypt MSG");
    assert_eq!(plain, body);

    let a = c.request(Command::Ack(msg_id), rcv_id.clone(), Some(&rcv_auth)).expect("ACK");
    assert!(matches!(a[0], BrokerMsg::Ok));
    let d = c.request(Command::Del, rcv_id.clone(), Some(&rcv_auth)).expect("DEL");
    assert!(matches!(d[0], BrokerMsg::Deld));
}
