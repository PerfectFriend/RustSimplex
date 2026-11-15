//! P0 regression (audit SEC-03/SEC-08): offline queue must not lose messages; delivery is one-at-a-time until ACK.
use std::net::SocketAddr;

use smp_rs::client::Client;
use smp_rs::crypto::*;
use smp_rs::protocol::*;
use smp_rs::server::{decrypt_for_recipient, spawn_engine, Engine};

fn start() -> SocketAddr {
    spawn_engine(Engine::bind_plain("127.0.0.1:0").unwrap()).0
}

#[test]
fn offline_three_messages_delivered_one_by_one_until_ack() {
    let addr = start();
    let kh = [0xA5u8; 32];
    let mut rcv = Client::connect_plain(addr, &kh).unwrap();
    let mut snd = Client::connect_plain(addr, &kh).unwrap();
    let rcv_auth = ed25519_keypair();
    let rcv_dh = x25519_keypair();
    let r = rcv
        .request(
            Command::New {
                rcv_auth_key: spki_ed25519(&rcv_auth.verifying.to_bytes()),
                rcv_dh_key: spki_x25519(&rcv_dh.public.to_bytes()),
                basic_auth: None,
                sub_mode: b'C', // create only: stay offline while sender queues 3 messages
                queue_req_data: None,
                ntf_creds: None,
            },
            vec![],
            Some(&rcv_auth),
        )
        .unwrap();
    let (rcv_id, snd_id, secret) = match &r[0] {
        BrokerMsg::Ids { rcv_id, snd_id, rcv_dh_key, .. } => {
            let (_a, raw) = parse_spki(rcv_dh_key).unwrap();
            (rcv_id.clone(), snd_id.clone(), x25519_dh(&rcv_dh.secret, &x25519_public(raw)))
        }
        other => panic!("IDS expected, got {other:?}"),
    };

    for i in 0..3u8 {
        let body = format!("m{i}").into_bytes();
        let s = snd.request(Command::Send { flags: false, body }, snd_id.clone(), None).unwrap();
        assert!(matches!(s[0], BrokerMsg::Ok), "SEND {i}: {s:?}");
    }
    // oversized SEND rejected without storing
    let big = vec![0u8; 16090];
    let e = snd.request(Command::Send { flags: false, body: big }, snd_id.clone(), None).unwrap();
    assert!(matches!(&e[0], BrokerMsg::Err(x) if x.contains("LARGE_MSG")), "got {e:?}");

    // SUB returns SOK + at most one MSG; then GET+ACK drains the rest
    let sub = rcv.request(Command::Sub, rcv_id.clone(), Some(&rcv_auth)).unwrap();
    assert!(matches!(sub[0], BrokerMsg::Sok(_)), "SUB: {sub:?}");
    let mut got = Vec::new();
    if let Some(BrokerMsg::Msg { msg_id, body }) = sub.get(1) {
        let pt = decrypt_for_recipient(&secret, msg_id, body).unwrap();
        got.push(String::from_utf8(pt).unwrap());
        rcv.request(Command::Ack(msg_id.clone()), rcv_id.clone(), Some(&rcv_auth)).unwrap();
    }
    while got.len() < 3 {
        let g = rcv.request(Command::Get, rcv_id.clone(), Some(&rcv_auth)).unwrap();
        match &g[0] {
            BrokerMsg::Msg { msg_id, body } => {
                let pt = decrypt_for_recipient(&secret, msg_id, body).unwrap();
                got.push(String::from_utf8(pt).unwrap());
                rcv.request(Command::Ack(msg_id.clone()), rcv_id.clone(), Some(&rcv_auth)).unwrap();
            }
            BrokerMsg::Sok(_) => break,
            other => panic!("GET: {other:?}"),
        }
    }
    assert_eq!(got, vec!["m0".to_string(), "m1".to_string(), "m2".to_string()]);
}
