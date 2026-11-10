//! End-to-end interop: Rust SMP client <-> Rust SMP server over TCP.
//! Full flow: NEW -> IDS, SUB -> SOK, SEND -> OK, pushed MSG -> decrypt -> ACK -> OK, DEL.

use std::net::TcpListener;
use std::thread;
use std::time::Duration;

use smp_rs::client::Client;
use smp_rs::crypto::*;
use smp_rs::protocol::*;
use smp_rs::server::{decrypt_for_recipient, new_state, serve_listener};

fn start_server() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let st = new_state();
    thread::spawn(move || {
        let _ = serve_listener(listener, st);
    });
    // give it a moment
    thread::sleep(Duration::from_millis(100));
    addr
}

#[test]
fn full_smp_roundtrip() {
    let addr = start_server();
    let key_hash = [0xCDu8; 32];

    // ---- recipient ----
    let mut rcv = Client::connect(&addr, &key_hash).expect("rcv connect");
    let rcv_auth = ed25519_keypair();
    let rcv_dh = x25519_keypair();
    let auth_der = spki_ed25519(&rcv_auth.verifying.to_bytes());
    let dh_der = spki_x25519(&rcv_dh.public.to_bytes());

    let resp = rcv
        .request(
            Command::New {
                rcv_auth_key: auth_der,
                rcv_dh_key: dh_der,
                basic_auth: None,
                sub_mode: b'S',
                queue_req_data: None,
                ntf_creds: None,
            },
            vec![],
            Some(&rcv_auth),
        )
        .expect("NEW");
    let (rcv_id, snd_id, srv_dh_der) = match &resp[0] {
        BrokerMsg::Ids { rcv_id, snd_id, rcv_dh_key, .. } => {
            (rcv_id.clone(), snd_id.clone(), rcv_dh_key.clone())
        }
        other => panic!("expected IDS, got {other:?}"),
    };
    assert_eq!(rcv_id.len(), 16);
    assert_eq!(snd_id.len(), 24);

    // recipient DH secret = DH(rcv_dh_priv, server_dh_pub)
    let (_a, srv_dh_raw) = parse_spki(&srv_dh_der).unwrap();
    let srv_dh_pub = x25519_dalek::PublicKey::from(srv_dh_raw);
    let rcv_dh_secret = x25519_dh(&rcv_dh.secret, &srv_dh_pub);

    // PING -> PONG
    let p = rcv.request(Command::Ping, vec![], None).expect("PING");
    assert!(matches!(p[0], BrokerMsg::Pong));

    // SUB -> SOK
    let s = rcv.request(Command::Sub, rcv_id.clone(), Some(&rcv_auth)).expect("SUB");
    assert!(matches!(s[0], BrokerMsg::Sok(_)), "got {s:?}");

    // ---- sender ----
    let mut snd = Client::connect(&addr, &key_hash).expect("snd connect");
    let body = b"hello over SMP e2e".to_vec();
    let r = snd
        .request(Command::Send { flags: false, body: body.clone() }, snd_id.clone(), None)
        .expect("SEND");
    assert!(matches!(r[0], BrokerMsg::Ok), "got {r:?}");

    // ---- recipient receives pushed MSG ----
    let msgs = rcv.recv_block().expect("recv MSG");
    let (msg_id, enc_body) = match &msgs[0] {
        BrokerMsg::Msg { msg_id, body } => (msg_id.clone(), body.clone()),
        other => panic!("expected MSG, got {other:?}"),
    };
    let plain = decrypt_for_recipient(&rcv_dh_secret, &msg_id, &enc_body).expect("decrypt MSG");
    assert_eq!(plain, body, "decrypted body must match sent body");

    // ACK -> OK
    let a = rcv.request(Command::Ack(msg_id), rcv_id.clone(), Some(&rcv_auth)).expect("ACK");
    assert!(matches!(a[0], BrokerMsg::Ok), "got {a:?}");

    // DEL -> DELD
    let d = rcv.request(Command::Del, rcv_id.clone(), Some(&rcv_auth)).expect("DEL");
    assert!(matches!(d[0], BrokerMsg::Deld), "got {d:?}");
}

#[test]
fn auth_rejected_for_wrong_key() {
    let addr = start_server();
    let key_hash = [0xEFu8; 32];
    let mut rcv = Client::connect(&addr, &key_hash).unwrap();
    let rcv_auth = ed25519_keypair();
    let other = ed25519_keypair(); // wrong key to sign SUB
    let dh = x25519_keypair();
    let resp = rcv
        .request(
            Command::New {
                rcv_auth_key: spki_ed25519(&rcv_auth.verifying.to_bytes()),
                rcv_dh_key: spki_x25519(&dh.public.to_bytes()),
                basic_auth: None,
                sub_mode: b'S',
                queue_req_data: None,
                ntf_creds: None,
            },
            vec![],
            Some(&rcv_auth),
        )
        .unwrap();
    let rcv_id = match &resp[0] {
        BrokerMsg::Ids { rcv_id, .. } => rcv_id.clone(),
        o => panic!("{o:?}"),
    };
    // sign SUB with the WRONG key -> ERR AUTH
    let s = rcv.request(Command::Sub, rcv_id, Some(&other)).unwrap();
    assert!(matches!(&s[0], BrokerMsg::Err(e) if e.contains("AUTH")), "got {s:?}");
}
