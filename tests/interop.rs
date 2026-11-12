//! End-to-end: Rust SMP client <-> Rust SMP engine over plain TCP and over TLS 1.3.
//! Flow: NEW -> IDS, SUB -> SOK, SEND -> OK, pushed MSG -> decrypt -> ACK -> OK, DEL.

use std::net::SocketAddr;

use smp_rs::client::Client;
use smp_rs::crypto::*;
use smp_rs::protocol::*;
use smp_rs::server::{decrypt_for_recipient, spawn_engine, Engine};

fn start_plain() -> SocketAddr {
    let e = Engine::bind_plain("127.0.0.1:0").unwrap();
    spawn_engine(e).0
}

fn start_tls() -> (SocketAddr, [u8; 32]) {
    let e = Engine::bind_tls("127.0.0.1:0", "127.0.0.1").unwrap();
    let kh = e.key_hash().unwrap();
    let (addr, _st, _sd, _h) = spawn_engine(e);
    (addr, kh)
}

fn new_queue(c: &mut Client, rcv_auth: &Ed25519Keypair, rcv_dh: &X25519Keypair) -> (Vec<u8>, Vec<u8>, [u8; 32], Vec<u8>) {
    let resp = c
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
            Some(rcv_auth),
        )
        .expect("NEW");
    match &resp[0] {
        BrokerMsg::Ids { rcv_id, snd_id, rcv_dh_key, .. } => {
            let (_a, srv_raw) = parse_spki(rcv_dh_key).unwrap();
            let secret = x25519_dh(&rcv_dh.secret, &x25519_public(srv_raw));
            (rcv_id.clone(), snd_id.clone(), secret, rcv_dh_key.clone())
        }
        other => panic!("expected IDS, got {other:?}"),
    }
}

fn roundtrip(mut rcv: Client, mut snd: Client) {
    let rcv_auth = ed25519_keypair();
    let rcv_dh = x25519_keypair();
    let (rcv_id, snd_id, secret, _srv_dh) = new_queue(&mut rcv, &rcv_auth, &rcv_dh);
    assert_eq!(rcv_id.len(), 16);
    assert_eq!(snd_id.len(), 24);

    let p = rcv.request(Command::Ping, vec![], None).expect("PING");
    assert!(matches!(p[0], BrokerMsg::Pong));

    let s = rcv.request(Command::Sub, rcv_id.clone(), Some(&rcv_auth)).expect("SUB");
    assert!(matches!(s[0], BrokerMsg::Sok(_)), "got {s:?}");

    let body = b"hello over SMP e2e".to_vec();
    let r = snd.request(Command::Send { flags: false, body: body.clone() }, snd_id.clone(), None).expect("SEND");
    assert!(matches!(r[0], BrokerMsg::Ok), "got {r:?}");

    let msgs = rcv.recv_block().expect("recv MSG");
    let (msg_id, enc_body) = match &msgs[0] {
        BrokerMsg::Msg { msg_id, body } => (msg_id.clone(), body.clone()),
        other => panic!("expected MSG, got {other:?}"),
    };
    let plain = decrypt_for_recipient(&secret, &msg_id, &enc_body).expect("decrypt MSG");
    assert_eq!(plain, body);

    let a = rcv.request(Command::Ack(msg_id), rcv_id.clone(), Some(&rcv_auth)).expect("ACK");
    assert!(matches!(a[0], BrokerMsg::Ok));
    let d = rcv.request(Command::Del, rcv_id.clone(), Some(&rcv_auth)).expect("DEL");
    assert!(matches!(d[0], BrokerMsg::Deld));
}

#[test]
fn plain_roundtrip() {
    let addr = start_plain();
    let kh = [0xCDu8; 32];
    let rcv = Client::connect_plain(addr, &kh).unwrap();
    let snd = Client::connect_plain(addr, &kh).unwrap();
    roundtrip(rcv, snd);
}

#[test]
fn tls_roundtrip() {
    let (addr, kh) = start_tls();
    let rcv = Client::connect_tls(addr, "127.0.0.1", kh).unwrap();
    let snd = Client::connect_tls(addr, "127.0.0.1", kh).unwrap();
    roundtrip(rcv, snd);
}

#[test]
fn tls_wrong_keyhash_rejected() {
    let (addr, _kh) = start_tls();
    let wrong = [0x11u8; 32];
    let r = Client::connect_tls(addr, "127.0.0.1", wrong);
    assert!(r.is_err(), "client must reject a router whose keyHash does not match");
}

#[test]
fn auth_rejected_for_wrong_key() {
    let addr = start_plain();
    let kh = [0xEFu8; 32];
    let mut rcv = Client::connect_plain(addr, &kh).unwrap();
    let rcv_auth = ed25519_keypair();
    let other = ed25519_keypair();
    let dh = x25519_keypair();
    let (rcv_id, _snd, _sec, _dh) = new_queue(&mut rcv, &rcv_auth, &dh);
    let s = rcv.request(Command::Sub, rcv_id, Some(&other)).unwrap();
    assert!(matches!(&s[0], BrokerMsg::Err(e) if e.contains("AUTH")), "got {s:?}");
}

#[test]
fn tls_x25519_box_auth_roundtrip() {
    // v0.16: queue created with X25519 auth key, all commands authorized with the
    // crypto_box authenticator (secretbox(dhSecret, cbNonce(corrId), sha512(authorized))).
    let (addr, kh) = start_tls();
    let mut rcv = Client::connect_tls(addr, "127.0.0.1", kh).unwrap();
    assert!(rcv.server_eph_pub.is_some(), "server hello must carry ephemeral X25519 authPubKey");
    let qauth = x25519_keypair();
    let secret = rcv.box_secret(&qauth).expect("box secret from server eph pub");
    let dh = x25519_keypair();
    let resp = rcv
        .request_box(
            Command::New {
                rcv_auth_key: spki_x25519(&qauth.public.to_bytes()),
                rcv_dh_key: spki_x25519(&dh.public.to_bytes()),
                basic_auth: None,
                sub_mode: b'S',
                queue_req_data: None,
                ntf_creds: None,
            },
            vec![],
            &secret,
        )
        .expect("NEW box");
    let (rcv_id, snd_id, srv_dh) = match &resp[0] {
        BrokerMsg::Ids { rcv_id, snd_id, rcv_dh_key, .. } => {
            let (_a, raw) = parse_spki(rcv_dh_key).unwrap();
            (rcv_id.clone(), snd_id.clone(), raw)
        }
        other => panic!("expected IDS, got {other:?}"),
    };
    let shared = x25519_dh(&dh.secret, &x25519_public(srv_dh));
    // SUB with box auth
    let s = rcv.request_box(Command::Sub, rcv_id.clone(), &secret).unwrap();
    assert!(matches!(&s[0], BrokerMsg::Sok(_)), "SUB -> {s:?}");
    // sender sends (sender side has no auth by default)
    let mut snd = Client::connect_tls(addr, "127.0.0.1", kh).unwrap();
    let body = b"box-auth body".to_vec();
    let ok = snd
        .request(Command::Send { flags: false, body: body.clone() }, snd_id.clone(), None)
        .unwrap();
    assert!(matches!(&ok[0], BrokerMsg::Ok), "SEND -> {ok:?}");
    let pushed = rcv.recv_block().unwrap();
    let (msg_id, enc_body) = match &pushed[0] {
        BrokerMsg::Msg { msg_id, body } => (msg_id.clone(), body.clone()),
        other => panic!("expected MSG, got {other:?}"),
    };
    let plain = decrypt_for_recipient(&shared, &msg_id, &enc_body).expect("decrypt MSG");
    assert_eq!(plain, body);
    let ack = rcv.request_box(Command::Ack(msg_id), rcv_id.clone(), &secret).unwrap();
    assert!(matches!(&ack[0], BrokerMsg::Ok), "ACK -> {ack:?}");
    // negative: wrong dhSecret must be rejected
    let bad = [0xABu8; 32];
    let r = rcv.request_box(Command::Sub, rcv_id.clone(), &bad).unwrap();
    assert!(matches!(&r[0], BrokerMsg::Err(e) if e.contains("AUTH")), "got {r:?}");
}

#[test]
fn session_binding_rejects_nonempty_sid() {
    use smp_rs::client::check_session_binding;
    assert!(check_session_binding(b"").is_ok());
    assert!(check_session_binding(b"tls-unique-value").is_err());
}
