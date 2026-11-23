//! SMP Agent Protocol e2e: initiator creates contact link, joiner connects ("D"),
//! HELLO exchange, A_MSG ping-pong with A_RCVD receipts.

use smp_rs::agent::*;
use smp_rs::client::Client;
use smp_rs::server::{spawn_engine, Engine};

#[test]
fn agent_duplex_handshake_and_msg() {
    let eng = Engine::bind_plain("127.0.0.1:0").unwrap();
    let (addr, _st, _sd, _h) = spawn_engine(eng);
    let kh = vec![0x77u8; 32];
    let host = "127.0.0.1";
    let port = addr.port();

    let ci = Client::connect_plain(addr, &kh).unwrap();
    let (mut a, link) = Agent::create_contact(ci, host, port, &kh, "alice").expect("create_contact");
    // official link shape (simplexmq 7.0.1.0): simplex:/invitation#/?v=..&smp=<escaped queueUri>
    assert!(link.starts_with("simplex:/invitation#/?v="), "got {link}");
    assert!(link.contains("&smp=smp%3A%2F%2F"), "smp= must be url-escaped: {link}");
    let parsed = smp_rs::agent_link::AgentLink::parse(&link).expect("official link parses");
    assert_eq!(parsed.mode, "invitation");
    assert_eq!(parsed.queues.len(), 1);
    assert_eq!(parsed.queues[0].host, host);
    assert_eq!(parsed.queues[0].port, port);
    assert_eq!(parsed.queues[0].key_hash, kh);

    let cj = Client::connect_plain(addr, &kh).unwrap();
    let mut b = Agent::join_contact(cj, &link).expect("join_contact");

    a.accept_contact().expect("accept (D -> HELLO)");
    b.await_hello().expect("await HELLO -> HELLO back");

    // Official-compat X448: both sides derived the SAME shared secret from the
    // exchanged public keys (initiator key via the invitation, joiner key via connInfo).
    let sa = a.x448_shared_secret().expect("initiator X448 shared secret");
    let sb = b.x448_shared_secret().expect("joiner X448 shared secret");
    assert_eq!(sa, sb, "both sides must derive the same X448 secret");
    assert_ne!(sa, [0u8; 56]);
    // each side learned the OTHER side's public key
    assert_eq!(a.peer_x448_spki.as_ref(), b.x448_public_spki().as_ref());
    assert_eq!(b.peer_x448_spki.as_ref(), a.x448_public_spki().as_ref());
    // and the secret really is the DH of the two public keys (not a copy of one side)
    let b_pub = smp_rs::x448::parse_spki_x448(&b.x448_public_spki().expect("b spki")).expect("b pub");
    let a_sk = a.x448_kp.as_ref().expect("a kp").secret;
    assert_eq!(smp_rs::x448::dh(&a_sk, &b_pub).expect("dh"), sa);
    // initiator reads joiner's HELLO
    let (_mid, am) = a.recv_agent().expect("recv HELLO");
    assert!(matches!(am, AgentMsg::Hello { .. }), "got {am:?}");

    // A_MSG alice -> bob
    let id = a.send_msg(b"ping from alice").expect("send_msg");
    let (_mid, am) = b.recv_agent().expect("bob recv");
    match am {
        AgentMsg::Msg { msg_id, body, .. } => {
            assert_eq!(msg_id, id);
            assert_eq!(body, b"ping from alice");
        }
        other => panic!("expected A_MSG, got {other:?}"),
    }
    b.send_rcvd(id, &[0u8; 32]).expect("rcvd");
    let (_mid, am) = a.recv_agent().expect("alice recv rcvd");
    match &am {
        AgentMsg::Rcvd { receipts, .. } => assert_eq!(receipts[0].agent_msg_id, id),
        other => panic!("expected A_RCVD, got {other:?}"),
    }

    // A_MSG bob -> alice
    let id2 = b.send_msg(b"pong from bob").expect("send_msg2");
    let (_mid, am) = a.recv_agent().expect("alice recv2");
    match am {
        AgentMsg::Msg { msg_id, body, .. } => {
            assert_eq!(msg_id, id2);
            assert_eq!(body, b"pong from bob");
        }
        other => panic!("expected A_MSG, got {other:?}"),
    }
}

#[test]
fn agent_wire_roundtrip() {
    let qs = vec![QueueInfo {
        version_min: 17,
        version_max: 20,
        host: "example.com".into(),
        port: 5223,
        key_hash: vec![1u8; 32],
        sender_id: vec![2u8; 16],
        dh_pub: vec![3u8; 44],
        queue_mode: b'C',
    }];
    let m = AgentMsg::ConnInfoReply(qs, b"{\"profile\":\"x\"}".to_vec());
    let e = encode_agent(&m, 0, &[]);
    match parse_agent(&e).expect("parse") {
        AgentMsg::ConnInfoReply(qs2, ci) => {
            assert_eq!(qs2.len(), 1);
            assert_eq!(qs2[0].host, "example.com");
            assert_eq!(qs2[0].port, 5223);
            assert_eq!(ci, b"{\"profile\":\"x\"}");
        }
        other => panic!("{other:?}"),
    }
    let m2 = AgentMsg::Msg { msg_id: 42, prev_hash: vec![9u8; 4], body: b"hello".to_vec() };
    let e2 = encode_agent(&m2, 42, &[9u8; 4]);
    match parse_agent(&e2).expect("parse2") {
        AgentMsg::Msg { msg_id, body, .. } => {
            assert_eq!(msg_id, 42);
            assert_eq!(body, b"hello");
        }
        other => panic!("{other:?}"),
    }
}
