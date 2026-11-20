//! Onion multi-hop e2e: client -> R1 -> R2 -> dest through nested PROXY/PFWD layers.

use smp_rs::crypto::*;
use smp_rs::onion::{fetch_hop, onion_request};
use smp_rs::protocol::*;
use smp_rs::server::{spawn_engine, Engine};

#[test]
fn onion_two_hop_roundtrip() {
    std::env::set_var("SMP_ALLOW_LOCAL_PROXY", "1");
    std::env::remove_var("SMP_STRICT");

    // destination router: create a queue directly
    let dest = Engine::bind_plain("127.0.0.1:0").unwrap();
    let (dest_addr, _st1, _sd1, _h1) = spawn_engine(dest);
    let kh = [0xCDu8; 32];
    let mut d = smp_rs::client::Client::connect_plain(dest_addr, &kh).unwrap();
    let rcv_auth = ed25519_keypair();
    let rcv_dh = x25519_keypair();
    let ids = d
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
        .unwrap();
    let (rcv_id, snd_id) = match &ids[0] {
        BrokerMsg::Ids { rcv_id, snd_id, .. } => (rcv_id.clone(), snd_id.clone()),
        other => panic!("expected IDS, got {other:?}"),
    };

    // subscriber on dest
    let mut sub = smp_rs::client::Client::connect_plain(dest_addr, &kh).unwrap();
    let sk = sub.request(Command::Sub, rcv_id.clone(), Some(&rcv_auth)).unwrap();
    assert!(matches!(sk[0], BrokerMsg::Sok(_)), "got {sk:?}");

    // two relay engines
    let r1 = Engine::bind_plain("127.0.0.1:0").unwrap();
    let (r1_addr, _st2, _sd2, _h2) = spawn_engine(r1);
    let r2 = Engine::bind_plain("127.0.0.1:0").unwrap();
    let (r2_addr, _st3, _sd3, _h3) = spawn_engine(r2);

    // fetch relay ephemeral pubs via server hello
    let hop1 = fetch_hop(r1_addr).unwrap();
    let hop2 = fetch_hop(r2_addr).unwrap();
    let dest_hop = fetch_hop(dest_addr).unwrap();

    // SEND through the 2-hop onion chain R1 -> R2 -> dest
    let body = b"onion over 2 hops".to_vec();
    let resp = onion_request(
        &[hop1, hop2],
        dest_addr,
        dest_hop.server_pub,
        Command::Send { flags: false, body: body.clone() },
        snd_id.clone(),
        None,
    )
    .expect("onion SEND");
    assert!(resp.iter().any(|m| matches!(m, BrokerMsg::Ok)), "got {resp:?}");

    // subscriber on dest receives the message
    let msgs = sub.recv_block().unwrap();
    let (msg_id, enc_body) = match &msgs[0] {
        BrokerMsg::Msg { msg_id, body } => (msg_id.clone(), body.clone()),
        other => panic!("expected MSG, got {other:?}"),
    };
    // decrypt the MSG body with the queue DH secret (as in tests/proxy.rs)
    let secret = x25519_dh(&rcv_dh.secret, &x25519_public(parse_spki(&ids_dh(&ids)).unwrap().1));
    let plain = smp_rs::server::decrypt_for_recipient(&secret, &msg_id, &enc_body).expect("decrypt MSG");
    assert_eq!(plain, body);

    // ACK through the same onion chain
    let ack = onion_request(
        &[fetch_hop(r1_addr).unwrap(), fetch_hop(r2_addr).unwrap()],
        dest_addr,
        dest_hop.server_pub,
        Command::Ack(msg_id),
        rcv_id.clone(),
        Some(&rcv_auth),
    )
    .expect("onion ACK");
    assert!(ack.iter().any(|m| matches!(m, BrokerMsg::Ok)), "got {ack:?}");
}

fn ids_dh(ids: &[BrokerMsg]) -> Vec<u8> {
    match &ids[0] {
        BrokerMsg::Ids { rcv_dh_key, .. } => rcv_dh_key.clone(),
        _ => panic!("no IDS"),
    }
}

#[test]
fn onion_wrong_hop_key_cannot_decrypt() {
    // a layer encrypted for R2 must not decrypt under R1's key
    let eph = x25519_keypair();
    let r1_pub = x25519_keypair().public.to_bytes();
    let r2_pub = x25519_keypair().public.to_bytes();
    let key_r2 = x25519_dh(&eph.secret, &x25519_public(r2_pub));
    let key_r1 = x25519_dh(&eph.secret, &x25519_public(r1_pub));
    let corr = random_bytes(24);
    let corr24: [u8; 24] = corr.try_into().unwrap();
    let padded = smp_rs::encoding::pad(b"secret", 512).unwrap();
    let enc = secretbox_encrypt(&key_r2, &corr24, &padded);
    assert!(secretbox_decrypt(&key_r1, &corr24, &enc).is_none(), "R1 key must not open R2 layer");
    assert!(secretbox_decrypt(&key_r2, &corr24, &enc).is_some());
}

#[test]
fn onion_single_hop_debug() {
    std::env::set_var("SMP_ALLOW_LOCAL_PROXY", "1");
    std::env::remove_var("SMP_STRICT");
    let dest = Engine::bind_plain("127.0.0.1:0").unwrap();
    let (dest_addr, _a, _b, _c) = spawn_engine(dest);
    let kh = [0xCDu8; 32];
    let mut d = smp_rs::client::Client::connect_plain(dest_addr, &kh).unwrap();
    let ids = d.request(Command::Ping, vec![], None).unwrap();
    assert!(matches!(ids[0], BrokerMsg::Pong));
    let r1 = Engine::bind_plain("127.0.0.1:0").unwrap();
    let (r1_addr, _d, _e, _f) = spawn_engine(r1);
    let hop1 = fetch_hop(r1_addr).unwrap();
    let dest_hop = fetch_hop(dest_addr).unwrap();
    let resp = onion_request(&[hop1], dest_addr, dest_hop.server_pub, Command::Ping, vec![], None).expect("onion PING 1-hop");
    eprintln!("[t] 1-hop resp: {resp:?}");
    assert!(resp.iter().any(|m| matches!(m, BrokerMsg::Pong)), "got {resp:?}");
}
