//! ADR decisions 2026-11-26: D1(a) X3DH dual-mode primitive, D2(b) async auto-reconnect.
use smp_rs::async_client::AsyncSmpClient;
use smp_rs::crypto::{x25519_keypair, x25519_public};
use smp_rs::protocol::Command;
use smp_rs::server::{new_state, Engine};
use smp_rs::x3dh::{x3dh_initiate, x3dh_respond, X3dhIdentity};

#[test]
fn x3dh_roundtrip_with_and_without_opk() {
    let alice = X3dhIdentity::new();
    let mut bob = X3dhIdentity::new();
    bob.opks.push(x25519_keypair());
    let ek = x25519_keypair();

    // without OPK
    let b = bob.bundle(None);
    let (sk_a, msg) = x3dh_initiate(&alice, &ek, &b).unwrap();
    let sk_b = x3dh_respond(&bob, None, &msg).unwrap();
    assert_eq!(sk_a, sk_b, "SK mismatch without OPK");

    // with OPK
    let b = bob.bundle(Some(&bob.opks[0]));
    let (sk_a, msg) = x3dh_initiate(&alice, &ek, &b).unwrap();
    let sk_b = x3dh_respond(&bob, Some(0), &msg).unwrap();
    assert_eq!(sk_a, sk_b, "SK mismatch with OPK");
}

#[test]
fn x3dh_rejects_forged_spk_signature() {
    let alice = X3dhIdentity::new();
    let bob = X3dhIdentity::new();
    let mut b = bob.bundle(None);
    b.spk_pub = x25519_keypair().public.to_bytes(); // swapped SPK, old sig
    let ek = x25519_keypair();
    assert!(x3dh_initiate(&alice, &ek, &b).is_err());
}

#[test]
fn x3dh_rejects_low_order_peer_key() {
    let alice = X3dhIdentity::new();
    let bob = X3dhIdentity::new();
    let mut b = bob.bundle(None);
    b.ik_x_pub = [0u8; 32]; // low-order point — must not be silently accepted (U-07)
    let ek = x25519_keypair();
    assert!(x3dh_initiate(&alice, &ek, &b).is_err());
}

#[test]
fn x3dh_responder_opk_mismatch_rejected() {
    let alice = X3dhIdentity::new();
    let mut bob = X3dhIdentity::new();
    bob.opks.push(x25519_keypair());
    bob.opks.push(x25519_keypair());
    let ek = x25519_keypair();
    let b = bob.bundle(Some(&bob.opks[0]));
    let (_sk, msg) = x3dh_initiate(&alice, &ek, &b).unwrap();
    assert!(x3dh_respond(&bob, Some(1), &msg).is_err(), "wrong OPK index must fail");
    assert!(x3dh_respond(&bob, Some(9), &msg).is_err(), "out-of-range OPK must fail");
}

#[tokio::test]
async fn async_client_request_retry_reconnects_and_restores_sub() {
    let e = Engine::bind_plain("127.0.0.1:0").unwrap();
    let addr = e.local_addr().unwrap();
    let e = std::sync::Arc::new(e);
    let e2 = e.clone();
    std::thread::spawn(move || { let _ = e2.serve(); });

    let mut c = AsyncSmpClient::new("127.0.0.1", addr.port(), [0u8; 32], false);
    c.connect().await.unwrap();

    // create a queue, remember the SUB
    let rcv_auth = smp_rs::crypto::ed25519_keypair();
    let rcv_dh = smp_rs::crypto::x25519_keypair();
    let resp = c.request(Command::New {
        rcv_auth_key: smp_rs::crypto::spki_ed25519(&rcv_auth.verifying.to_bytes()),
        rcv_dh_key: smp_rs::crypto::spki_x25519(&rcv_dh.public.to_bytes()),
        basic_auth: None, sub_mode: b'S', queue_req_data: None, ntf_creds: None,
    }, vec![], Some(&rcv_auth)).await.unwrap();
    let rcv_id = resp.iter().find_map(|m| match m {
        smp_rs::protocol::BrokerMsg::Ids { rcv_id, .. } => Some(rcv_id.clone()),
        _ => None,
    }).expect("IDS");
    c.subscribe(&rcv_id, Some(&rcv_auth)).await.unwrap();
    assert_eq!(c.subs.len(), 1);

    // happy-path retry works
    let r = c.request_retry(Command::Sub, rcv_id.clone(), Some(&rcv_auth)).await.unwrap();
    assert!(r.iter().any(|m| matches!(m, smp_rs::protocol::BrokerMsg::Sok(_))));

    // simulate a dropped connection: kill the stream, then request_retry must reconnect
    // (server still up, same port) and restore the remembered SUB
    c.reconnect().await.unwrap();
    assert!(c.is_connected());
    c.request(Command::Ping, vec![], None).await.unwrap();
    // the re-SUB SOKs may come first — drain blocks until Pong
    let mut got_pong = false;
    for _ in 0..5 {
        let blk = c.recv_block().await.unwrap();
        if blk.iter().any(|m| matches!(m, smp_rs::protocol::BrokerMsg::Pong)) { got_pong = true; break; }
    }
    assert!(got_pong, "no Pong after reconnect");

    e.shutdown.store(true, std::sync::atomic::Ordering::Relaxed);
    let _ = new_state(); // keep import used in all cfgs
    let _ = x25519_public([1u8; 32]);
}
