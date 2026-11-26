//! Audit #3, Sprint B: U-18 — ReconnectingClient restores SUB after a reconnect.

use smp_rs::client::Client;
use smp_rs::crypto::{ed25519_keypair, spki_ed25519, spki_x25519, x25519_keypair};
use smp_rs::protocol::{BrokerMsg, Command};
use smp_rs::reconnect::{Endpoint, ReconnectingClient};
use smp_rs::server::Engine;

fn spawn_engine() -> std::net::SocketAddr {
    let e = Engine::bind_plain_with_strict("127.0.0.1:0", false).unwrap();
    let a = e.local_addr().unwrap();
    std::thread::spawn(move || {
        let _ = e.serve();
    });
    a
}

#[test]
fn sub_restored_after_reconnect() {
    let addr = spawn_engine();

    // create a queue with a second client
    let mut owner = Client::connect_plain(addr, &[0u8; 32]).unwrap();
    let kp = ed25519_keypair();
    let dh = x25519_keypair();
    let r = owner
        .request(
            Command::New {
                rcv_auth_key: spki_ed25519(&kp.verifying.to_bytes()),
                rcv_dh_key: spki_x25519(&dh.public.to_bytes()),
                basic_auth: None,
                sub_mode: b'S',
                queue_req_data: None,
                ntf_creds: None,
            },
            vec![],
            Some(&kp),
        )
        .unwrap();
    let (rcv_id, snd_id) = match &r[0] {
        BrokerMsg::Ids { rcv_id, snd_id, .. } => (rcv_id.clone(), snd_id.clone()),
        other => panic!("expected IDS, got {other:?}"),
    };

    let ep = Endpoint { addr, host: "test".into(), key_hash: [0u8; 32], tls: false, with_sni: true };
    let mut rc = ReconnectingClient::new(ep);
    rc.connect().unwrap();
    let r = rc.subscribe(rcv_id.clone(), Some(&kp)).unwrap();
    assert!(!r.iter().any(|m| matches!(m, BrokerMsg::Err(_))), "SUB failed: {r:?}");

    // message arrives on the subscription
    owner.request(Command::Send { flags: false, body: b"one".to_vec() }, snd_id.clone(), None).unwrap();
    let blk = rc.recv_block().unwrap();
    assert!(blk.iter().any(|m| matches!(m, BrokerMsg::Msg { .. })), "no MSG: {blk:?}");

    // connection drops (simulated) -> reconnect must re-SUB automatically
    rc.force_reconnect();
    owner.request(Command::Send { flags: false, body: b"two".to_vec() }, snd_id.clone(), None).unwrap();
    let blk = rc.recv_block().unwrap(); // triggers ensure -> connect -> re-SUB, then reads
    // the pushed MSG may arrive in the first block after re-SUB
    let got_two = blk.iter().any(|m| matches!(m, BrokerMsg::Msg { .. }))
        || rc.recv_block().unwrap().iter().any(|m| matches!(m, BrokerMsg::Msg { .. }));
    assert!(got_two, "MSG after reconnect missing — SUB was not restored: {blk:?}");
}
