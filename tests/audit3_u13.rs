//! Audit #3, U-13/U-19: resource caps and input validation on the server.
//!
//! U-13: connection cap + handshake timeout (accept-loop level).
//! U-19: store quotas — FNEW size/packet/total caps, FPUT chunk/offset/chunk-count
//! validation, queue and proxy quotas.

use smp_rs::client::Client;
use smp_rs::crypto::{ed25519_keypair, spki_ed25519};
use smp_rs::protocol::{BrokerMsg, Command};
use smp_rs::server::{Engine, MAX_XFTP_CHUNK, MAX_XFTP_FILE_SIZE};

fn spawn_engine() -> std::net::SocketAddr {
    let e = Engine::bind_plain_with_strict("127.0.0.1:0", false).unwrap();
    let a = e.local_addr().unwrap();
    std::thread::spawn(move || {
        let _ = e.serve();
    });
    a
}

#[test]
fn fnew_oversized_file_rejected() {
    let addr = spawn_engine();
    let mut c = Client::connect_plain(addr, &[0u8; 32]).unwrap();
    let kp = ed25519_keypair();
    let spki = spki_ed25519(&kp.verifying.to_bytes());
    let r = c
        .request(
            Command::Fnew { size: MAX_XFTP_FILE_SIZE + 1, digest: vec![0; 32], sender_key: spki },
            vec![],
            Some(&kp),
        )
        .unwrap();
    assert!(
        matches!(&r[0], BrokerMsg::Err(e) if e.contains("QUOTA")),
        "oversized FNEW must be QUOTA, got {r:?}"
    );
}

#[test]
fn fput_validation() {
    let addr = spawn_engine();
    let mut c = Client::connect_plain(addr, &[0u8; 32]).unwrap();
    let kp = ed25519_keypair();
    let spki = spki_ed25519(&kp.verifying.to_bytes());
    let r = c
        .request(Command::Fnew { size: 100, digest: vec![0; 32], sender_key: spki }, vec![], Some(&kp))
        .unwrap();
    let pid = match &r[0] {
        BrokerMsg::Fid { packet_id } => packet_id.clone(),
        other => panic!("expected FID, got {other:?}"),
    };

    // offset beyond declared file size
    let r = c
        .request(Command::Fput { packet_id: pid.clone(), offset: 1000, chunk: vec![0u8; 10] }, vec![], Some(&kp))
        .unwrap();
    assert!(matches!(&r[0], BrokerMsg::Err(e) if e.contains("QUOTA")), "bad offset must be QUOTA, got {r:?}");

    // chunk larger than one block cannot even be encoded by the client (pad overflow)
    // — the server-side MAX_XFTP_CHUNK cap is defense-in-depth behind that.
    let r = c.request(
        Command::Fput { packet_id: pid.clone(), offset: 0, chunk: vec![0u8; MAX_XFTP_CHUNK + 1] },
        vec![],
        Some(&kp),
    );
    assert!(r.is_err(), "oversized chunk must fail at encode, got {r:?}");

    // a valid put still works
    let r = c
        .request(Command::Fput { packet_id: pid, offset: 0, chunk: vec![7u8; 10] }, vec![], Some(&kp))
        .unwrap();
    assert!(matches!(&r[0], BrokerMsg::Ok), "valid FPUT must be Ok, got {r:?}");
}

#[test]
fn fput_unknown_packet_rejected() {
    let addr = spawn_engine();
    let mut c = Client::connect_plain(addr, &[0u8; 32]).unwrap();
    let kp = ed25519_keypair();
    let r = c
        .request(Command::Fput { packet_id: vec![9u8; 16], offset: 0, chunk: vec![1u8; 4] }, vec![], Some(&kp))
        .unwrap();
    assert!(matches!(&r[0], BrokerMsg::Err(e) if e.contains("NO_FILE")), "got {r:?}");
}

#[test]
fn skey_without_signature_rejected_u04() {
    // U-04 regression: SKEY must require a signature — unsigned SKEY gets AUTH,
    // and SKEY addressed by rcv_id (the old lookup) must NOT rotate snd_auth.
    let addr = spawn_engine();
    let mut c = Client::connect_plain(addr, &[0u8; 32]).unwrap();
    let kp = ed25519_keypair();
    // create a queue (auth = recipient key signs)
    let rcv_spki = spki_ed25519(&kp.verifying.to_bytes());
    let dh = smp_rs::crypto::x25519_keypair();
    let r = c
        .request(
            Command::New {
                rcv_auth_key: rcv_spki,
                rcv_dh_key: smp_rs::crypto::spki_x25519(&dh.public.to_bytes()),
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

    // unsigned SKEY (auth=None) addressed by snd_id -> AUTH
    let new_kp = ed25519_keypair();
    let new_spki = spki_ed25519(&new_kp.verifying.to_bytes());
    let r = c.request(Command::Skey(new_spki.clone()), snd_id.clone(), None).unwrap();
    assert!(matches!(&r[0], BrokerMsg::Err(e) if e.contains("AUTH")), "unsigned SKEY must fail, got {r:?}");

    // SKEY addressed by rcv_id (old vulnerable lookup) -> AUTH, no rotation
    let r = c.request(Command::Skey(new_spki.clone()), rcv_id.clone(), Some(&new_kp)).unwrap();
    assert!(matches!(&r[0], BrokerMsg::Err(e) if e.contains("AUTH")), "SKEY by rcv_id must fail, got {r:?}");

    // signed SKEY by snd_id with the NEW key (first binding) -> Ok
    let r = c.request(Command::Skey(new_spki.clone()), snd_id.clone(), Some(&new_kp)).unwrap();
    assert!(matches!(&r[0], BrokerMsg::Ok), "signed SKEY must succeed, got {r:?}");
}
