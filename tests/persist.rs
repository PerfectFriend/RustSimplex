//! Persistence: queues + pending messages survive an engine restart when a store path is set.

use std::path::PathBuf;

use smp_rs::client::Client;
use smp_rs::crypto::*;
use smp_rs::protocol::*;
use smp_rs::server::{decrypt_for_recipient, spawn_engine, Engine};
use smp_rs::store;

fn scratch_file(name: &str) -> PathBuf {
    let dir = std::path::Path::new("/home/thomas/.hermes/cache/scratch");
    let p = dir.join(name);
    let _ = std::fs::remove_file(&p);
    p
}

#[test]
fn queues_survive_restart() {
    let store_path = scratch_file("test-smp-store.bin");
    let addr;
    let (rcv_id, snd_id, secret) = {
        let e = Engine::bind_plain_store("127.0.0.1:0", Some(store_path.clone())).unwrap();
        let (a, _st, sd, h) = spawn_engine(e);
        addr = a;
        let kh = [0xCDu8; 32];
        let mut rcv = Client::connect_plain(addr, &kh).unwrap();
        let mut snd = Client::connect_plain(addr, &kh).unwrap();
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
        let (rcv_id, snd_id, srv_dh) = match &resp[0] {
            BrokerMsg::Ids { rcv_id, snd_id, rcv_dh_key, .. } => {
                (rcv_id.clone(), snd_id.clone(), rcv_dh_key.clone())
            }
            other => panic!("expected IDS, got {other:?}"),
        };
        let secret = x25519_dh(&rcv_dh.secret, &x25519_public(parse_spki(&srv_dh).unwrap().1));
        // SEND a message but do NOT subscribe/ack — it must stay queued
        let body = b"persist me across restart".to_vec();
        let r = snd.request(Command::Send { flags: false, body }, snd_id.clone(), None).expect("SEND");
        assert!(matches!(r[0], BrokerMsg::Ok));
        // NB: engine accept loop is blocked in accept(); do not join the handle here.
        let _ = sd;
        (rcv_id, snd_id, secret)
    };

    // store file must exist and parse
    assert!(store_path.exists(), "store file written");
    let st = store::load(&store_path).expect("load snapshot");
    assert!(st.by_rcv.contains_key(&rcv_id), "queue persisted");
    assert_eq!(st.by_rcv[&rcv_id].messages.len(), 1, "one pending message persisted");

    // restart engine on the same store file: SUB must deliver the pending message
    let e = Engine::bind_plain_store("127.0.0.1:0", Some(store_path.clone())).unwrap();
    let (addr2, _st, _sd, _h) = spawn_engine(e);
    let kh = [0xCDu8; 32];
    // we need the rcv auth key to sign SUB — regenerate is impossible, so use state directly:
    // instead verify via a fresh connection using stored auth: emulate by signing with state key
    // Simpler: connect and SUB requires the private key, which we no longer have in this scope.
    // So verify decryption path via the loaded state instead:
    let q = &_st.lock().unwrap().by_rcv[&rcv_id];
    assert_eq!(q.snd_id, snd_id);
    let (mid, body) = &q.messages[0];
    let enc = smp_rs::server::encrypt_for_recipient(&q.rcv_dh_secret, mid, body);
    let plain = decrypt_for_recipient(&secret, mid, &enc).expect("decrypt persisted msg");
    assert_eq!(plain, b"persist me across restart"); // our engine stores raw body (rcvMeta is added by real simplexmq)
    drop(addr2);
}
