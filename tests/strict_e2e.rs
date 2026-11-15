//! Strict v23 block-chain e2e (local): SMP_STRICT=1 makes both peers use 16384B ciphertext blocks.
use std::net::SocketAddr;

use smp_rs::client::Client;
use smp_rs::crypto::*;
use smp_rs::protocol::*;
use smp_rs::server::{spawn_engine, Engine};

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
    assert!(matches!(r[0], BrokerMsg::Ids { .. }), "got {r:?}");
}
