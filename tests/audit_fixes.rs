//! Regression tests for the 2026-11 multi-zone security audit findings (CRITICAL/HIGH).
//! Rule under test: wire/peer-controlled input must produce Err, never a panic;
//! E2E must fail closed; delivered messages must be ACKed (no redelivery).
#![cfg(test)]
use smp_rs::agent::Agent;
use smp_rs::client::Client;
use smp_rs::pq::KEM_PK_LEN;
use smp_rs::pqdr::{kem_encaps_pub, PqdrRatchet};
use smp_rs::server::{spawn_engine, Engine};
use smp_rs::crypto::x25519_keypair;

#[test]
fn audit_kem_encaps_pub_bad_len_is_err_not_panic() {
    assert!(kem_encaps_pub(&[]).is_err());
    assert!(kem_encaps_pub(&[0u8; KEM_PK_LEN - 1]).is_err());
    assert!(kem_encaps_pub(&[0u8; KEM_PK_LEN + 1]).is_err());
}

#[test]
fn audit_init_sender_bad_peer_kem_is_err_not_panic() {
    // peer KEM key from a forged connInfo must not crash the initiator
    let sk = [9u8; 32];
    let dh = x25519_keypair();
    let r = PqdrRatchet::init_sender(&sk, vec![], dh.public, vec![]);
    assert!(r.is_err());
    let r2 = PqdrRatchet::init_sender(&sk, vec![], dh.public, vec![0u8; 10]);
    assert!(r2.is_err());
}

fn pair() -> (Agent, Agent) {
    let eng = Engine::bind_plain("127.0.0.1:0").unwrap();
    let (addr, _st, _sd, _h) = spawn_engine(eng);
    let kh = vec![0x66u8; 32];
    let ci = Client::connect_plain(addr, &kh).unwrap();
    let (mut a, link) = Agent::create_contact(ci, "127.0.0.1", addr.port(), &kh, "alice").unwrap();
    let cj = Client::connect_plain(addr, &kh).unwrap();
    let mut b = Agent::join_contact(cj, &link).unwrap();
    a.accept_contact().unwrap();
    b.await_hello().unwrap();
    let _ = a.recv_agent().unwrap();
    (a, b)
}

#[test]
fn audit_send_msg_fail_closed_without_ratchet() {
    let (mut a, _b) = pair();
    a.ratchet = None; // simulate negotiation failure
    a.e2e = true;
    let r = a.send_msg(b"must not go plaintext");
    assert!(r.is_err(), "e2e=true with no ratchet must refuse plaintext send");
}

#[test]
fn audit_recv_agent_acks_so_no_redelivery() {
    use smp_rs::protocol::{BrokerMsg, Command};
    let (mut a, mut b) = pair();
    a.send_msg(b"m1").unwrap();
    let (id1, _m1) = b.recv_agent().unwrap();
    // recv_agent must have ACKed: drain the stale ACK-Ok response block(s), then a
    // fresh SUB on the same queue must return SOK with NO Msg for id1.
    let mut sub = b
        .client
        .request(Command::Sub, b.rcv_id.clone(), Some(&b.rcv_auth))
        .unwrap();
    if !sub.iter().any(|m| matches!(m, BrokerMsg::Sok(_))) {
        // first block was the stale ACK response — read the real SUB response
        sub = b.client.recv_block().unwrap();
    }
    assert!(sub.iter().any(|m| matches!(m, BrokerMsg::Sok(_))), "SUB: {sub:?}");
    assert!(
        !sub.iter().any(|m| matches!(m, BrokerMsg::Msg { msg_id, .. } if *msg_id == id1)),
        "ACK missing: msg {id1:?} redelivered on re-SUB"
    );
    // and the next real message still flows
    a.send_msg(b"m2").unwrap();
    let (id2, _m2) = b.recv_agent().unwrap();
    assert_ne!(id1, id2);
}
