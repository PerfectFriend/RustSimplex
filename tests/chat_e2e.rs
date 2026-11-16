//! E2E chat over PQDR ratchet, ON BY DEFAULT (Agent::e2e = true).
//! Covers the old backlog edge: first A_MSG after HELLO, plus concurrent send from both sides.
#![cfg(test)]
use smp_rs::agent::Agent;
use smp_rs::chat::*;
use smp_rs::client::Client;
use smp_rs::server::{spawn_engine, Engine};

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
fn chat_e2e_over_pqdr_default_on() {
    let (mut a, mut b) = pair();
    let mid = send_text(&mut a, "e2e hello").unwrap();
    let (rid, text) = recv_text(&mut b).unwrap();
    assert_eq!(rid, mid);
    assert_eq!(text, "e2e hello");
    // reverse direction after ratchet established
    let mid2 = send_text(&mut b, "e2e reply").unwrap();
    let (rid2, text2) = recv_text(&mut a).unwrap();
    assert_eq!(rid2, mid2);
    assert_eq!(text2, "e2e reply");
}

#[test]
fn chat_e2e_concurrent_first_send() {
    // Both sides send their first message before reading anything:
    // joiner's outbox must buffer until the first inbound ratchet frame sets ckr.
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
    let m1 = send_text(&mut a, "from a").unwrap();
    let m2 = send_text(&mut b, "from b").unwrap();
    let (r1, t1) = recv_text(&mut b).unwrap();
    let (r2, t2) = recv_text(&mut a).unwrap();
    assert_eq!((r1, t1.as_str()), (m1, "from a"));
    assert_eq!((r2, t2.as_str()), (m2, "from b"));
}
