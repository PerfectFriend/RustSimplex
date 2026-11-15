//! Known-failing opt-in E2E chat path (requires SMP_E2E=1). Kept ignored in the
//! default gate until the pqdr root-chain-after-HELLO edge is fixed.
#![cfg(test)]
use smp_rs::agent::Agent;
use smp_rs::chat::*;
use smp_rs::client::Client;
use smp_rs::server::{spawn_engine, Engine};

#[test]
#[ignore = "SMP_E2E=1 chat: first A_MSG AUTH — pqdr root chain after HELLO (backlog)"]
fn chat_e2e_over_pqdr() {
    if std::env::var("SMP_E2E").as_deref() != Ok("1") {
        return;
    }
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
    let mid = send_text(&mut a, "e2e hello").unwrap();
    let (rid, text) = recv_text(&mut b).unwrap();
    assert_eq!(rid, mid);
    assert_eq!(text, "e2e hello");
}
