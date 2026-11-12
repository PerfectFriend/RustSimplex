//! Chat protocol e2e over agent duplex connection: x.info profile + x.msg.new text both ways.

use smp_rs::agent::Agent;
use smp_rs::chat::*;
use smp_rs::client::Client;
use smp_rs::server::{spawn_engine, Engine};

#[test]
fn chat_text_over_agent_connection() {
    let eng = Engine::bind_plain("127.0.0.1:0").unwrap();
    let (addr, _st, _sd, _h) = spawn_engine(eng);
    let kh = vec![0x55u8; 32];

    let ci = Client::connect_plain(addr, &kh).unwrap();
    let (mut a, link) = Agent::create_contact(ci, "127.0.0.1", addr.port(), &kh, "alice").unwrap();
    let cj = Client::connect_plain(addr, &kh).unwrap();
    let mut b = Agent::join_contact(cj, &link).unwrap();
    a.accept_contact().unwrap();
    b.await_hello().unwrap();
    let (_, am) = a.recv_agent().unwrap();
    assert!(matches!(am, smp_rs::agent::AgentMsg::Hello { .. }));

    eprintln!("[t] send_info a");
    send_info(&mut a, "Alice").unwrap();
    eprintln!("[t] send_info b");
    send_info(&mut b, "Bob").unwrap();

    // text messages both ways
    eprintln!("[t] send_text a");
    let mid = send_text(&mut a, "hello bob!").unwrap();
    eprintln!("[t] recv_text b");
    let (rid, text) = recv_text(&mut b).unwrap();
    assert_eq!(rid, mid);
    assert_eq!(text, "hello bob!");

    let mid2 = send_text(&mut b, "hi alice!").unwrap();
    eprintln!("[t] recv_text a");
    let (rid2, text2) = recv_text(&mut a).unwrap();
    assert_eq!(rid2, mid2);
    assert_eq!(text2, "hi alice!");
}
