//! Regression tests for external audit #3 (2026-11-25), findings U-01/C1 and U-12/H6:
//! the receive side of an established E2E session must fail closed — a raw or
//! confirmation-wrapped plaintext agent frame injected into the queue (anyone who
//! knows snd_id can SEND) must NOT be delivered, and an undecryptable ratchet
//! frame must NOT wedge the queue (it is ACKed and dropped, the next real
//! message still flows).
//!
//! RED proof: on the pre-fix code these tests fail — the injected frame is
//! returned by recv_agent as a genuine peer message (U-01), and the bad ratchet
//! frame makes recv_agent return Err without ACK (U-12 wedge).
use smp_rs::agent::{encode_agent, Agent, AgentMsg};
use smp_rs::agent_envelope::{encode as env_encode, Envelope};
use smp_rs::client::Client;
use smp_rs::protocol::Command;
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

/// Inject a body into the peer's queue as if it came from the peer (attacker
/// knows snd_id from the link; the queue has no snd_auth in this harness).
fn inject(a: &mut Agent, body: Vec<u8>) {
    let peer = a.peer_snd_id.clone().expect("peer snd id");
    let resp = a
        .client
        .request(Command::Send { flags: false, body }, peer, None)
        .expect("inject SEND");
    assert!(
        resp.iter().all(|m| !matches!(m, smp_rs::protocol::BrokerMsg::Err(_))),
        "inject rejected: {resp:?}"
    );
}

#[test]
fn u01_raw_plaintext_frame_in_e2e_session_is_dropped_not_delivered() {
    let (mut a, mut b) = pair();
    assert!(b.ratchet.is_some(), "harness must have an established ratchet");
    // legacy raw frame: no agentMsgEnvelope version prefix — pre-fix code accepts it
    let raw = encode_agent(
        &AgentMsg::Msg { msg_id: 1, prev_hash: vec![], body: b"INJECTED".to_vec() },
        1,
        &[],
    );
    inject(&mut a, raw);
    a.send_msg(b"real").unwrap();
    let (_id, am) = b.recv_agent().expect("recv must skip the forged frame and return the real one");
    match am {
        AgentMsg::Msg { body, .. } => assert_eq!(body, b"real", "forged plaintext frame was delivered!"),
        other => panic!("expected the real Msg, got {other:?}"),
    }
}

#[test]
fn u01_confirmation_wrapped_plaintext_is_dropped_in_e2e_session() {
    let (mut a, mut b) = pair();
    // wrap the raw frame in a "C" confirmation envelope: pre-fix code treats the
    // confirmation payload as plaintext and delivers it mid-session
    let raw = encode_agent(
        &AgentMsg::Msg { msg_id: 2, prev_hash: vec![], body: b"INJECTED-C".to_vec() },
        2,
        &[],
    );
    let wrapped = env_encode(&Envelope::Confirmation { pq: false, e2e_params: vec![], enc_conn_info: raw });
    inject(&mut a, wrapped);
    a.send_msg(b"real2").unwrap();
    let (_id, am) = b.recv_agent().expect("recv must skip the confirmation-wrapped frame");
    match am {
        AgentMsg::Msg { body, .. } => assert_eq!(body, b"real2"),
        other => panic!("expected the real Msg, got {other:?}"),
    }
}

#[test]
fn u12_bad_ratchet_frame_is_acked_and_does_not_wedge_the_queue() {
    let (mut a, mut b) = pair();
    // valid "M" envelope with garbage ciphertext: ratchet decrypt fails. Pre-fix
    // code propagated the error WITHOUT ACK, so the message was redelivered on
    // every SUB forever (queue wedge). Post-fix: ACK + drop, next message flows.
    let bad = env_encode(&Envelope::Msg { enc_agent_msg: vec![0xAA; 64] });
    inject(&mut a, bad);
    a.send_msg(b"after-garbage").unwrap();
    let (_id, am) = b.recv_agent().expect("queue must not be wedged by a bad ratchet frame");
    match am {
        AgentMsg::Msg { body, .. } => assert_eq!(body, b"after-garbage"),
        other => panic!("expected the real Msg, got {other:?}"),
    }
    // and the garbage frame was ACKed: a fresh SUB must not redeliver it
    use smp_rs::protocol::BrokerMsg;
    let mut sub = b
        .client
        .request(Command::Sub, b.rcv_id.clone(), Some(&b.rcv_auth))
        .unwrap();
    if !sub.iter().any(|m| matches!(m, BrokerMsg::Sok(_))) {
        sub = b.client.recv_block().unwrap();
    }
    assert!(
        !sub.iter().any(|m| matches!(m, BrokerMsg::Msg { body, .. } if body.len() == 64 + 8)),
        "garbage frame was not ACKed: {sub:?}"
    );
}
