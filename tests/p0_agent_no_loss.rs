//! P0-6 (audited 2026-11-23): the agent layer must not lose messages.
//!
//! Acceptance criteria from the audit:
//!  - a SEND answered with `ERR` must surface as an error (not a silent success);
//!  - a block carrying 3 MSG frames must yield 3 messages, not 1.

use smp_rs::agent::*;
use smp_rs::crypto::*;
use smp_rs::protocol::{BrokerMsg, Command};
use smp_rs::reconnect::SmpTransport;
use smp_rs::client::ClResult;

/// A transport that answers from a scripted queue of blocks and records the commands.
struct MockTransport {
    blocks: Vec<Vec<BrokerMsg>>,
    responses: Vec<Vec<BrokerMsg>>,
    acks: Vec<Vec<u8>>,
}

impl MockTransport {
    fn new() -> Self {
        MockTransport { blocks: Vec::new(), responses: Vec::new(), acks: Vec::new() }
    }
}

impl SmpTransport for MockTransport {
    fn request(&mut self, _cmd: Command, _entity_id: Vec<u8>, _auth: Option<&Ed25519Keypair>) -> ClResult<Vec<BrokerMsg>> {
        if self.responses.is_empty() {
            Ok(vec![BrokerMsg::Ok])
        } else {
            Ok(self.responses.remove(0))
        }
    }
    fn send_only(&mut self, cmd: Command, _entity_id: Vec<u8>, _auth: Option<&Ed25519Keypair>) -> ClResult<()> {
        if let Command::Ack(id) = cmd {
            self.acks.push(id);
        }
        Ok(())
    }
    fn recv_block(&mut self) -> ClResult<Vec<BrokerMsg>> {
        if self.blocks.is_empty() {
            Ok(vec![BrokerMsg::Ok])
        } else {
            Ok(self.blocks.remove(0))
        }
    }
    fn session_id(&self) -> Option<&[u8]> {
        None
    }
    fn enable_strict(&mut self, _dh_secret: &[u8; 32]) {}
}

/// Build an agent with a mock transport and the matching DH material.
fn agent_with(t: MockTransport) -> (Agent<MockTransport>, [u8; 32]) {
    let rcv_dh = x25519_keypair();
    let srv = x25519_keypair();
    let secret = x25519_dh(&rcv_dh.secret, &x25519_public(srv.public.to_bytes()));
    let a = Agent {
        client: t,
        rcv_auth: ed25519_keypair(),
        rcv_dh: rcv_dh.clone(),
        rcv_id: b"rcv".to_vec(),
        snd_id: b"snd".to_vec(),
        srv_dh: spki_x25519(&srv.public.to_bytes()),
        peer_snd_id: Some(b"peer".to_vec()),
        msg_counter: 0,
        prev_hash: vec![0u8; 32],
        host: "127.0.0.1".into(),
        port: 5222,
        key_hash: vec![0u8; 32],
        kem: None,
        ratchet: None,
        init_ci: Vec::new(),
        initiator: true,
        outbox: Vec::new(),
        e2e: false,
        x448_kp: None,
        peer_x448_spki: None,
        x448_shared: None,
        pending_msgs: std::collections::VecDeque::new(),
    };
    (a, secret)
}

#[test]
fn send_rejected_by_the_server_is_an_error() {
    let mut t = MockTransport::new();
    t.responses.push(vec![BrokerMsg::Err("AUTH bad signature".into())]);
    let (mut a, _secret) = agent_with(t);

    let err = a.send_msg(b"hello").expect_err("an ERR reply must not look like success");
    assert!(err.contains("SEND rejected"), "unexpected error: {err}");
    assert!(err.contains("AUTH"), "the server error must be visible: {err}");
}

#[test]
fn send_ok_is_reported_as_success() {
    let mut t = MockTransport::new();
    t.responses.push(vec![BrokerMsg::Ok]);
    let (mut a, _secret) = agent_with(t);
    assert_eq!(a.send_msg(b"hello").unwrap(), 1);
}

#[test]
fn a_block_with_three_messages_yields_three_messages() {
    let (mut a, secret) = agent_with(MockTransport::new());

    // three MSG frames in ONE broker block
    let mut block = Vec::new();
    for i in 0..3i64 {
        let msg_id = format!("m{i}").into_bytes();
        let frame = encode_agent(
            &AgentMsg::Msg { msg_id: i, prev_hash: vec![0u8; 32], body: format!("body-{i}").into_bytes() },
            i,
            &[0u8; 32],
        );
        let enc = smp_rs::server::encrypt_for_recipient(&secret, &msg_id, &frame).unwrap();
        block.push(BrokerMsg::Msg { msg_id, body: enc });
    }
    a.client.blocks.push(block);

    // recv_agent returns them one by one — none may be dropped
    let mut got = Vec::new();
    for _ in 0..3 {
        let (_id, am) = a.recv_agent().unwrap();
        match am {
            AgentMsg::Msg { msg_id, body, .. } => got.push((msg_id, body)),
            other => panic!("unexpected agent message: {other:?}"),
        }
    }
    assert_eq!(got.len(), 3, "all three messages must be delivered");
    assert_eq!(got[0].0, 0);
    assert_eq!(got[1].0, 1);
    assert_eq!(got[2].0, 2);
    assert_eq!(got[2].1, b"body-2".to_vec());

    // every message was ACKed exactly once (queue cleanup without loss)
    assert_eq!(a.client.acks.len(), 3, "each message must be ACKed once");
}

#[test]
fn recv_agent_all_returns_the_whole_block() {
    let (mut a, secret) = agent_with(MockTransport::new());

    let mut block = Vec::new();
    for i in 0..3i64 {
        let msg_id = format!("m{i}").into_bytes();
        let frame = encode_agent(
            &AgentMsg::Msg { msg_id: i, prev_hash: vec![0u8; 32], body: format!("body-{i}").into_bytes() },
            i,
            &[0u8; 32],
        );
        let enc = smp_rs::server::encrypt_for_recipient(&secret, &msg_id, &frame).unwrap();
        block.push(BrokerMsg::Msg { msg_id, body: enc });
    }
    a.client.blocks.push(block);

    let all = a.recv_agent_all().unwrap();
    assert_eq!(all.len(), 3, "recv_agent_all must return every message of the block");
    assert_eq!(a.client.acks.len(), 3);
}
