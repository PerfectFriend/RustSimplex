//! ReconnectingClient integration: the client must recover by itself when the
//! server goes away and comes back on the same address.
//!
//! This is the W1-Task 1.2 proof that `ReconnectingClient` is reachable from a
//! real call path (audit finding N-14: it was `pub` with no caller and no test).

use smp_rs::crypto::*;
use smp_rs::protocol::*;
use smp_rs::reconnect::{Endpoint, ReconnectingClient};
use smp_rs::server::{spawn_engine, Engine};
use std::net::TcpListener;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

fn free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind probe");
    l.local_addr().expect("addr").port()
}

/// A server we can stop and restart on the same port.
struct StoppableServer {
    addr: std::net::SocketAddr,
    shutdown: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl StoppableServer {
    fn start(port: u16) -> StoppableServer {
        let engine = Engine::bind_plain(&format!("127.0.0.1:{port}")).expect("bind engine");
        let (addr, _state, shutdown, handle) = spawn_engine(engine);
        StoppableServer { addr, shutdown, handle: Some(handle) }
    }

    /// Ask the server to stop and wait for the accept loop to exit, so the
    /// listening socket is really closed before we rebind the port.
    fn stop(mut self) {
        self.shutdown.store(true, std::sync::atomic::Ordering::SeqCst);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

fn new_queue_cmd(rcv_auth: &Ed25519Keypair, rcv_dh: &X25519Keypair) -> Command {
    Command::New {
        rcv_auth_key: spki_ed25519(&rcv_auth.verifying.to_bytes()),
        rcv_dh_key: spki_x25519(&rcv_dh.public.to_bytes()),
        basic_auth: None,
        sub_mode: b'S',
        queue_req_data: None,
        ntf_creds: None,
    }
}

#[test]
fn reconnecting_client_recovers_after_server_restart() {
    let port = free_port();
    let server = StoppableServer::start(port);
    let addr = server.addr;
    let kh = [0xAB; 32];

    let ep = Endpoint {
        addr,
        host: "127.0.0.1".to_string(),
        key_hash: kh,
        tls: false,
        with_sni: true,
    };
    let mut rc = ReconnectingClient::new(ep);

    // --- Phase 1: server is up; create a queue through the reconnecting client.
    let rcv_auth = ed25519_keypair();
    let rcv_dh = x25519_keypair();
    let ids = rc
        .request(new_queue_cmd(&rcv_auth, &rcv_dh), vec![], Some(&rcv_auth))
        .expect("NEW through reconnecting client");
    let (rcv_id, _snd_id) = match &ids[0] {
        BrokerMsg::Ids { rcv_id, snd_id, .. } => (rcv_id.clone(), snd_id.clone()),
        other => panic!("expected IDS, got {other:?}"),
    };

    eprintln!("[phase2] stopping server");
    // --- Phase 2: stop the server, then bring a new one up on the same port.
    server.stop();
    eprintln!("[phase2] server stopped");
    eprintln!("[phase2] starting server2");
    let server2 = StoppableServer::start(port);
    eprintln!("[phase2] server2 up");
    assert_eq!(server2.addr.port(), port, "server must come back on the same port");

    // --- Phase 3: the very next request must succeed without any explicit
    // reconnect() call from the caller.
    let rcv_auth2 = ed25519_keypair();
    let rcv_dh2 = x25519_keypair();
    eprintln!("[phase3] requesting through reconnecting client");
    let ids2 = rc
        .request(new_queue_cmd(&rcv_auth2, &rcv_dh2), vec![], Some(&rcv_auth2))
        .expect("NEW after server restart — reconnecting client must re-dial by itself");
    assert!(
        matches!(ids2[0], BrokerMsg::Ids { .. }),
        "expected IDS after reconnect, got {:?}",
        ids2[0]
    );

    // Session state (queue ids) lives in the agent layer and survives reconnects —
    // SMP is stateless per connection.
    assert!(!rcv_id.is_empty());
    server2.stop();
}

#[test]
fn reconnecting_client_reports_failure_when_server_never_returns() {
    // A port nobody listens on: the client must surface an error rather than
    // hang forever or panic.
    let port = free_port();
    let ep = Endpoint {
        addr: format!("127.0.0.1:{port}").parse().expect("addr"),
        host: "127.0.0.1".to_string(),
        key_hash: [0xCD; 32],
        tls: false,
        with_sni: true,
    };
    let mut rc = ReconnectingClient::new(ep);
    let started = std::time::Instant::now();
    let res = rc.request(Command::Ping, vec![], None);
    assert!(res.is_err(), "expected an error against a dead port, got {res:?}");
    assert!(
        started.elapsed() < Duration::from_secs(30),
        "reconnect must give up in bounded time, took {:?}",
        started.elapsed()
    );
}
