//! W4-Task 4.1: e2e tests for the REAL async SMP client (`smp_rs::async_client::AsyncSmpClient`).
//!
//! The sync server engine (`smp_rs::server::Engine`) runs on std threads; the
//! async client talks to it over ordinary TCP / TLS 1.3 from a tokio runtime.
//!
//! NOTE on runtime flavor: `#[tokio::test]` defaults to a current_thread
//! runtime, which makes the non-blocking proof below stronger — a blocking
//! (std::net / spawn_blocking-facade) implementation would stall the only
//! worker thread and the timer assertion would fail.

use smp_rs::async_client::AsyncSmpClient;
use smp_rs::protocol::{BrokerMsg, Command};
use smp_rs::server::{spawn_engine, Engine};
use std::net::{SocketAddr, TcpListener};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// A real server engine on a std thread, stopped cleanly on drop-ish `stop()`.
struct TestServer {
    addr: SocketAddr,
    shutdown: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl TestServer {
    fn from_engine(engine: Engine) -> TestServer {
        let (addr, _state, shutdown, handle) = spawn_engine(engine);
        TestServer { addr, shutdown, handle: Some(handle) }
    }
    fn start_plain() -> TestServer {
        let engine = Engine::bind_plain("127.0.0.1:0").expect("bind plain engine");
        Self::from_engine(engine)
    }
    fn start_plain_strict() -> TestServer {
        let engine = Engine::bind_plain_with_strict("127.0.0.1:0", true).expect("bind strict engine");
        Self::from_engine(engine)
    }
    fn start_tls() -> (TestServer, [u8; 32]) {
        let engine = Engine::bind_tls("127.0.0.1:0", "127.0.0.1").expect("bind tls engine");
        let kh = engine.key_hash().expect("tls engine has a key hash");
        (Self::from_engine(engine), kh)
    }
    fn stop(mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

fn has_pong(msgs: &[BrokerMsg]) -> bool {
    msgs.iter().any(|m| matches!(m, BrokerMsg::Pong))
}

#[tokio::test]
async fn plain_handshake_then_ping_pong() {
    let server = TestServer::start_plain();
    let key_hash = [0xABu8; 32];
    let mut c = AsyncSmpClient::connect_plain(server.addr, &key_hash)
        .await
        .expect("connect_plain");
    assert!(c.session_id().is_empty(), "plain mode session id is empty");
    let reply = c.request(Command::Ping, vec![], None).await.expect("PING request");
    assert!(has_pong(&reply), "expected PONG, got {reply:?}");
    server.stop();
}

#[tokio::test]
async fn send_only_then_recv_block_roundtrip() {
    let server = TestServer::start_plain();
    let mut c = AsyncSmpClient::connect_plain(server.addr, &[0xCD; 32])
        .await
        .expect("connect_plain");
    c.send_only(Command::Ping, vec![], None).await.expect("send_only");
    let reply = c.recv_block().await.expect("recv_block");
    assert!(has_pong(&reply), "expected PONG, got {reply:?}");
    server.stop();
}

#[tokio::test]
async fn new_then_connect_plain_ping() {
    let server = TestServer::start_plain();
    let mut c = AsyncSmpClient::new("127.0.0.1", server.addr.port(), [0xEF; 32], false);
    c.connect().await.expect("connect()");
    assert!(c.is_connected());
    let reply = c.request(Command::Ping, vec![], None).await.expect("PING");
    assert!(has_pong(&reply), "expected PONG, got {reply:?}");
    server.stop();
}

#[tokio::test]
async fn tls_handshake_then_ping_pong() {
    let (server, kh) = TestServer::start_tls();
    let mut c = AsyncSmpClient::connect_tls(server.addr, "127.0.0.1", kh, true)
        .await
        .expect("connect_tls (real async TLS 1.3 handshake)");
    assert_eq!(c.session_id().len(), 32, "TLS session id is the 32-byte channel binding");
    let reply = c.request(Command::Ping, vec![], None).await.expect("PING over TLS");
    assert!(has_pong(&reply), "expected PONG, got {reply:?}");
    server.stop();
}

#[tokio::test]
async fn tls_wrong_key_hash_is_rejected() {
    // Router key-hash pinning is a security property: a TLS peer presenting a
    // different offline CA must fail the handshake (PinVerifier in
    // crate::transport::tls_client_config). The plain path cannot pin (no TLS),
    // exactly like the sync client.
    let (server, _kh) = TestServer::start_tls();
    let wrong = [0x11u8; 32];
    let r = AsyncSmpClient::connect_tls(server.addr, "127.0.0.1", wrong, true).await;
    assert!(r.is_err(), "client must reject a router whose keyHash does not match, got {r:?}");
    server.stop();
}

#[tokio::test]
async fn two_concurrent_async_clients_both_get_pong() {
    let server = TestServer::start_plain();
    let mut a = AsyncSmpClient::connect_plain(server.addr, &[0x01; 32]).await.expect("client A");
    let mut b = AsyncSmpClient::connect_plain(server.addr, &[0x02; 32]).await.expect("client B");
    let (ra, rb) = tokio::join!(a.request(Command::Ping, vec![], None), b.request(Command::Ping, vec![], None));
    let ra = ra.expect("PING on client A");
    let rb = rb.expect("PING on client B");
    assert!(has_pong(&ra), "client A expected PONG, got {ra:?}");
    assert!(has_pong(&rb), "client B expected PONG, got {rb:?}");
    server.stop();
}

#[tokio::test]
async fn pending_connect_does_not_block_the_tokio_runtime() {
    // A "stalled" server: accepts TCP but never sends the SMP server hello, and
    // only drops the socket after 600 ms. While the connect future is pending,
    // the runtime must still run timers. With the current_thread runtime a
    // blocking implementation would stall the only worker thread for the whole
    // 600 ms, so the 100 ms sleep could not complete before 500 ms elapsed.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind stalled listener");
    let addr = listener.local_addr().expect("addr");
    std::thread::spawn(move || {
        if let Ok((sock, _peer)) = listener.accept() {
            std::thread::sleep(Duration::from_millis(600));
            drop(sock); // EOF for the client
        }
    });
    let kh = [0u8; 32];
    let pending = tokio::spawn(async move { AsyncSmpClient::connect_plain(addr, &kh).await });
    let t0 = std::time::Instant::now();
    tokio::time::timeout(Duration::from_secs(2), tokio::time::sleep(Duration::from_millis(100)))
        .await
        .expect("timer must fire while a connection attempt is pending");
    let elapsed = t0.elapsed();
    assert!(
        elapsed < Duration::from_millis(500),
        "executor appears blocked ({elapsed:?}) — the async client must yield, not block the runtime"
    );
    let res = pending.await.expect("join handle");
    assert!(res.is_err(), "stalled server must surface an error after EOF, got {res:?}");
}

#[tokio::test]
async fn strict_v23_blocks_work_over_the_async_transport() {
    // Both sides enable strict v23 block-chain encryption. The async client
    // reuses the pure sb_chain crypto (encrypt_block/decrypt_block) and must
    // interoperate with the sync server pump.
    let server = TestServer::start_plain_strict();
    let mut c = AsyncSmpClient::connect_plain(server.addr, &[0x07; 32])
        .await
        .expect("connect_plain");
    c.maybe_enable_strict(true).unwrap();
    assert!(c.has_strict_keys(), "strict keys derived from the server hello authPubKey");
    let reply = c.request(Command::Ping, vec![], None).await.expect("PING in strict mode");
    assert!(has_pong(&reply), "expected PONG in strict mode, got {reply:?}");
    server.stop();
}
