//! W4-Task 4.2: the backoff cycle must be real, observable and testable.
//!
//! The plan's scenario: the server fails 3 times in a row -> the client comes
//! up after an exponential backoff, and the backoff never exceeds max_backoff.
//!
//! The test drives the schedule with a small base and a small cap and asserts
//! on the RECORDED delays, not on wall-clock timing: a timing-based test would
//! be flaky on a loaded machine and would prove nothing about the policy.

use smp_rs::protocol::{BrokerMsg, Command};
use smp_rs::reconnect::{Endpoint, ReconnectingClient};
use smp_rs::server::{handle_conn, new_state, Mode};
use std::net::{SocketAddr, TcpListener};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// A server that drops the first `failures` connections during the handshake
/// and serves the rest normally.
fn flaky_server(failures: usize) -> (SocketAddr, Arc<AtomicBool>, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind flaky listener");
    let addr = listener.local_addr().expect("addr");
    let stop = Arc::new(AtomicBool::new(false));
    let stop_thread = stop.clone();
    let handle = std::thread::spawn(move || {
        let st = new_state();
        let mut dropped = 0usize;
        listener
            .set_nonblocking(true)
            .expect("non-blocking listener");
        loop {
            if stop_thread.load(Ordering::SeqCst) {
                break;
            }
            match listener.accept() {
                Ok((tcp, _peer)) => {
                    // On Linux the accepted socket inherits O_NONBLOCK from the
                    // listener — the server's blocking read path must not see
                    // EAGAIN (the same trap the Engine hit, see ROADMAP W1.4).
                    let _ = tcp.set_nonblocking(false);
                    if dropped < failures {
                        dropped += 1;
                        // EOF in the middle of the SMP handshake -> the client's
                        // connect attempt fails and the backoff kicks in.
                        drop(tcp);
                        continue;
                    }
                    let _ = handle_conn(tcp, &Mode::Plain, st.clone(), false, false);
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(2));
                }
                Err(_) => break,
            }
        }
    });
    (addr, stop, handle)
}

fn endpoint(addr: SocketAddr) -> Endpoint {
    Endpoint {
        addr,
        host: "test".into(),
        key_hash: [0u8; 32],
        tls: false,
        with_sni: true,
    }
}

fn has_pong(msgs: &[BrokerMsg]) -> bool {
    msgs.iter().any(|m| matches!(m, BrokerMsg::Pong))
}

#[test]
fn backoff_schedule_is_exponential_and_capped() {
    let ep = endpoint("127.0.0.1:1".parse().expect("addr"));
    let rc = ReconnectingClient::with_backoff(ep, Duration::from_millis(5), Duration::from_millis(40));
    assert_eq!(rc.base_backoff(), Duration::from_millis(5));
    assert_eq!(rc.max_backoff(), Duration::from_millis(40));
    assert_eq!(rc.backoff_for(0), Duration::from_millis(5));
    assert_eq!(rc.backoff_for(1), Duration::from_millis(10));
    assert_eq!(rc.backoff_for(2), Duration::from_millis(20));
    // the cap applies from the third attempt on
    assert_eq!(rc.backoff_for(3), Duration::from_millis(40));
    assert_eq!(rc.backoff_for(10), Duration::from_millis(40));
    // a huge attempt number must NOT overflow and must NOT hang
    assert_eq!(rc.backoff_for(u32::MAX), Duration::from_millis(40));
    // a base larger than the cap saturates to the cap
    let big = ReconnectingClient::with_backoff(
        endpoint("127.0.0.1:1".parse().expect("addr")),
        Duration::from_secs(60),
        Duration::from_millis(40),
    );
    assert_eq!(big.backoff_for(0), Duration::from_millis(40));
    // a zero base means no delay at all (and must not loop forever)
    let zero = ReconnectingClient::with_backoff(
        endpoint("127.0.0.1:1".parse().expect("addr")),
        Duration::ZERO,
        Duration::from_millis(40),
    );
    assert_eq!(zero.backoff_for(u32::MAX), Duration::ZERO);
}

#[test]
fn defaults_are_unchanged() {
    let ep = endpoint("127.0.0.1:1".parse().expect("addr"));
    let rc = ReconnectingClient::new(ep);
    assert_eq!(rc.base_backoff(), Duration::from_millis(50));
    assert_eq!(rc.max_backoff(), Duration::from_secs(8));
    assert_eq!(rc.backoff_for(0), Duration::from_millis(50));
    assert_eq!(rc.backoff_for(3), Duration::from_millis(400));
}

#[test]
fn client_comes_up_after_three_consecutive_failures() {
    // The plan's scenario: the server fails 3 times in a row, the client
    // recovers, and every applied delay stays within the cap.
    let (addr, stop, handle) = flaky_server(3);
    let mut rc = ReconnectingClient::with_backoff(
        endpoint(addr),
        Duration::from_millis(5),
        Duration::from_millis(40),
    );
    rc.connect_with_retry(8).expect("the client must come up");
    let applied = rc.applied_backoffs().to_vec();
    assert_eq!(
        applied,
        vec![Duration::from_millis(5), Duration::from_millis(10), Duration::from_millis(20)],
        "three failures -> three exponential delays"
    );
    assert!(
        applied.iter().all(|d| *d <= rc.max_backoff()),
        "no delay may exceed max_backoff: {applied:?}"
    );
    assert_eq!(rc.backoff_count(), 3);
    assert_eq!(rc.total_backoff(), Duration::from_millis(35));
    assert_eq!(rc.last_backoff(), Some(Duration::from_millis(20)));
    // the recovered connection really works
    let reply = rc.request(Command::Ping, vec![], None).expect("PING after recovery");
    assert!(has_pong(&reply), "expected PONG, got {reply:?}");
    // the server thread is inside handle_conn until the client goes away
    drop(rc);
    stop.store(true, Ordering::SeqCst);
    let _ = handle.join();
}

#[test]
fn a_dead_server_exhausts_the_budget_with_a_capped_backoff() {
    // port 1 is closed: every attempt fails, the delays grow and then sit at
    // the cap.
    let mut rc = ReconnectingClient::with_backoff(
        endpoint("127.0.0.1:1".parse().expect("addr")),
        Duration::from_millis(5),
        Duration::from_millis(40),
    );
    let err = rc.connect_with_retry(6).expect_err("a dead server must fail");
    assert!(!err.is_empty());
    let applied = rc.applied_backoffs().to_vec();
    assert_eq!(
        applied,
        vec![
            Duration::from_millis(5),
            Duration::from_millis(10),
            Duration::from_millis(20),
            Duration::from_millis(40),
            Duration::from_millis(40),
        ],
        "the delay grows and then sticks at max_backoff"
    );
}

#[test]
fn the_strict_secret_survives_a_reconnect() {
    let (addr, stop, handle) = flaky_server(0);
    let mut rc = ReconnectingClient::with_backoff(
        endpoint(addr),
        Duration::from_millis(5),
        Duration::from_millis(40),
    );
    rc.connect_with_retry(4).expect("connect");
    rc.enable_strict([7u8; 32]);
    assert!(rc.has_strict_keys(), "strict keys are active after enable_strict");
    // drop the connection and let the client redial: the remembered secret must
    // be re-applied to the new session.
    rc.force_reconnect();
    rc.connect_with_retry(4).expect("reconnect");
    assert!(
        rc.has_strict_keys(),
        "the strict secret must be re-applied after a reconnect"
    );
    drop(rc);
    stop.store(true, Ordering::SeqCst);
    let _ = handle.join();
}
