//! W2 Task 1.3 — strict mode and the local-proxy guard must be per-connection /
//! per-engine, not process-global.
//!
//! Before this change the server read `SMP_STRICT` and the proxy guard read
//! `SMP_ALLOW_LOCAL_PROXY` from the process environment on every connection,
//! and the tests mutated those variables globally. With `cargo test` running
//! test binaries in parallel, one test could silently change the behaviour of
//! another (a coin flip that happened to pass 15 runs in a row).

use smp_rs::client::Client;
use smp_rs::server::{spawn_engine, Engine};
use std::sync::atomic::Ordering;

/// Two engines in one process: one strict, one not. The strict flag must not
/// leak from one engine to the other.
#[test]
fn strict_mode_is_per_engine_not_process_global() {
    // Engine A: strict enabled explicitly.
    let strict_engine = Engine::bind_plain_with_strict("127.0.0.1:0", true).expect("bind strict");
    let (addr_a, _st_a, shutdown_a, handle_a) = spawn_engine(strict_engine);

    // Engine B: strict disabled explicitly — in the same process, concurrently.
    let plain_engine = Engine::bind_plain_with_strict("127.0.0.1:0", false).expect("bind plain");
    let (addr_b, _st_b, shutdown_b, handle_b) = spawn_engine(plain_engine);

    // The two engines must be independently reachable.
    let a = Client::connect_plain_with_strict(addr_a, &[0u8; 32], true).expect("connect strict");
    let b = Client::connect_plain_with_strict(addr_b, &[0u8; 32], false).expect("connect plain");

    // A strict client must have derived its chain keys, a non-strict one must not.
    assert!(a.has_strict_keys(), "strict client must enable block encryption");
    assert!(!b.has_strict_keys(), "non-strict client must not enable block encryption");

    shutdown_a.store(true, Ordering::SeqCst);
    shutdown_b.store(true, Ordering::SeqCst);
    handle_a.join().ok();
    handle_b.join().ok();
}

/// The default (`bind_plain`) must not depend on the process environment.
#[test]
fn default_engine_strict_state_is_deterministic() {
    let e1 = Engine::bind_plain("127.0.0.1:0").expect("bind");
    let e2 = Engine::bind_plain("127.0.0.1:0").expect("bind");
    assert_eq!(e1.strict, e2.strict, "two default engines must agree on strict mode");
}

/// The local-proxy guard must be per-engine, not read from the environment on
/// every request.
#[test]
fn local_proxy_guard_is_per_engine() {
    // By default a local proxy destination is refused.
    let strict_engine = Engine::bind_plain_with_strict("127.0.0.1:0", false).expect("bind");
    assert!(!strict_engine.allow_local_proxy, "local proxy must be refused by default");

    // Explicitly enabled engines allow it.
    let permissive = Engine::bind_plain_with_proxy_and_strict("127.0.0.1:0", true, false).expect("bind");
    assert!(permissive.allow_local_proxy, "explicit opt-in must be honoured");
}
