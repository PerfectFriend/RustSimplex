//! W2 Task 2.4 — local NTF server e2e: the full signed command cycle
//! `TNEW -> IDTKN` / `SNEW -> IDSUB`, deterministically and without network access.

use smp_rs::crypto::{ed25519_keypair, spki_ed25519, spki_x25519};
use smp_rs::ntf::*;
use smp_rs::ntf_server::{spawn_engine, NtfEngine};
use std::io::{Read, Write};
use std::sync::atomic::Ordering;

/// A plaintext transport that runs the NTF handshake, so the test can drive the
/// client API without TLS.
struct PlainTransport {
    stream: std::net::TcpStream,
}

impl PlainTransport {
    fn connect(addr: std::net::SocketAddr) -> Self {
        let stream = std::net::TcpStream::connect(addr).expect("connect");
        stream.set_read_timeout(Some(std::time::Duration::from_secs(10))).unwrap();
        stream.set_write_timeout(Some(std::time::Duration::from_secs(10))).unwrap();
        PlainTransport { stream }
    }
}

impl Read for PlainTransport {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.stream.read(buf)
    }
}

impl Write for PlainTransport {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.stream.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.stream.flush()
    }
}

/// Start a local NTF server and return a connected client plus the server handles.
fn start_server_and_client() -> (NtfClient<PlainTransport>, std::sync::Arc<std::sync::Mutex<smp_rs::ntf_server::NtfState>>, std::sync::Arc<std::sync::atomic::AtomicBool>, std::thread::JoinHandle<()>) {
    let engine = NtfEngine::bind_plain("127.0.0.1:0").expect("bind");
    let (addr, state, shutdown, handle) = spawn_engine(engine);

    // The client API expects a pinned CA; the plaintext transport has no TLS, so
    // we use the same fingerprint on both sides (the pin check is exercised
    // separately in tests/ntf_client_e2e.rs).
    let ca = [0x42u8; 64];
    let fp = key_hash_from_ca_der(&ca);
    let transport = PlainTransport::connect(addr);
    let client = NtfClient::connect(transport, &ca, fp).expect("ntf connect");
    (client, state, shutdown, handle)
}

#[test]
fn ntf_server_tnew_snew_full_cycle() {
    let (mut client, state, shutdown, handle) = start_server_and_client();

    // --- PING works (already covered elsewhere, kept as a sanity check) ---
    let pong = client.ping().expect("ping");
    assert_eq!(pong.tag, NtfResponseTag::Pong);

    // --- TNEW: register a device token ---
    let kp = ed25519_keypair();
    let verify_key = spki_ed25519(&kp.verifying.to_bytes());
    let dh_pub_key = spki_x25519(&[0x33u8; 32]);
    let device_token = vec![0xAAu8; 32];

    let (token_id, server_dh) = client
        .new_token(&device_token, &verify_key, &dh_pub_key, &kp.signing)
        .expect("TNEW");
    assert_eq!(token_id.len(), 16, "server assigns a 16-byte token id");
    assert_eq!(server_dh.len(), 44, "server returns the X25519 SPKI DER");
    assert_eq!(state.lock().unwrap().token_count(), 1);

    // --- SNEW: create a subscription under that token ---
    let sub_kp = ed25519_keypair();
    let notifier_key = spki_ed25519(&sub_kp.verifying.to_bytes());
    let smp_server = vec![0x5Au8; 4];
    let notifier_id = vec![0xEFu8; 16];

    // The subscription is authorized by the TOKEN's verify key (Haskell
    // Notifications/Server.hs:839), not by the notifier key.
    let sub_id = client
        .new_subscription(&token_id, &smp_server, &notifier_id, &notifier_key, &kp.signing)
        .expect("SNEW");
    assert_eq!(sub_id.len(), 16, "server assigns a 16-byte subscription id");
    assert_eq!(state.lock().unwrap().subscription_count(), 1);

    // The notifier key was recorded.
    {
        let st = state.lock().unwrap();
        let sub = st.subscriptions.get(&sub_id).expect("subscription recorded");
        assert_eq!(sub.token_id, token_id);
        assert_eq!(sub.notifier_id, notifier_id);
        assert_eq!(sub.notifier_key, sub_kp.verifying.to_bytes());
    }

    shutdown.store(true, Ordering::SeqCst);
    handle.join().ok();
}

#[test]
fn ntf_server_rejects_tnew_with_bad_signature() {
    let (mut client, state, shutdown, handle) = start_server_and_client();

    // Sign with a DIFFERENT key than the verify key advertised in the command.
    let signer = ed25519_keypair();
    let other = ed25519_keypair();
    let verify_key = spki_ed25519(&other.verifying.to_bytes());
    let dh_pub_key = spki_x25519(&[0x33u8; 32]);
    let device_token = vec![0xAAu8; 32];

    let err = client
        .new_token(&device_token, &verify_key, &dh_pub_key, &signer.signing)
        .expect_err("must reject a TNEW signed by the wrong key");
    assert!(err.contains("TNEW failed"), "unexpected error: {err}");
    assert_eq!(state.lock().unwrap().token_count(), 0, "no token must be registered");

    shutdown.store(true, Ordering::SeqCst);
    handle.join().ok();
}

#[test]
fn ntf_server_rejects_snew_with_unknown_token() {
    let (mut client, state, shutdown, handle) = start_server_and_client();

    let kp = ed25519_keypair();
    let notifier_key = spki_ed25519(&kp.verifying.to_bytes());
    let unknown_token = vec![0x77u8; 16];

    let err = client
        .new_subscription(&unknown_token, &[0x5Au8; 4], &[0xEFu8; 16], &notifier_key, &kp.signing)
        .expect_err("must reject SNEW for an unknown token");
    assert!(err.contains("SNEW failed"), "unexpected error: {err}");
    assert_eq!(state.lock().unwrap().subscription_count(), 0);

    shutdown.store(true, Ordering::SeqCst);
    handle.join().ok();
}
