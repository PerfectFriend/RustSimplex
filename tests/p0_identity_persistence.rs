//! Sprint "store + identity" (audit P0-4 / P1-5, 2026-11-23).
//!
//! Acceptance criteria from the audit:
//!   P0-4 "restart of the server keeps the keyHash, the client reconnects without
//!         changing the pin"  ->  tests: engine_restart_preserves_key_hash,
//!                               init_router_store_is_stable
//!   P1-5 "refuse persistence without a key (or require --insecure-plain-store)"
//!                             ->  tests: store_without_key_is_refused,
//!                               key_file_beats_env_var

use smp_rs::identity::{RouterIdentity, StoredIdentity};
use smp_rs::server::{Engine, ServerState, StoreOpts};
use smp_rs::store::{self, StoreKey};

fn tmp(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join("smp-rs-p0-identity");
    std::fs::create_dir_all(&d).unwrap();
    let p = d.join(name);
    let _ = std::fs::remove_file(&p);
    p
}

#[test]
fn stored_identity_recomputes_key_hash_from_the_cert() {
    let id = RouterIdentity::generate("localhost").unwrap();
    let sid = StoredIdentity::from_router(&id);
    let back = sid.to_router().unwrap();
    assert_eq!(back.key_hash, id.key_hash, "keyHash must come back unchanged");
    // the hash is NOT stored: a tampered cert DER yields a different address
    let mut bad = sid.clone();
    bad.offline_der[0] ^= 0xFF;
    assert_ne!(bad.to_router().unwrap().key_hash, id.key_hash);
}

#[test]
fn identity_survives_an_encrypted_store_roundtrip() {
    let p = tmp("identity.store");
    let key = [0x11u8; 32];
    let mut st = ServerState::new();
    let id = RouterIdentity::generate("localhost").unwrap();
    st.identity = Some(StoredIdentity::from_router(&id));
    store::save_with_key(&p, &st, Some(key)).unwrap();
    let loaded = store::load_with_key(&p, Some(key)).unwrap();
    let sid = loaded.identity.expect("the identity must be persisted");
    assert_eq!(sid.to_router().unwrap().key_hash, id.key_hash, "P0-4: keyHash survives the store");
    // and the ephemeral server key too (onion hops)
    assert_eq!(loaded.eph_secret, st.eph_secret);
}

#[test]
fn engine_restart_preserves_key_hash() {
    let p = tmp("engine-identity.store");
    let key = [0x22u8; 32];
    let opts = || StoreOpts { key: Some(StoreKey::from_bytes(key)), allow_plain_store: false };
    let kh1 = Engine::bind_tls_store_opts("127.0.0.1:0", "localhost", Some(p.clone()), opts())
        .unwrap()
        .key_hash()
        .unwrap();
    assert!(p.exists(), "the identity must be persisted at bind time");
    let kh2 = Engine::bind_tls_store_opts("127.0.0.1:0", "localhost", Some(p.clone()), opts())
        .unwrap()
        .key_hash()
        .unwrap();
    assert_eq!(kh1, kh2, "P0-4: the smp:// keyHash must survive a restart");
}

#[test]
fn init_router_store_is_stable_across_runs() {
    let p = tmp("init.store");
    let opts = || StoreOpts { key: Some(StoreKey::from_bytes([0x33u8; 32])), allow_plain_store: false };
    let a1 = smp_rs::server::init_router_store("127.0.0.1:5223", "localhost", &p, opts()).unwrap();
    let a2 = smp_rs::server::init_router_store("127.0.0.1:5223", "localhost", &p, opts()).unwrap();
    assert_eq!(a1, a2, "init must return the same address on every run");
    assert!(a1.starts_with("smp://") && a1.contains("localhost:5223"), "unexpected address {a1}");
}

#[test]
fn store_without_key_is_refused_unless_opted_in() {
    let p = tmp("plain-refused.store");
    let res = Engine::bind_plain_store_opts("127.0.0.1:0", Some(p.clone()), StoreOpts { key: None, allow_plain_store: false });
    let err = match res {
        Ok(_) => panic!("a store without an encryption key must be refused (P1-5)"),
        Err(e) => e.to_string(),
    };
    assert!(err.contains("encryption key"), "unexpected error: {err}");
    assert!(!p.exists(), "no store file may be written");
    // the explicit opt-in still works
    let _e = Engine::bind_plain_store_opts("127.0.0.1:0", Some(p.clone()), StoreOpts::plain()).unwrap();
}

#[test]
fn key_file_beats_env_var() {
    let d = std::env::temp_dir().join("smp-rs-p0-identity");
    std::fs::create_dir_all(&d).unwrap();
    let kf = d.join("store.key");
    let file_key = [0x44u8; 32];
    std::fs::write(&kf, file_key.iter().map(|b| format!("{b:02x}")).collect::<String>()).unwrap();
    std::env::set_var("SMP_STORE_KEY_FILE", &kf);
    std::env::set_var("SMP_STORE_KEY", [0x55u8; 32].iter().map(|b| format!("{b:02x}")).collect::<String>());
    let k = store::store_key_from_env().unwrap().expect("a key must be configured");
    assert_eq!(k.as_bytes(), &file_key, "SMP_STORE_KEY_FILE must take precedence");
    std::env::remove_var("SMP_STORE_KEY_FILE");
    std::env::remove_var("SMP_STORE_KEY");
}
