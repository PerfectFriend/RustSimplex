//! P0-2 (audited 2026-11-23): the server must FAIL CLOSED when the store file exists
//! but cannot be loaded — never start with an empty state and overwrite it.
//!
//! Acceptance criterion from the audit:
//!   "a corrupted / wrong-key-encrypted file is not overwritten; the process exits
//!    with an error".

use smp_rs::server::{Engine, ServerState};
use smp_rs::store;

fn tmp_path(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join("smp-rs-p0-store");
    std::fs::create_dir_all(&d).unwrap();
    d.join(name)
}

#[test]
fn unreadable_store_is_never_overwritten() {
    let path = tmp_path("unreadable.store");
    let _ = std::fs::remove_file(&path);
    let key = [0x5Au8; 32];
    let other = [0xA5u8; 32];

    // a valid store, encrypted with `key`
    store::save_with_key(&path, &ServerState::new(), Some(key)).unwrap();
    let good = std::fs::read(&path).unwrap();
    assert!(!good.is_empty());

    // 1) the wrong key must fail closed, and must not touch the file
    std::env::set_var("SMP_STORE_KEY", hex(&other));
    let err = match store::load_checked(&path) {
        Ok(_) => panic!("wrong key must fail closed"),
        Err(e) => e,
    };
    assert!(err.contains("cannot be loaded"), "unexpected error: {err}");
    assert_eq!(std::fs::read(&path).unwrap(), good, "store must stay byte-identical");

    // 2) the engine must refuse to start on that store
    let res = Engine::bind_plain_store("127.0.0.1:0", Some(path.clone()));
    assert!(res.is_err(), "the server must not start on an unreadable store");
    assert_eq!(std::fs::read(&path).unwrap(), good, "store must stay byte-identical");

    // 3) the right key loads it
    std::env::set_var("SMP_STORE_KEY", hex(&key));
    assert!(store::load_checked(&path).unwrap().is_some(), "the correct key must load");

    // 4) a corrupt file also fails closed
    std::fs::write(&path, b"this is not a store").unwrap();
    assert!(store::load_checked(&path).is_err(), "a corrupt store must fail closed");
    let res = Engine::bind_plain_store("127.0.0.1:0", Some(path.clone()));
    assert!(res.is_err(), "the server must not start on a corrupt store");
    assert_eq!(
        std::fs::read(&path).unwrap(),
        b"this is not a store",
        "a corrupt store must not be rewritten either"
    );

    // 5) a missing file is NOT an error: it is a fresh store
    let fresh = tmp_path("fresh.store");
    let _ = std::fs::remove_file(&fresh);
    assert!(store::load_checked(&fresh).unwrap().is_none(), "a missing store is a fresh one");

    std::env::remove_var("SMP_STORE_KEY");
}

fn hex(b: &[u8; 32]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
