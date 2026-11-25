//! Audit #3 regression tests:
//! U-06/H5 — `update_store` must FAIL CLOSED on an existing-but-undecryptable store
//! (wrong key) and leave the file byte-identical (pre-fix: silent reset + overwrite).
//! U-07/F-04 — `x25519_dh_checked` must reject a small-order (all-zero) peer public key.
use smp_rs::crypto::{x25519_dh_checked, x25519_keypair, XPublic};
use smp_rs::server::ServerState;
use smp_rs::store::{load_checked_with_key, save_with_key, update_store};

fn tmpdir(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("smp-audit3-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn u06_update_store_wrong_key_is_error_and_file_untouched() {
    let d = tmpdir("u06");
    let p = d.join("store.bin");
    let k1 = [1u8; 32];
    let k2 = [2u8; 32];
    save_with_key(&p, &ServerState::new(), Some(k1)).unwrap();
    let before = std::fs::read(&p).unwrap();
    // wrong key must be a hard error, not a silent empty-state overwrite
    let r = update_store(&p, Some(k2), |_st| {});
    assert!(r.is_err(), "update_store with wrong key must fail (fail-closed), got Ok");
    let after = std::fs::read(&p).unwrap();
    assert_eq!(before, after, "store file must be byte-identical after a failed update");
    // and the right key still works
    update_store(&p, Some(k1), |_st| {}).unwrap();
    assert!(load_checked_with_key(&p, Some(k1)).unwrap().is_some());
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn u07_x25519_dh_checked_rejects_small_order_peer_key() {
    let kp = x25519_keypair();
    let zero = XPublic::from([0u8; 32]);
    assert!(x25519_dh_checked(&kp.secret, &zero).is_err(), "all-zero peer key must be rejected");
    // low-order point 1 (little-endian): 01 00 ... 00
    let mut p1 = [0u8; 32];
    p1[0] = 1;
    assert!(x25519_dh_checked(&kp.secret, &XPublic::from(p1)).is_err());
    // a real key must pass
    let peer = x25519_keypair();
    assert!(x25519_dh_checked(&kp.secret, &peer.public).is_ok());
}
