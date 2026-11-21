//! Task 6.5: store format versions, migrations and rollback.
//!
//! v1 — the snapshot payload with no header (the original format).
//! v2 — magic + version + payload length + checksum + the same payload.
//!
//! A migration must never damage the store: the new payload is built and
//! validated before anything on disk is touched, the previous bytes are kept
//! as `<store>.v1.bak`, and the replacement is an atomic write.

use std::path::{Path, PathBuf};

use smp_rs::server::{Queue, ServerState};
use smp_rs::store;

fn scratch_store(name: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let p = std::env::temp_dir().join(format!("{name}-{}-{nanos}", std::process::id()));
    let _ = std::fs::remove_file(&p);
    p
}

/// A queue that survives a snapshot round trip.
fn test_queue(rcv_id: Vec<u8>) -> Queue {
    Queue {
        snd_id: rcv_id.clone(),
        rcv_auth_raw: [0u8; 32],
        rcv_auth_x: false,
        snd_auth: None,
        rcv_dh_secret: [0u8; 32],
        messages: std::collections::VecDeque::new(),
        subscriber: None,
        ntf_id: None,
        ntf_auth_raw: None,
        rcv_ntf_dh_secret: None,
        ntf_subscriber: None,
        rcv_id,
    }
}

/// Writes a store in the legacy (v1) format and returns its bytes.
fn write_legacy(path: &Path, st: &ServerState) -> Vec<u8> {
    let bytes = store::snapshot_bytes(st);
    std::fs::write(path, &bytes).expect("write legacy store");
    bytes
}

#[test]
fn a_legacy_store_loads_and_upgrades_to_the_current_format() {
    let path = scratch_store("legacy-upgrade");
    let mut st = ServerState::default();
    st.by_rcv.insert(b"rcv-1".to_vec(), test_queue(b"rcv-1".to_vec()));
    let legacy = write_legacy(&path, &st);

    // it loads as it is
    let loaded = store::load(&path).expect("the legacy store loads");
    assert_eq!(loaded.by_rcv.len(), 1, "the legacy queues are readable");
    assert_eq!(store::store_version(&path), Some(1));

    match store::migrate_store(&path, None).expect("migrate") {
        store::Migration::Upgraded { from, to, backup } => {
            assert_eq!(from, 1);
            assert_eq!(to, store::CURRENT_STORE_VERSION);
            assert!(backup.exists(), "the previous bytes are kept as a backup");
            assert_eq!(std::fs::read(&backup).expect("read backup"), legacy);
        }
        other => panic!("unexpected migration result: {other:?}"),
    }

    assert_eq!(store::store_version(&path), Some(store::CURRENT_STORE_VERSION));
    let loaded = store::load(&path).expect("the migrated store loads");
    assert_eq!(loaded.by_rcv.len(), 1, "the queues survived the migration");

    // migrating again changes nothing
    assert_eq!(
        store::migrate_store(&path, None).expect("migrate again"),
        store::Migration::UpToDate
    );
}

#[test]
fn a_failed_migration_leaves_the_store_untouched() {
    let path = scratch_store("broken-migration");
    let mut bytes = write_legacy(&path, &ServerState::default());
    // a queue count that cannot be read
    bytes[0..4].copy_from_slice(&u32::MAX.to_le_bytes());
    std::fs::write(&path, &bytes).expect("write broken store");

    let err = store::migrate_store(&path, None).expect_err("a broken store must not migrate");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    assert_eq!(
        std::fs::read(&path).expect("read store"),
        bytes,
        "a failed migration must leave the store exactly as it was"
    );
}

#[test]
fn a_store_from_the_future_is_refused() {
    let path = scratch_store("future-store");
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"SMPSTORE");
    bytes.extend_from_slice(&99u32.to_le_bytes());
    bytes.extend_from_slice(&0u64.to_le_bytes());
    bytes.extend_from_slice(&0u64.to_le_bytes());
    std::fs::write(&path, &bytes).expect("write future store");

    assert!(
        store::load(&path).is_none(),
        "a store written by a newer version must not be loaded"
    );
    let err = store::migrate_store(&path, None).expect_err("a future store must not migrate");
    assert!(
        err.to_string().contains("newer"),
        "the error must say why: {err}"
    );
    assert_eq!(std::fs::read(&path).expect("read store"), bytes);
}

#[test]
fn a_corrupted_store_is_rejected_by_the_checksum() {
    let path = scratch_store("corrupt-store");
    let mut st = ServerState::default();
    st.by_rcv.insert(b"rcv-1".to_vec(), test_queue(b"rcv-1".to_vec()));
    store::save(&path, &st).expect("save");

    let mut bytes = std::fs::read(&path).expect("read store");
    // corrupt a byte of the queue's auth key: the legacy parser would have
    // accepted this silently, the checksum must not
    let at = bytes.len() - 8;
    bytes[at] ^= 0xff;
    std::fs::write(&path, &bytes).expect("write corrupt store");

    assert!(
        store::load(&path).is_none(),
        "a corrupted store must be rejected"
    );
}

#[test]
fn the_backup_restores_the_legacy_store() {
    let path = scratch_store("rollback");
    let legacy = write_legacy(&path, &ServerState::default());
    let backup = match store::migrate_store(&path, None).expect("migrate") {
        store::Migration::Upgraded { backup, .. } => backup,
        other => panic!("unexpected migration result: {other:?}"),
    };

    // roll back by hand
    std::fs::copy(&backup, &path).expect("restore");
    assert_eq!(std::fs::read(&path).expect("read store"), legacy);
    assert_eq!(store::store_version(&path), Some(1));
    assert!(store::load(&path).is_some(), "the restored store loads");
}
