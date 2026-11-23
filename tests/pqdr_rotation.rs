//! W6-Task 6.2: key rotation schedule + a testable reorder window.
//!
//! Two things are pinned here:
//!
//! 1. the rotation schedule — a long-lived session must rotate its DH+KEM
//!    keys on a schedule instead of relying on the caller to remember;
//! 2. the reorder window — how many messages of a chain may arrive out of
//!    order. The window was a hard-coded constant, so it could not be tested
//!    at a sane scale; it is now per-ratchet, with the production default
//!    unchanged.
//!
//! WHERE a rotation may happen is the subtle part, and the tests below pin it:
//! a proactive rotation must be built on the peer's CURRENT root, and the
//! peer only moves to a new root when it sees a new DH key from us. So the
//! one safe point is right after we mirrored the peer's ratchet step (the
//! "mirror point"). A rotation built on a stale root derives a key the peer
//! cannot reproduce — that was a real defect in `rotate()`, found here and
//! now refused loudly.
//!
//! The in-flight invariant: a message encrypted BEFORE a rotation must still
//! be decryptable AFTER it. The rotation carries the old chain's length (pn),
//! so the receiver derives the old chain's skipped keys and can decrypt late
//! messages — as long as they are inside the reorder window.

use smp_rs::crypto::*;
use smp_rs::pq::kem_keypair;
use smp_rs::pqdr::*;

/// (alice, bob) with an explicit config on both sides.
fn pair_with(sk: &[u8; 32], ad: &[u8], cfg: RatchetConfig) -> (PqdrRatchet, PqdrRatchet) {
    let bob_dh = x25519_keypair();
    let bob_kem = kem_keypair();
    let alice = PqdrRatchet::init_sender_with_config(
        sk,
        ad.to_vec(),
        bob_dh.public,
        bob_kem.ek.as_ref().to_vec(),
        cfg,
    )
    .unwrap();
    let bob = PqdrRatchet::init_receiver_with_config(
        sk,
        ad.to_vec(),
        bob_dh.clone(),
        bob_kem,
        alice.kem_s.ek.as_ref().to_vec(),
        cfg,
    );
    (alice, bob)
}

fn dh_pub_of(wire: &[u8]) -> Vec<u8> {
    decode_ratchet_msg(wire).expect("decode").header.dh_pub_spki
}

/// Alice sends, Bob answers, Alice receives: the receipt is the mirror point,
/// the only place where a proactive rotation is consistent.
fn exchange(alice: &mut PqdrRatchet, bob: &mut PqdrRatchet, tag: &str) {
    let m = format!("{tag}-a").into_bytes();
    let w = alice.encrypt(&m).unwrap();
    assert_eq!(bob.decrypt(&w).expect("bob decrypt"), m, "{tag}");
    let m = format!("{tag}-b").into_bytes();
    let w = bob.encrypt(&m).unwrap();
    assert_eq!(alice.decrypt(&w).expect("alice decrypt"), m, "{tag}");
}

#[test]
fn the_default_schedule_is_a_message_count() {
    let cfg = RatchetConfig::default();
    assert_eq!(
        cfg.rotation,
        RotationSchedule::EveryMessages(DEFAULT_ROTATE_EVERY)
    );
    assert_eq!(cfg.max_skip, MAX_SKIP, "the production window must not change");
}

#[test]
fn manual_schedule_never_rotates_on_its_own() {
    let cfg = RatchetConfig {
        rotation: RotationSchedule::Manual,
        max_skip: MAX_SKIP,
    };
    let (mut a, mut b) = pair_with(&[1u8; 32], b"manual", cfg);
    exchange(&mut a, &mut b, "warmup");
    let first = dh_pub_of(&a.encrypt(b"m0").unwrap());
    for i in 0..20 {
        let w = a.encrypt(format!("m{i}").as_bytes()).unwrap();
        assert_eq!(b.decrypt(&w).expect("decrypt"), format!("m{i}").as_bytes());
    }
    let last = dh_pub_of(&a.encrypt(b"last").unwrap());
    assert_eq!(first, last, "a manual schedule must not rotate the DH key");
    assert_eq!(a.rotation_schedule(), RotationSchedule::Manual);
}

#[test]
fn the_schedule_rotates_the_dh_key_after_n_messages() {
    let cfg = RatchetConfig {
        rotation: RotationSchedule::EveryMessages(2),
        max_skip: MAX_SKIP,
    };
    let (mut a, mut b) = pair_with(&[2u8; 32], b"rotate", cfg);
    exchange(&mut a, &mut b, "warmup");

    // two messages in the current epoch — still the old DH key
    let mut pubs = Vec::new();
    for i in 0..2 {
        let m = format!("pre{i}").into_bytes();
        let w = a.encrypt(&m).unwrap();
        pubs.push(dh_pub_of(&w));
        assert_eq!(b.decrypt(&w).expect("decrypt"), m, "pre{i}");
    }
    assert!(pubs.windows(2).all(|w| w[0] == w[1]), "no rotation yet");

    // bob answers -> alice mirrors his step -> the schedule fires there
    let m = b"reply".to_vec();
    let w = b.encrypt(&m).unwrap();
    assert_eq!(a.decrypt(&w).expect("alice"), m);

    let m = b"after".to_vec();
    let w = a.encrypt(&m).unwrap();
    assert_ne!(dh_pub_of(&w), pubs[0], "the schedule must rotate the DH key");
    assert_eq!(b.decrypt(&w).expect("decrypt after rotation"), m);
}

#[test]
fn a_reorder_window_gap_inside_is_accepted_and_beyond_is_refused() {
    let window = 4u32;
    let cfg = RatchetConfig {
        rotation: RotationSchedule::Manual,
        max_skip: window,
    };
    let (mut a, mut b) = pair_with(&[3u8; 32], b"window", cfg);
    assert_eq!(b.max_skip(), window);

    let wires: Vec<Vec<u8>> = (0..8).map(|i| a.encrypt(format!("m{i}").as_bytes()).unwrap()).collect();

    // a gap of exactly `window` messages is inside the window
    assert_eq!(b.decrypt(&wires[0]).expect("first"), b"m0");
    let pt = b
        .decrypt(&wires[window as usize])
        .expect("a gap inside the window must be accepted");
    assert_eq!(pt, format!("m{window}").as_bytes());

    // a gap beyond the window is refused with a clear error (fresh receiver:
    // the previous one already consumed part of the chain)
    let (mut a2, mut b2) = pair_with(&[3u8; 32], b"window2", cfg);
    let wires2: Vec<Vec<u8>> = (0..8).map(|i| a2.encrypt(format!("m{i}").as_bytes()).unwrap()).collect();
    assert_eq!(b2.decrypt(&wires2[0]).expect("first"), b"m0");
    let err = b2
        .decrypt(&wires2[7])
        .expect_err("a gap beyond the window must fail");
    assert!(
        err.contains("too many skipped messages"),
        "unexpected error: {err}"
    );
}

#[test]
fn a_message_encrypted_before_a_rotation_still_decrypts_after_it() {
    // The in-flight invariant.
    let cfg = RatchetConfig {
        rotation: RotationSchedule::EveryMessages(2),
        max_skip: 8,
    };
    let (mut a, mut b) = pair_with(&[4u8; 32], b"inflight", cfg);
    exchange(&mut a, &mut b, "warmup");

    // "keep" is delivered (it makes bob ratchet, so alice gets a fresh peer
    // root); "late" stays in flight
    let keep = a.encrypt(b"keep").unwrap();
    assert_eq!(b.decrypt(&keep).expect("keep"), b"keep");
    let late = a.encrypt(b"late").unwrap();

    // bob answers -> alice mirrors -> the schedule rotates
    let w = b.encrypt(b"trigger").unwrap();
    assert_eq!(a.decrypt(&w).expect("alice"), b"trigger");

    let fresh = a.encrypt(b"fresh").unwrap();
    assert_ne!(
        dh_pub_of(&late),
        dh_pub_of(&fresh),
        "the rotation must have happened"
    );

    // the NEW chain arrives first, the OLD message arrives late
    assert_eq!(b.decrypt(&fresh).expect("new chain"), b"fresh");
    assert_eq!(
        b.decrypt(&late).expect("late message from the old chain"),
        b"late",
        "a message encrypted before the rotation must survive it"
    );
}

#[test]
fn a_rotation_on_a_stale_peer_root_is_refused() {
    // The defect this task found: the peer's root moves on as soon as it sees
    // a new DH key from us, so a rotation built on the old copy of it derives
    // a key the peer cannot reproduce. `rotate()` must refuse instead of
    // silently corrupting the chain.
    let cfg = RatchetConfig {
        rotation: RotationSchedule::Manual,
        max_skip: MAX_SKIP,
    };
    let (mut a, mut b) = pair_with(&[8u8; 32], b"stale", cfg);
    exchange(&mut a, &mut b, "warmup");
    // alice sends a message carrying a new DH key -> bob ratchets -> alice's
    // copy of bob's root is stale from now on
    let w = a.encrypt(b"trigger").unwrap();
    assert_eq!(b.decrypt(&w).expect("bob"), b"trigger");
    let err = a.rotate().expect_err("a stale peer root must be refused");
    assert!(err.contains("fresh peer root"), "unexpected error: {err}");
    // the refusal is harmless: the conversation continues
    let w = b.encrypt(b"reply").unwrap();
    assert_eq!(a.decrypt(&w).expect("alice"), b"reply");
    let w = a.encrypt(b"next").unwrap();
    assert_eq!(b.decrypt(&w).expect("bob"), b"next");
}

#[test]
fn the_global_skipped_key_cap_still_prunes() {
    let cfg = RatchetConfig {
        rotation: RotationSchedule::Manual,
        max_skip: 5000,
    };
    let (mut a, mut b) = pair_with(&[5u8; 32], b"prune", cfg);
    let total = MAX_SKIPPED_TOTAL + 100;
    let wires: Vec<Vec<u8>> = (0..total).map(|i| a.encrypt(format!("m{i}").as_bytes()).unwrap()).collect();
    assert_eq!(b.decrypt(&wires[0]).expect("first"), b"m0");
    assert_eq!(
        b.decrypt(&wires[total - 1]).expect("last"),
        format!("m{}", total - 1).as_bytes()
    );
    assert!(
        b.skipped_key_count() <= MAX_SKIPPED_TOTAL,
        "the global cap must prune: {} > {MAX_SKIPPED_TOTAL}",
        b.skipped_key_count()
    );
}

#[test]
fn the_policy_survives_a_snapshot_roundtrip() {
    let cfg = RatchetConfig {
        rotation: RotationSchedule::EveryMessages(7),
        max_skip: 42,
    };
    let (mut a, mut b) = pair_with(&[6u8; 32], b"persist", cfg);
    exchange(&mut a, &mut b, "warmup");
    a.set_rotation_schedule(RotationSchedule::EveryMessages(9));
    a.set_max_skip(11);

    let restored = PqdrRatchet::restore(&a.snapshot()).expect("restore");
    assert_eq!(
        restored.rotation_schedule(),
        RotationSchedule::EveryMessages(9)
    );
    assert_eq!(restored.max_skip(), 11);
    assert_eq!(restored.max_skip(), a.max_skip());
}
