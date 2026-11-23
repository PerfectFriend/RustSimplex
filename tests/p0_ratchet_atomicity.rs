//! P0-1 (audited 2026-11-23): the ratchet must not mutate its state before authentication.
//!
//! Acceptance criteria from the audit:
//!  - a replayed frame is rejected and the NEXT valid frame still decrypts;
//!  - a frame with a forged new DH key is rejected and leaves the state untouched;
//!  - a tampered body that claims a skipped (dh, ns) does NOT burn that skipped key;
//!  - a forged DH-ratchet step does not rotate the sender/receiver chains.

use smp_rs::crypto::*;
use smp_rs::pq::kem_keypair;
use smp_rs::pqdr::*;

/// Build an (alice, bob) pair sharing SK; alice = sender init, bob = receiver init.
fn pair(sk: &[u8; 32], ad: &[u8]) -> (PqdrRatchet, PqdrRatchet) {
    let bob_dh = x25519_keypair();
    let bob_kem = kem_keypair();
    let alice = PqdrRatchet::init_sender(
        sk,
        ad.to_vec(),
        bob_dh.public,
        bob_kem.ek.as_ref().to_vec(),
    )
    .unwrap();
    let bob = PqdrRatchet::init_receiver(
        sk,
        ad.to_vec(),
        bob_dh.clone(),
        bob_kem,
        alice.kem_s.ek.as_ref().to_vec(),
    );
    (alice, bob)
}

#[test]
fn replayed_frame_is_rejected_and_next_frame_still_decrypts() {
    let sk = [0x21u8; 32];
    let (mut a, mut b) = pair(&sk, b"ad");
    let m0 = a.encrypt(b"first").unwrap();
    assert_eq!(b.decrypt(&m0).unwrap(), b"first");
    let m1 = a.encrypt(b"second").unwrap();

    // replay of the already accepted frame
    let err = b.decrypt(&m0).unwrap_err();
    assert!(err.to_lowercase().contains("replay") || err.to_lowercase().contains("auth"),
        "expected a replay/auth error, got {err:?}");

    // the receiving chain must NOT have been advanced by the replay
    assert_eq!(b.decrypt(&m1).unwrap(), b"second", "chain survived the replay");
}

#[test]
fn forged_new_dh_key_leaves_the_state_untouched() {
    let sk = [0x22u8; 32];
    let (mut a, mut b) = pair(&sk, b"ad");
    let m0 = a.encrypt(b"hello").unwrap();
    assert_eq!(b.decrypt(&m0).unwrap(), b"hello");
    let before = b.snapshot();

    // forge a frame whose header advertises a DIFFERENT DH key
    let mut msg = decode_ratchet_msg(&m0).unwrap();
    let other = x25519_keypair();
    msg.header.dh_pub_spki = spki_x25519(&other.public.to_bytes());
    let forged = encode_ratchet_msg(&msg);

    assert!(b.decrypt(&forged).is_err(), "forged DH frame must be rejected");
    assert_eq!(b.snapshot(), before, "state must be unchanged after a forged frame");

    // and the ratchet still works afterwards
    let m1 = a.encrypt(b"after").unwrap();
    assert_eq!(b.decrypt(&m1).unwrap(), b"after");
}

#[test]
fn tampered_skipped_body_does_not_burn_the_skipped_key() {
    let sk = [0x23u8; 32];
    let (mut a, mut b) = pair(&sk, b"ad");
    let m0 = a.encrypt(b"zero").unwrap();
    let m1 = a.encrypt(b"one").unwrap();
    let m2 = a.encrypt(b"two").unwrap();

    // deliver #2 first: #0 and #1 become skipped keys
    assert_eq!(b.decrypt(&m2).unwrap(), b"two");

    // forge #0 with a tampered body but an otherwise valid header
    let mut msg = decode_ratchet_msg(&m0).unwrap();
    if msg.body.len() > 16 {
        msg.body[16] ^= 0xFF;
    }
    let forged = encode_ratchet_msg(&msg);
    assert!(b.decrypt(&forged).is_err(), "tampered body must be rejected");

    // the REAL #0 must still decrypt: the skipped key was not consumed
    assert_eq!(b.decrypt(&m0).unwrap(), b"zero", "skipped key survived the forgery");
    assert_eq!(b.decrypt(&m1).unwrap(), b"one");
}

#[test]
fn forged_frame_does_not_rotate_the_receiving_chain() {
    let sk = [0x24u8; 32];
    let (mut a, mut b) = pair(&sk, b"ad");
    let m0 = a.encrypt(b"one").unwrap();
    let m1 = a.encrypt(b"two").unwrap();
    assert_eq!(b.decrypt(&m0).unwrap(), b"one");
    let before = b.snapshot();

    // replay m0 after it was accepted: state must stay byte-identical
    assert!(b.decrypt(&m0).is_err());
    assert_eq!(b.snapshot(), before, "replay must not change the state");

    // the next genuine message still decrypts
    assert_eq!(b.decrypt(&m1).unwrap(), b"two");
}

#[test]
fn garbage_input_is_rejected_without_state_change() {
    let sk = [0x25u8; 32];
    let (_a, mut b) = pair(&sk, b"ad");
    let before = b.snapshot();
    for junk in [
        vec![],
        vec![0u8; 1],
        vec![0xFFu8; 7],
        vec![0x00u8; 64],
        b"not a ratchet message".to_vec(),
    ] {
        assert!(b.decrypt(&junk).is_err(), "garbage must be rejected");
        assert_eq!(b.snapshot(), before, "state changed on garbage input");
    }
}
