//! PQDR E2E ratchet smoke: two parties init from a shared SK and exchange
//! 20 messages alternating directions; every decrypt must match the plaintext.
use smp_rs::crypto::{x25519_keypair, x25519_public};
use smp_rs::pq::kem_keypair;
use smp_rs::pqdr::{PqdrRatchet, PQDR_VERSION};

#[test]
fn pqdr_e2e_twenty_messages_both_directions() {
    let sk = [7u8; 32]; // in production: X3DH-derived SK
    let ad = b"simplex-rs-e2e-test".to_vec();

    // Bob (receiver) publishes DH + KEM keys in the connection request.
    let dh_b = x25519_keypair();
    let kem_b = kem_keypair();
    let dh_b_raw = dh_b.public.to_bytes();
    let kem_b_pk = kem_b.ek.as_ref().to_vec();

    // Alice (sender) encapsulates to Bob's keys.
    let mut alice = PqdrRatchet::init_sender(&sk, ad.clone(), x25519_public(dh_b_raw), kem_b_pk).unwrap();
    let mut bob = PqdrRatchet::init_receiver(&sk, ad, dh_b, kem_b, Vec::new());
    assert_eq!(PQDR_VERSION, 3);

    for i in 0..20 {
        let msg = format!("hello {i}").into_bytes();
        if i % 2 == 0 {
            let wire = alice.encrypt(&msg).unwrap();
            let pt = bob.decrypt(&wire).expect("bob decrypt");
            assert_eq!(pt, msg, "round {i}");
        } else {
            let wire = bob.encrypt(&msg).unwrap();
            let pt = alice.decrypt(&wire).expect("alice decrypt");
            assert_eq!(pt, msg, "round {i}");
        }
    }
}

#[test]
fn pqdr_snapshot_restore_continues_chain() {
    let sk = [3u8; 32];
    let ad = b"snap".to_vec();
    let dh_b = smp_rs::crypto::x25519_keypair();
    let kem_b = smp_rs::pq::kem_keypair();
    let mut alice = PqdrRatchet::init_sender(&sk, ad.clone(), smp_rs::crypto::x25519_public(dh_b.public.to_bytes()), kem_b.ek.as_ref().to_vec()).unwrap();
    let mut bob = PqdrRatchet::init_receiver(&sk, ad, dh_b, kem_b, Vec::new());
    for i in 0..5 {
        let m = format!("pre{i}").into_bytes();
        let w = if i % 2 == 0 { alice.encrypt(&m).unwrap() } else { bob.encrypt(&m).unwrap() };
        let _ = if i % 2 == 0 { bob.decrypt(&w).unwrap() } else { alice.decrypt(&w).unwrap() };
    }
    let mut alice2 = PqdrRatchet::restore(&alice.snapshot()).unwrap();
    let mut bob2 = PqdrRatchet::restore(&bob.snapshot()).unwrap();
    for i in 5..10 {
        let m = format!("post{i}").into_bytes();
        if i % 2 == 0 {
            let w = alice2.encrypt(&m).unwrap();
            assert_eq!(bob2.decrypt(&w).unwrap(), m);
        } else {
            let w = bob2.encrypt(&m).unwrap();
            assert_eq!(alice2.decrypt(&w).unwrap(), m);
        }
    }
}
