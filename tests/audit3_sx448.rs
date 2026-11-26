//! SX448 parity increment (ADR D1(a) follow-up): dual DH alg in the PQDR ratchet
//! (X25519 legacy / X448 stock-SimpleX) + AEAD-style `ad` binding of the header.
use smp_rs::pqdr::{
    decode_ratchet_msg, DhAlg, DhKey, DhPub, PqdrRatchet, PQDR_VERSION, PQDR_VERSION_AD,
    RatchetConfig, RotationSchedule,
};
use smp_rs::pq::kem_keypair;

fn cfg(alg: DhAlg, ad: bool) -> RatchetConfig {
    RatchetConfig {
        rotation: RotationSchedule::Manual,
        max_skip: 100,
        dh_alg: alg,
        aead_ad: ad,
    }
}

fn pair(alg: DhAlg, ad: bool) -> (PqdrRatchet, PqdrRatchet) {
    let sk = [7u8; 32];
    let bob_dh = DhKey::gen(alg);
    let bob_kem = kem_keypair();
    let bob = PqdrRatchet::init_receiver_with_config(
        &sk, b"link-ad".to_vec(), bob_dh.clone(), bob_kem.clone(), vec![],
        cfg(alg, ad),
    );
    let alice = PqdrRatchet::init_sender_with_config(
        &sk, b"link-ad".to_vec(), bob_dh.public(), bob_kem.ek.as_ref().to_vec(),
        cfg(alg, ad),
    ).unwrap();
    (alice, bob)
}

#[test]
fn x448_ratchet_roundtrip() {
    let (mut a, mut b) = pair(DhAlg::X448, false);
    for i in 0..5u32 {
        let w = a.encrypt(format!("x448 msg {i}").as_bytes()).unwrap();
        // header carries an X448 SPKI (56-byte raw key)
        let m = decode_ratchet_msg(&w).unwrap();
        assert!(smp_rs::x448::parse_spki_x448(&m.header.dh_pub_spki).is_some());
        assert_eq!(m.header.max_version, PQDR_VERSION);
        assert_eq!(b.decrypt(&w).unwrap(), format!("x448 msg {i}").as_bytes());
    }
    // and back
    let w = b.encrypt(b"reply").unwrap();
    assert_eq!(a.decrypt(&w).unwrap(), b"reply");
}

#[test]
fn x25519_ratchet_still_legacy_wire() {
    let (mut a, mut b) = pair(DhAlg::X25519, false);
    let w = a.encrypt(b"hi").unwrap();
    let m = decode_ratchet_msg(&w).unwrap();
    assert_eq!(m.header.max_version, PQDR_VERSION);
    assert!(smp_rs::x448::parse_spki_x448(&m.header.dh_pub_spki).is_none());
    assert_eq!(b.decrypt(&w).unwrap(), b"hi");
}

#[test]
fn cross_alg_rejected() {
    let (mut a, mut b) = pair(DhAlg::X448, false);
    let w = a.encrypt(b"x").unwrap();
    // a X25519-only receiver must refuse an X448 header
    let sk = [7u8; 32];
    let bob_dh = DhKey::gen(DhAlg::X25519);
    let bob_kem = kem_keypair();
    let mut b25 = PqdrRatchet::init_receiver_with_config(
        &sk, vec![], bob_dh, bob_kem, vec![], cfg(DhAlg::X25519, false),
    );
    let _ = &mut b;
    assert!(b25.decrypt(&w).is_err());
}

#[test]
fn aead_ad_binds_header_and_roundtrips() {
    let (mut a, mut b) = pair(DhAlg::X25519, true);
    let w = a.encrypt(b"ad-bound").unwrap();
    let m = decode_ratchet_msg(&w).unwrap();
    assert_eq!(m.header.max_version, PQDR_VERSION_AD, "AD frames must bump the wire version");
    assert_eq!(b.decrypt(&w).unwrap(), b"ad-bound");
    // tamper with the header (ns) — AD binding must break AUTH
    let mut w2 = w.clone();
    let mut m2 = decode_ratchet_msg(&w2).unwrap();
    m2.header.ns = m2.header.ns.wrapping_add(1);
    w2 = smp_rs::pqdr::encode_ratchet_msg(&m2);
    assert!(b.decrypt(&w2).is_err(), "tampered header must fail with AD binding");
}

#[test]
fn snapshot_v2_roundtrip_x448() {
    let (mut a, mut b) = pair(DhAlg::X448, true);
    let w1 = a.encrypt(b"one").unwrap();
    assert_eq!(b.decrypt(&w1).unwrap(), b"one");
    let snap = b.snapshot();
    let mut b2 = PqdrRatchet::restore(&snap).unwrap();
    assert_eq!(b2.dh_alg, DhAlg::X448);
    let w2 = a.encrypt(b"two").unwrap();
    assert_eq!(b2.decrypt(&w2).unwrap(), b"two");
}

#[test]
fn low_order_x448_pub_rejected() {
    let sk = [7u8; 32];
    let alice = PqdrRatchet::init_sender_with_config(
        &sk, vec![], DhPub::X448([0u8; 56]), kem_keypair().ek.as_ref().to_vec(),
        cfg(DhAlg::X448, false),
    );
    assert!(alice.is_err(), "low-order X448 peer key must be rejected (U-07)");
}

#[test]
fn smp_version_negotiation_min_of_max() {
    use smp_rs::transport::negotiate_version;
    // overlap -> min(client_max, server_max) (plan item 15)
    assert_eq!(negotiate_version(15, 23, 17, 23), Some(23));
    assert_eq!(negotiate_version(15, 20, 17, 23), Some(20));
    assert_eq!(negotiate_version(20, 23, 17, 19), None, "no overlap -> fail-closed");
}
