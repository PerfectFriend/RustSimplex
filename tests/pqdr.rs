//! PQDR KEM tests: SNTRUP761 round-trip, hybrid secret, kemParams wire format, kcb box.
use smp_rs::encoding::Reader;
use smp_rs::pq::*;

#[test]
fn kem_sizes_match_reference() {
    assert_eq!(KEM_PK_LEN, 1158);
    assert_eq!(KEM_SK_LEN, 1763);
    assert_eq!(KEM_CT_LEN, 1039);
    assert_eq!(KEM_SS_LEN, 32);
}

#[test]
fn kem_encaps_decaps_roundtrip() {
    let kp = kem_keypair();
    assert_eq!(kp.ek.as_ref().len(), KEM_PK_LEN);
    assert_eq!(kp.dk.as_ref().len(), KEM_SK_LEN);
    let (ct, ss1) = kem_encaps(&kp.ek);
    assert_eq!(ct.len(), KEM_CT_LEN);
    let ss2 = kem_decaps(&kp.dk, &ct).unwrap();
    assert_eq!(ss1, ss2, "decaps must recover the same shared secret");
}

#[test]
fn kem_wrong_ct_gives_wrong_key() {
    let kp = kem_keypair();
    let (mut ct, ss1) = kem_encaps(&kp.ek);
    ct[0] ^= 1;
    let ss2 = kem_decaps(&kp.dk, &ct).unwrap();
    assert_ne!(ss1, ss2, "tampered ciphertext must not yield the same key");
}

#[test]
fn kem_hybrid_secret_is_sha3_256_of_dh_then_kem() {
    let dh = [0x11u8; 32];
    let kem = [0x22u8; 32];
    let h = kem_hybrid_secret(&dh, &kem);
    // known-answer: python3 hashlib.sha3_256(b'\x11'*32 + b'\x22'*32)
    let expect = hex("127eebf5734e0a01b9b7d16b2b122bd36f617a1aae4accf9bc251e0a8903645e");
    assert_eq!(h, expect);
    // cross-check with sha3 crate directly (same algorithm, independent call path)
    use sha3::{Digest, Sha3_256};
    let mut hh = Sha3_256::new();
    hh.update([0x11u8; 32]);
    hh.update([0x22u8; 32]);
    let direct: [u8; 32] = hh.finalize().into();
    assert_eq!(h, direct);
}

#[test]
fn kem_params_wire_golden() {
    // None -> b'0'
    let mut v = Vec::new();
    encode_kem_params(&mut v, &KemParams::None).unwrap();
    assert_eq!(v, vec![b'0']);

    // Pk -> b'1' b'P' large(pk): u16 BE len 1158 + pk
    let pk = vec![0xAB; KEM_PK_LEN];
    let mut v = Vec::new();
    encode_kem_params(&mut v, &KemParams::Pk(pk.clone())).unwrap();
    assert_eq!(&v[..2], b"1P");
    assert_eq!(&v[2..4], &(KEM_PK_LEN as u16).to_be_bytes());
    assert_eq!(&v[4..], &pk[..]);
    let mut r = Reader::new(&v);
    assert_eq!(decode_kem_params(&mut r).unwrap(), KemParams::Pk(pk.clone()));

    // CtPk -> b'1' b'A' large(ct) large(pk)
    let ct = vec![0xCD; KEM_CT_LEN];
    let mut v = Vec::new();
    encode_kem_params(&mut v, &KemParams::CtPk(ct.clone(), pk.clone())).unwrap();
    assert_eq!(&v[..2], b"1A");
    let mut r = Reader::new(&v);
    assert_eq!(decode_kem_params(&mut r).unwrap(), KemParams::CtPk(ct, pk));
}

#[test]
fn kcb_box_roundtrip_with_hybrid_key() {
    let kp = kem_keypair();
    let (ct, kem_ss) = kem_encaps(&kp.ek);
    let dh = [0x77u8; 32];
    let hybrid = kem_hybrid_secret(&dh, &kem_ss);
    let nonce = [0x01u8; 24];
    let msg = b"pqdr protected payload";
    let enc = kcb_encrypt(&hybrid, &nonce, msg);
    assert_eq!(enc.len(), msg.len() + 16);
    let dec = kcb_decrypt(&hybrid, &nonce, &enc).unwrap();
    assert_eq!(dec, msg);
    // decapsulated side derives the same hybrid key and decrypts
    let kem_ss2 = kem_decaps(&kp.dk, &ct).unwrap();
    let hybrid2 = kem_hybrid_secret(&dh, &kem_ss2);
    assert_eq!(hybrid, hybrid2);
    assert_eq!(kcb_decrypt(&hybrid2, &nonce, &enc).unwrap(), msg);
    // wrong nonce / tampered tag must fail
    let mut bad = enc.clone();
    bad[0] ^= 1;
    assert!(kcb_decrypt(&hybrid, &nonce, &bad).is_none());
    let wrong_nonce = [0x02u8; 24];
    assert!(kcb_decrypt(&hybrid, &wrong_nonce, &enc).is_none());
}

fn hex(s: &str) -> [u8; 32] {    let mut out = [0u8; 32];
    let b = s.as_bytes();
    for i in 0..32 {
        out[i] = u8::from_str_radix(std::str::from_utf8(&b[2 * i..2 * i + 2]).unwrap(), 16).unwrap();
    }
    out
}

#[test]
fn e2e_ratchet_params_wire_roundtrip() {
    use smp_rs::crypto::{spki_x25519, x25519_keypair};
    let kp = x25519_keypair();
    let kem = kem_keypair();
    let p = E2eRatchetParams {
        v_min: 5,
        v_max: 5,
        snd_dh_spki: spki_x25519(&kp.public.to_bytes()),
        rcv_dh_spki: spki_x25519(&kp.public.to_bytes()),
        kem: KemParams::Pk(kem.ek.as_ref().to_vec()),
    };
    let mut v = Vec::new();
    encode_e2e_ratchet_params(&mut v, &p).unwrap();
    // layout: u16 u16 short(44B spki) short(44B spki) '1' 'P' large(1158B pk)
    assert_eq!(&v[..4], &[0, 5, 0, 5]);
    assert_eq!(v[4], 44);
    let mut r = Reader::new(&v);
    let back = decode_e2e_ratchet_params(&mut r).unwrap();
    assert_eq!(back, p);
    assert_eq!(r.rest().len(), 0);
}

#[test]
fn conn_info_json_carries_pq_e2e_params() {
    let kem = kem_keypair();
    let mut e2e = Vec::new();
    encode_e2e_ratchet_params(
        &mut e2e,
        &E2eRatchetParams {
            v_min: 5,
            v_max: 5,
            snd_dh_spki: vec![0x30; 44],
            rcv_dh_spki: vec![0x30; 44],
            kem: KemParams::Pk(kem.ek.as_ref().to_vec()),
        },
    )
    .unwrap();
    let ci = smp_rs::agent::ConnInfo { profile: "alice".into(), pq_support: true, e2e: Some(e2e.clone()) };
    let j = serde_json::to_vec(&ci).unwrap();
    let back: smp_rs::agent::ConnInfo = serde_json::from_slice(&j).unwrap();
    assert_eq!(back, ci);
    assert!(back.pq_support);
    // legacy connInfo without e2e still parses (backward compat)
    let old: smp_rs::agent::ConnInfo = serde_json::from_slice(br#"{"profile":"bob","pq_support":false}"#).unwrap();
    assert_eq!(old.e2e, None);
}
