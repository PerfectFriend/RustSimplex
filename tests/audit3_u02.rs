//! U-02 (audit #3, CRITICAL): handle_rfwd must never panic on wire-controlled
//! lengths — corr_id (transmission) and fwd_corr (decrypted payload) are
//! shortStrings of arbitrary length 0..=255. Pre-fix code did
//! copy_from_slice into [u8;24] → remote panic (process crash with panic=abort).
use smp_rs::crypto::{secretbox_encrypt, spki_x25519, x25519_keypair};
use smp_rs::encoding::{w_short, w_u16};
use smp_rs::protocol::Transmission;
use smp_rs::proxy::handle_rfwd;

fn dispatch(t: &Transmission) -> Vec<Transmission> {
    vec![t.clone()]
}

#[test]
fn u02_bad_corr_id_len_returns_err_not_panic() {
    let eph = x25519_keypair().secret;
    let sess = [7u8; 32];
    let sid = vec![0u8; 16];
    let r = std::panic::catch_unwind(|| {
        handle_rfwd(&[0xAA; 40], &[0u8; 10], &sess, &eph, &sid, &dispatch)
    });
    match r {
        Ok(Err(e)) => assert!(e.contains("corr_id"), "unexpected err: {e}"),
        other => panic!("expected clean Err, got panic-or-value: {}", other.is_err()),
    }
}

#[test]
fn u02_bad_fwd_corr_len_returns_err_not_panic() {
    let eph = x25519_keypair().secret;
    let sess = [9u8; 32];
    let sid = vec![0u8; 16];
    let ck = x25519_keypair();
    // craft a proxy-layer payload whose fwd_corr is 10 bytes, not 24
    let mut fwd = Vec::new();
    w_short(&mut fwd, &[0u8; 10]).unwrap();
    w_u16(&mut fwd, 23);
    w_short(&mut fwd, &spki_x25519(&ck.public.to_bytes())).unwrap();
    fwd.extend_from_slice(&[0u8; 40]);
    let n = [0u8; 24]; // corr_id itself is fine here
    let enc = secretbox_encrypt(&sess, &n, &fwd).unwrap();
    let r = std::panic::catch_unwind(|| {
        handle_rfwd(&enc, &[0u8; 24], &sess, &eph, &sid, &dispatch)
    });
    match r {
        Ok(Err(e)) => assert!(e.contains("fwd_corr"), "unexpected err: {e}"),
        other => panic!("expected clean Err, got panic-or-value: {}", other.is_err()),
    }
}
