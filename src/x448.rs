//! X448 (Curve448) Diffie-Hellman — RFC 7748.
//!
//! The official SimpleX agent E2E ratchet uses X448 keys (`C.X448` in simplexmq),
//! so interop with the stock mobile client needs this. Implemented over the RustCrypto
//! `x448` crate (RFC 7748, `static_secrets` feature).
//!
//! NOTE: we previously used `cx448` 0.1.1, which pulls `crypto-bigint` 0.5.5 — affected by
//! RUSTSEC-2026-0387 (secret-dependent branches in constant-time arithmetic, fixed in
//! crypto-bigint >= 0.7.6). `cx448` has no release with the fix, so the dependency was
//! swapped for RustCrypto `x448`, which has no crypto-bigint in its tree and clamps
//! scalars per RFC 7748 in `StaticSecret::from`.
//!
//! Wire formats:
//!   - raw public key: 56 bytes
//!   - X.509 SPKI: `30 42 30 05 06 03 2b 65 6f 03 39 00 <56 bytes>`
//!     (id-X448 = 1.3.101.111 → OID `2b 65 6f`)

use rand::rngs::OsRng;
use rand::RngCore;

pub const X448_LEN: usize = 56;
/// id-X448 = 1.3.101.111
pub const X448_OID: [u8; 3] = [0x2b, 0x65, 0x6f];
/// SPKI prefix for a 56-byte X448 public key.
pub const X448_SPKI_PREFIX: [u8; 12] = [0x30, 0x42, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6f, 0x03, 0x39, 0x00];
/// X448 base point (RFC 7748 §5): 9 followed by 55 zero bytes.
pub const X448_BASE: [u8; 56] = {
    let mut b = [0u8; 56];
    b[0] = 9;
    b
};

/// RFC 7748 §5 scalar clamping for X448: clear the two low bits of the first
/// octet and set the high bit of the last octet.
/// Applied by `x448::StaticSecret::from` internally; kept public for wire-level tooling.
pub fn clamp_scalar(k: &[u8; 56]) -> [u8; 56] {
    let mut k = *k;
    k[0] &= 252;
    k[55] |= 128;
    k
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct X448Keypair {
    pub secret: [u8; 56],
    pub public: [u8; 56],
}

/// Generate a fresh X448 keypair (OsRng).
///
/// The scalar is clamped here *and* by `x448::StaticSecret::from`, so the stored
/// secret is exactly the scalar the peer will use in its DH computation.
pub fn keypair() -> X448Keypair {
    let mut bytes = [0u8; 56];
    OsRng.fill_bytes(&mut bytes);
    let secret = clamp_scalar(&bytes);
    // clamped fresh scalar is always a valid X448 secret; unwrap_or keeps this infallible path panic-free
    let public = public_from_secret(&secret).unwrap_or([0u8; 56]);
    X448Keypair { secret, public }
}

/// public = X448(clamp(secret), base).
/// `StaticSecret::from` clamps per RFC 7748; `PublicKey::from(&secret)` performs
/// the base-point multiplication.
pub fn public_from_secret(secret: &[u8; 56]) -> Option<[u8; 56]> {
    let s = x448::StaticSecret::from(*secret);
    Some(*x448::PublicKey::from(&s).as_bytes())
}

/// X448(clamp(secret), peer_public); None if the peer key is malformed or low-order.
pub fn dh(secret: &[u8; 56], peer_public: &[u8; 56]) -> Option<[u8; 56]> {
    let peer = x448::PublicKey::from_bytes(peer_public)?;
    let s = x448::StaticSecret::from(*secret);
    let shared = s.diffie_hellman(&peer);
    Some(*shared.as_bytes())
}

/// Wrap a raw 56-byte X448 public key into X.509 SPKI DER.
pub fn spki_x448(raw56: &[u8; 56]) -> Vec<u8> {
    let mut v = Vec::with_capacity(68);
    v.extend_from_slice(&X448_SPKI_PREFIX);
    v.extend_from_slice(raw56);
    v
}

/// Parse an X.509 SPKI DER blob carrying an X448 public key.
/// (crypto::parse_spki only handles 32-byte X25519/Ed25519 keys, so X448 is parsed here.)
pub fn parse_spki_x448(der: &[u8]) -> Option<[u8; 56]> {
    if der.len() != 68 || der[..12] != X448_SPKI_PREFIX {
        return None;
    }
    let mut out = [0u8; 56];
    out.copy_from_slice(&der[12..68]);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Golden vector generated with Python `cryptography` (OpenSSL X448) —
    // cross-implementation check that our X448 math matches the reference.
    const GOLDEN_PRIV: &str = "ec010ad67e57f464605e5273daba41f433f2eb42850dbce2c73c2ca3a23d63e84ac135ef4adeede4cd20322a463903130b817f61d8d233d1";
    const GOLDEN_SPKI: &str = "3042300506032b656f033900bd2e3619e7fa725b896020c4662778bf3104af3c514abfdb889777db2212ab071436fd93e43184d063ad853ca4a30a2c7ffa61f75bc34871";
    const GOLDEN_PEER_PUB: &str = "5c7a27edc2b5203c625530ccefba701d6a8353ec73b2b50020255a351c0afac697738ed80edf4e24cc704b633c66ee80198e1a68189a7d62";
    const GOLDEN_SHARED: &str = "d1a7cd1533252e535e9ff72a41a13627e7b8473b5b3fdc2a8c1ab49ba51547635abf019377474bc8b348c5b29f86dfceedbd9d72c2470449";

    #[test]
    fn golden_vector_matches_openssl() {
        let sk: [u8; 56] = hex::decode(GOLDEN_PRIV).unwrap().try_into().unwrap();
        let spki = hex::decode(GOLDEN_SPKI).unwrap();
        let peer: [u8; 56] = hex::decode(GOLDEN_PEER_PUB).unwrap().try_into().unwrap();
        let shared = hex::decode(GOLDEN_SHARED).unwrap();

        // SPKI wraps exactly the public key derived from the private key
        let pubkey = public_from_secret(&sk).expect("valid scalar");
        assert_eq!(spki_x448(&pubkey), spki);
        // SPKI parses back to the raw key
        assert_eq!(parse_spki_x448(&spki).unwrap(), pubkey);
        // DH matches OpenSSL's shared secret
        assert_eq!(dh(&sk, &peer).unwrap().to_vec(), shared);
    }

    #[test]
    fn keypair_dh_roundtrip() {
        let a = keypair();
        let b = keypair();
        let s1 = dh(&a.secret, &b.public).expect("dh a");
        let s2 = dh(&b.secret, &a.public).expect("dh b");
        assert_eq!(s1, s2, "both sides must derive the same shared secret");
        assert_ne!(s1, [0u8; 56]);
        // SPKI roundtrip of a generated key
        let spki = spki_x448(&a.public);
        assert_eq!(spki.len(), 68);
        assert_eq!(parse_spki_x448(&spki).unwrap(), a.public);
    }

    #[test]
    fn low_order_peer_key_is_rejected() {
        let a = keypair();
        assert!(dh(&a.secret, &[0u8; 56]).is_none(), "all-zero point must be rejected");
    }

    #[test]
    fn wrong_oid_spki_is_rejected() {
        // X25519 SPKI (OID ...6e) must not parse as X448
        let wrong = crate::crypto::spki_x25519(&[7u8; 32]);
        assert!(parse_spki_x448(&wrong).is_none());
    }
}
