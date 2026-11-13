//! Crypto layer matching `Simplex.Messaging.Crypto`:
//!   - X25519 DH (x25519-dalek), Ed25519 signatures (ed25519-dalek)
//!   - Keys are encoded on the wire as X.509 SubjectPublicKeyInfo DER
//!     (44-byte fixed templates), wrapped in shortString.
//!   - NaCl crypto_box / crypto_secretbox == XSalsa20-Poly1305 secretbox
//!     with key = DH shared secret (32B), nonce = 24B. Output is NaCl
//!     format: 16-byte MAC || ciphertext.
//!   - CbNonce = 24 raw bytes. cbNonce(msgId) = msgId zero-padded right to 24.
//!   - KeyHash = SHA-256 (32B), base64url in string form.

use aead::{Aead, KeyInit};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256, Sha512};
pub use x25519_dalek::PublicKey as XPublic;
use x25519_dalek::StaticSecret;
use xsalsa20poly1305::{Nonce, XSalsa20Poly1305};

use crate::encoding::{w_short, EncodeError, Reader};

pub const NONCE_LEN: usize = 24;
pub const KEY_LEN: usize = 32;
pub const SIG_LEN: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthAlg {
    Ed25519,
    X25519,
}

// ---------- X.509 SPKI DER (fixed 44-byte templates) ----------
// X25519 OID 1.3.101.110 ; Ed25519 OID 1.3.101.112
pub fn spki_x25519(raw32: &[u8; 32]) -> Vec<u8> {
    let mut v = Vec::with_capacity(44);
    v.extend_from_slice(&[0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00]);
    v.extend_from_slice(raw32);
    v
}
pub fn spki_ed25519(raw32: &[u8; 32]) -> Vec<u8> {
    let mut v = Vec::with_capacity(44);
    v.extend_from_slice(&[0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00]);
    v.extend_from_slice(raw32);
    v
}

/// Parse a 44-byte SPKI DER back into (alg, raw32).
pub fn parse_spki(der: &[u8]) -> Result<(AuthAlg, [u8; 32]), EncodeError> {
    if der.len() != 44 {
        return Err(EncodeError(format!("spki len {} != 44", der.len())));
    }
    let oid = &der[6..9];
    let raw: [u8; 32] = der.get(12..44).and_then(|s| s.try_into().ok()).unwrap_or([0u8; 32]);
    if oid == [0x2b, 0x65, 0x6e] {
        Ok((AuthAlg::X25519, raw))
    } else if oid == [0x2b, 0x65, 0x70] {
        Ok((AuthAlg::Ed25519, raw))
    } else {
        Err(EncodeError("unknown spki oid".into()))
    }
}

/// Wire encoding of a public auth key: shortString(SPKI DER).
pub fn encode_pubkey(out: &mut Vec<u8>, alg: &AuthAlg, raw32: &[u8; 32]) -> Result<(), EncodeError> {
    let der = match alg {
        AuthAlg::Ed25519 => spki_ed25519(raw32),
        AuthAlg::X25519 => spki_x25519(raw32),
    };
    w_short(out, &der)
}
pub fn decode_pubkey(r: &mut Reader) -> Result<(AuthAlg, [u8; 32]), EncodeError> {
    let der = r.short()?;
    parse_spki(&der)
}

// ---------- X25519 ----------
#[derive(Clone)]
pub struct X25519Keypair {
    pub secret: StaticSecret,
    pub public: XPublic,
}
pub fn x25519_keypair() -> X25519Keypair {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = XPublic::from(&secret);
    X25519Keypair { secret, public }
}
pub fn x25519_dh(secret: &StaticSecret, peer_pub: &XPublic) -> [u8; 32] {
    secret.diffie_hellman(peer_pub).to_bytes()
}

// ---------- Ed25519 ----------
pub struct Ed25519Keypair {
    pub signing: SigningKey,
    pub verifying: VerifyingKey,
}
pub fn ed25519_keypair() -> Ed25519Keypair {
    let signing = SigningKey::generate(&mut OsRng);
    let verifying = signing.verifying_key();
    Ed25519Keypair { signing, verifying }
}
pub fn ed25519_sign(kp: &Ed25519Keypair, msg: &[u8]) -> [u8; SIG_LEN] {
    kp.signing.sign(msg).to_bytes()
}
pub fn ed25519_verify(pub_raw: &[u8; 32], msg: &[u8], sig: &[u8; SIG_LEN]) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(pub_raw) else { return false };
    let s = Signature::from_bytes(sig);
    vk.verify(msg, &s).is_ok()
}

/// X25519 public key from raw 32 bytes.
pub fn x25519_public(raw: [u8; 32]) -> XPublic {
    XPublic::from(raw)
}

// ---------- NaCl crypto_box == HSalsa20(shared, 0^16) then XSalsa20-Poly1305 ----------
/// Derive the symmetric key exactly like NaCl crypto_box_beforenm: HSalsa20(shared, 0^16).
fn box_key(shared: &[u8; 32]) -> [u8; 32] {
    hsalsa20(shared, &[0u8; 16])
}

/// HSalsa20 (NaCl): Salsa20 core with key, 16-byte nonce, no feedforward, output words 0,5,10,15,6,7,8,9.
pub fn hsalsa20_pub(key: &[u8; 32], nonce: &[u8; 16]) -> [u8; 32] { hsalsa20(key, nonce) }
fn hsalsa20(key: &[u8; 32], nonce: &[u8; 16]) -> [u8; 32] {
    const SIGMA: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574]; // "expand 32-byte k"
    let k = |i: usize| u32::from_le_bytes([key[4*i], key[4*i+1], key[4*i+2], key[4*i+3]]);
    let n = |i: usize| u32::from_le_bytes([nonce[4*i], nonce[4*i+1], nonce[4*i+2], nonce[4*i+3]]);
    let mut x = [
        SIGMA[0], k(0), k(1), k(2),
        k(3), SIGMA[1], n(0), n(1),
        n(2), n(3), SIGMA[2], k(4),
        k(5), k(6), k(7), SIGMA[3],
    ];
    let rotl = |v: u32, c: u32| v.rotate_left(c);
    macro_rules! qr {
        ($a:expr, $b:expr, $c:expr, $d:expr) => {
            x[$b] ^= rotl(x[$a].wrapping_add(x[$d]), 7);
            x[$c] ^= rotl(x[$b].wrapping_add(x[$a]), 9);
            x[$d] ^= rotl(x[$c].wrapping_add(x[$b]), 13);
            x[$a] ^= rotl(x[$d].wrapping_add(x[$c]), 18);
        };
    }
    for _ in 0..10 {
        qr!(0, 4, 8, 12); qr!(5, 9, 13, 1); qr!(10, 14, 2, 6); qr!(15, 3, 7, 11);
        qr!(0, 1, 2, 3); qr!(5, 6, 7, 4); qr!(10, 11, 8, 9); qr!(15, 12, 13, 14);
    }
    let out = [x[0], x[5], x[10], x[15], x[6], x[7], x[8], x[9]];
    let mut r = [0u8; 32];
    for (i, w) in out.iter().enumerate() {
        r[4*i..4*i+4].copy_from_slice(&w.to_le_bytes());
    }
    r
}
/// NaCl format output: 16-byte MAC || ciphertext (the xsalsa20poly1305 0.9 crate uses NaCl order natively).
pub fn secretbox_encrypt(key: &[u8; 32], nonce24: &[u8; 24], plaintext: &[u8]) -> Vec<u8> {
    let k = box_key(key);
    let cipher = XSalsa20Poly1305::new(&k.into());
    cipher
        .encrypt(Nonce::from_slice(nonce24), plaintext)
        .unwrap_or_else(|_| vec![0u8; 16])
}
pub fn secretbox_decrypt(key: &[u8; 32], nonce24: &[u8; 24], nacl: &[u8]) -> Option<Vec<u8>> {
    if nacl.len() < 16 {
        return None;
    }
    let k = box_key(key);
    let cipher = XSalsa20Poly1305::new(&k.into());
    cipher.decrypt(Nonce::from_slice(nonce24), nacl).ok()
}

/// cbNonce: take up to 24 bytes, right-pad with zeros to 24.
pub fn cb_nonce(bytes: &[u8]) -> [u8; 24] {
    let mut n = [0u8; 24];
    let k = bytes.len().min(24);
    n[..k].copy_from_slice(&bytes[..k]);
    n
}

/// Raw NaCl secretbox (XSalsa20-Poly1305 with the key used directly, NO HSalsa20 beforenm).
/// Used for XFTP file encryption, where the file key from the file description is the box key itself.
pub fn raw_secretbox_encrypt(key: &[u8; 32], nonce24: &[u8; 24], plaintext: &[u8]) -> Vec<u8> {
    let cipher = XSalsa20Poly1305::new(key.into());
    cipher.encrypt(Nonce::from_slice(nonce24), plaintext).unwrap_or_else(|_| vec![0u8; 16])
}
pub fn raw_secretbox_decrypt(key: &[u8; 32], nonce24: &[u8; 24], nacl: &[u8]) -> Option<Vec<u8>> {
    if nacl.len() < 16 {
        return None;
    }
    let cipher = XSalsa20Poly1305::new(key.into());
    cipher.decrypt(Nonce::from_slice(nonce24), nacl).ok()
}

// ---------- hashes ----------
pub fn sha256(b: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b);
    h.finalize().into()
}
pub fn sha512(b: &[u8]) -> [u8; 64] {
    let mut h = Sha512::new();
    h.update(b);
    h.finalize().into()
}

/// KeyHash = SHA-256, string form base64url (no padding). We keep raw 32B on the wire.
pub fn key_hash(cert_der: &[u8]) -> [u8; 32] {
    sha256(cert_der)
}

pub fn base64url_nopad(b: &[u8]) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut s = String::new();
    for chunk in b.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        s.push(T[(n >> 18 & 63) as usize] as char);
        s.push(T[(n >> 12 & 63) as usize] as char);
        if chunk.len() > 1 {
            s.push(T[(n >> 6 & 63) as usize] as char);
        }
        if chunk.len() > 2 {
            s.push(T[(n & 63) as usize] as char);
        }
    }
    s
}

pub fn random_bytes(n: usize) -> Vec<u8> {
    use rand::RngCore;
    let mut v = vec![0u8; n];
    OsRng.fill_bytes(&mut v);
    v
}
