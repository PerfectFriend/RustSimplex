//! Strict SMP v23 transport block-chain encryption (SimpleX `SbChainKey`).
//!
//! Mirrors simplexmq `Simplex.Messaging.Crypto`:
//! - `sbcInit sessionId secret` = HKDF-SHA512(salt=sessionId, ikm=secret, info="SimpleXSbChainInit", 64), split 32/32.
//! - `sbcHkdf ck` = HKDF-SHA512(salt="", ikm=ck, info="SimpleXSbChain", 88) -> ck'(32) | sbKey(32) | nonce(24).
//! - Block: pad encoded block with '#' to `block_size - 16`, then XSalsa20-Poly1305 secretbox (16B tag) -> `block_size`.

use aead::{Aead, KeyInit};
use hkdf::Hkdf;
use sha2::Sha512;
use xsalsa20poly1305::{Key, Nonce, XSalsa20Poly1305};
use std::io::{Read, Write};

pub const BLOCK_SIZE: usize = 16384;
pub const TAG_SIZE: usize = 16;
pub const PAD_LEN: usize = BLOCK_SIZE - TAG_SIZE; // 16368

fn hkdf_sha512(salt: &[u8], ikm: &[u8], info: &[u8], out: &mut [u8]) {
    let hk = Hkdf::<Sha512>::new(Some(salt), ikm);
    hk.expand(info, out).expect("hkdf expand");
}

/// (ck_send, ck_rcv) chain roots from session id + DH secret.
pub fn sbc_init(session_id: &[u8], secret: &[u8]) -> ([u8; 32], [u8; 32]) {
    let mut out = [0u8; 64];
    hkdf_sha512(session_id, secret, b"SimpleXSbChainInit", &mut out);
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    a.copy_from_slice(&out[..32]);
    b.copy_from_slice(&out[32..]);
    (a, b)
}

/// Advance chain: returns (next_chain_key, secretbox_key, nonce).
pub fn sbc_hkdf(ck: &[u8; 32]) -> ([u8; 32], [u8; 32], [u8; 24]) {
    let mut out = [0u8; 88];
    hkdf_sha512(b"", ck, b"SimpleXSbChain", &mut out);
    let mut ck2 = [0u8; 32];
    let mut key = [0u8; 32];
    let mut nonce = [0u8; 24];
    ck2.copy_from_slice(&out[0..32]);
    key.copy_from_slice(&out[32..64]);
    nonce.copy_from_slice(&out[64..88]);
    (ck2, key, nonce)
}

pub fn pad_to(buf: &[u8], len: usize) -> Vec<u8> {
    assert!(buf.len() <= len, "block too large");
    let mut out = buf.to_vec();
    out.resize(len, b'#');
    out
}

pub fn unpad(mut buf: Vec<u8>) -> Vec<u8> {
    while buf.last() == Some(&b'#') {
        buf.pop();
    }
    buf
}

/// Length-prefixed pad for strict blocks: u16 BE len + payload + '#' to `len` (avoids trailing-'#' ambiguity).
pub fn pad_block(buf: &[u8], len: usize) -> Vec<u8> {
    assert!(buf.len() <= len - 2, "block too large");
    let mut out = Vec::with_capacity(len);
    out.extend_from_slice(&(buf.len() as u16).to_be_bytes());
    out.extend_from_slice(buf);
    out.resize(len, b'#');
    out
}

pub fn unpad_block(buf: &[u8]) -> Result<Vec<u8>, &'static str> {
    if buf.len() < 2 {
        return Err("short block");
    }
    let n = u16::from_be_bytes([buf[0], buf[1]]) as usize;
    if 2 + n > buf.len() {
        return Err("bad pad length");
    }
    Ok(buf[2..2 + n].to_vec())
}

/// Encrypt one encoded block (without outer padding) and advance the chain.
pub fn encrypt_block(ck: &[u8; 32], encoded_block: &[u8]) -> ([u8; 32], Vec<u8>) {
    let (ck2, key, nonce) = sbc_hkdf(ck);
    let padded = pad_block(encoded_block, PAD_LEN);
    let cipher = XSalsa20Poly1305::new(Key::from_slice(&key));
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce), padded.as_slice())
        .expect("secretbox encrypt");
    debug_assert_eq!(ct.len(), BLOCK_SIZE);
    (ck2, ct)
}

/// Decrypt one full block and advance the chain. Returns encoded block without padding.
pub fn decrypt_block(ck: &[u8; 32], block: &[u8]) -> Result<([u8; 32], Vec<u8>), &'static str> {
    if block.len() != BLOCK_SIZE {
        return Err("bad block size");
    }
    let (ck2, key, nonce) = sbc_hkdf(ck);
    let cipher = XSalsa20Poly1305::new(Key::from_slice(&key));
    let pt = cipher
        .decrypt(Nonce::from_slice(&nonce), block)
        .map_err(|_| "bad tag")?;
    Ok((ck2, unpad_block(&pt)?))
}

/// Derive directional chain keys. Server: snd=a, rcv=b. Client: swapped (Haskell `swap` in smpTHandleClient).
pub fn strict_keys(session_id: &[u8], secret: &[u8], client: bool) -> ([u8; 32], [u8; 32]) {
    let (a, b) = sbc_init(session_id, secret);
    if client { (b, a) } else { (a, b) }
}

/// Wire-level strict block I/O: on the wire a strict block is exactly BLOCK_SIZE ciphertext (no u16 prefix).
pub fn write_block_encrypted<W: Write>(w: &mut W, ck: &mut [u8; 32], encoded_block: &[u8]) -> std::io::Result<()> {
    let (next, ct) = encrypt_block(ck, encoded_block);
    *ck = next;
    w.write_all(&ct)?;
    w.flush()
}

pub fn read_block_encrypted<R: Read>(r: &mut R, ck: &mut [u8; 32]) -> std::io::Result<Vec<u8>> {
    let mut buf = vec![0u8; BLOCK_SIZE];
    r.read_exact(&mut buf)?;
    let (next, pt) = decrypt_block(ck, &buf).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    *ck = next;
    Ok(pt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_roundtrip_and_advance() {
        let (c0a, _c0b) = sbc_init(b"session-id-32-bytes-aaaaaaaaaaaaa", b"dh-secret-32-bytes-aaaaaaaaaaaa");
        let ck = c0a;
        let mut block = b"PING".to_vec();
        block.extend_from_slice(&[0u8; 100]);
        let (ck1, ct) = encrypt_block(&ck, &block);
        assert_eq!(ct.len(), BLOCK_SIZE);
        assert_ne!(ck1, ck);
        let (ck1b, pt) = decrypt_block(&ck, &ct).unwrap();
        assert_eq!(ck1b, ck1);
        assert_eq!(pt, block);
        // second block uses advanced chain key, different ciphertext
        let (ck2, ct2) = encrypt_block(&ck1, &block);
        assert_ne!(ct2, ct);
        let (_ck3, pt2) = decrypt_block(&ck1, &ct2).unwrap();
        assert_eq!(pt2, block);
        // wrong chain key fails tag
        assert!(decrypt_block(&ck2, &ct).is_err());
    }

    #[test]
    fn hkdf_lengths_match_spec() {
        let (a, b) = sbc_init(b"sid", b"secret");
        assert_ne!(a, b);
        let (ck2, key, nonce) = sbc_hkdf(&a);
        assert_ne!(ck2, a);
        assert_eq!(key.len(), 32);
        assert_eq!(nonce.len(), 24);
    }

    #[test]
    fn strict_pad_keeps_trailing_hash_bytes() {
        let (ck, _b) = sbc_init(b"sid", b"secret");
        let mut payload = b"data#".to_vec();
        payload.extend_from_slice(&[b'#'; 5]);
        let (_ck2, ct) = encrypt_block(&ck, &payload);
        let (_c3, pt) = decrypt_block(&ck, &ct).unwrap();
        assert_eq!(pt, payload);
    }

    #[test]
    fn strict_keys_swap_for_client() {
        let (sa, sb) = strict_keys(b"sid", b"secret", false);
        let (ca, cb) = strict_keys(b"sid", b"secret", true);
        assert_eq!(sa, cb);
        assert_eq!(sb, ca);
        assert_ne!(sa, sb);
    }

    #[test]
    fn strict_block_io_over_tcp() {
        use std::net::{TcpListener, TcpStream};
        use std::thread;
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let h = thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            let (c0, _) = sbc_init(b"sid", b"secret");
            let mut ck = c0;
            let a = read_block_encrypted(&mut s, &mut ck).unwrap();
            let b = read_block_encrypted(&mut s, &mut ck).unwrap();
            write_block_encrypted(&mut s, &mut ck, b"PONG").unwrap();
            (a, b)
        });
        let mut c = TcpStream::connect(addr).unwrap();
        let (c0, _) = sbc_init(b"sid", b"secret");
        let mut ck = c0;
        write_block_encrypted(&mut c, &mut ck, b"PING-1").unwrap();
        write_block_encrypted(&mut c, &mut ck, b"PING-2").unwrap();
        let pong = read_block_encrypted(&mut c, &mut ck).unwrap();
        let (a, b) = h.join().unwrap();
        assert_eq!(a, b"PING-1");
        assert_eq!(b, b"PING-2");
        assert_eq!(pong, b"PONG");
    }
}
