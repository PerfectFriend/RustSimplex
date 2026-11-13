//! PQDR — post-quantum augmented double ratchet (protocol/pqdr.md), with the exact
//! KDFs from Simplex.Messaging.Crypto.Ratchet (simplexmq):
//!
//!   hkdf3 salt ikm info = HKDF-SHA512(salt, ikm, info, 96) -> 3 x 32 bytes
//!   rootKdf rk (dh || kem_ss)  info="SimpleXRootRatchet"  -> (RK', CK, NHK)
//!   chainKdf ck                info="SimpleXChainRatchet"  -> (CK', MK, IV1, IV2)
//!
//! DH is X25519 here (Simplex production uses Curve448; the KDF/DH-ratchet structure
//! is identical). KEM is SNTRUP761, running as "parallel ping-pong" per pqdr.md:
//! every DH ratchet step performs two KEM agreements (decapsulate the incoming
//! ciphertext — KEM #2, and encapsulate against the incoming encapsulation key —
//! KEM #1) and both shared secrets enter the root KDF.
//!
//! Deviations from the wire spec (documented in docs/SECURITY.md):
//!   - message header is sent as plaintext fields (not AES-256-GCM encrypted);
//!   - message body uses XSalsa20-Poly1305 secretbox with MK (nonce = IV1 || n)
//!     instead of AES-256-GCM — same ratchet/KDF structure, different AEAD.

use sha2::{Digest, Sha512};

use crate::crypto::{secretbox_decrypt, secretbox_encrypt, x25519_dh, x25519_keypair, x25519_public, X25519Keypair, XPublic};
use crate::encoding::{w_large, w_short, w_u16, w_u32, EncodeError, Reader};
use crate::pq::{kem_decaps, kem_encaps, kem_keypair, KemKeypair, KemParams, KEM_CT_LEN, KEM_PK_LEN};

pub const PQDR_VERSION: u16 = 3; // pqRatchetE2EEncryptVersion
pub const MAX_SKIP: u32 = 1000;

// ---------- HKDF-SHA512 (hand-rolled HMAC) ----------

fn hmac_sha512(key: &[u8], msg: &[u8]) -> [u8; 64] {
    let mut k = [0u8; 128];
    if key.len() > 128 {
        let h = Sha512::digest(key);
        k[..64].copy_from_slice(&h);
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; 128];
    let mut opad = [0x5cu8; 128];
    for i in 0..128 {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let mut inner = Sha512::new();
    inner.update(ipad);
    inner.update(msg);
    let ih = inner.finalize();
    let mut outer = Sha512::new();
    outer.update(opad);
    outer.update(ih);
    outer.finalize().into()
}

/// HKDF-SHA512 extract+expand (Ratchet.hs `hkdf` = H.extract salt ikm / H.expand prk info n).
fn hkdf(salt: &[u8], ikm: &[u8], info: &[u8], n: usize) -> Vec<u8> {
    let prk = hmac_sha512(salt, ikm);
    let mut out = Vec::with_capacity(n);
    let mut t: Vec<u8> = Vec::new();
    let mut counter = 1u8;
    while out.len() < n {
        let mut m = t.clone();
        m.extend_from_slice(info);
        m.push(counter);
        t = hmac_sha512(&prk, &m).to_vec();
        out.extend_from_slice(&t);
        counter = counter.wrapping_add(1);
    }
    out.truncate(n);
    out
}

/// hkdf3 salt ikm info -> (32, 32, 32)  (Ratchet.hs `hkdf3`, 96 bytes).
fn hkdf3(salt: &[u8], ikm: &[u8], info: &[u8]) -> ([u8; 32], [u8; 32], [u8; 32]) {
    let out = hkdf(salt, ikm, info, 96);
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    let mut c = [0u8; 32];
    a.copy_from_slice(&out[..32]);
    b.copy_from_slice(&out[32..64]);
    c.copy_from_slice(&out[64..96]);
    (a, b, c)
}

/// rootKdf: (RK', CK, NHK) = hkdf3(rk, dh || kem_ss, "SimpleXRootRatchet")
fn root_kdf(rk: &[u8; 32], dh: &[u8; 32], kem_ss: Option<&[u8; 32]>) -> ([u8; 32], [u8; 32], [u8; 32]) {
    let mut ikm = dh.to_vec();
    if let Some(ss) = kem_ss {
        ikm.extend_from_slice(ss);
    }
    hkdf3(rk, &ikm, b"SimpleXRootRatchet")
}

/// chainKdf: (CK', MK, IV1||IV2) = hkdf3("", ck, "SimpleXChainRatchet")
fn chain_kdf(ck: &[u8; 32]) -> ([u8; 32], [u8; 32], [u8; 16], [u8; 16]) {
    let (ck2, mk, ivs) = hkdf3(&[], ck, b"SimpleXChainRatchet");
    let mut iv1 = [0u8; 16];
    let mut iv2 = [0u8; 16];
    iv1.copy_from_slice(&ivs[..16]);
    iv2.copy_from_slice(&ivs[16..32]);
    (ck2, mk, iv1, iv2)
}

// ---------- wire ----------

/// Plaintext message header (pqdr.md `msgHeader`, X25519 dh key instead of Curve448).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MsgHeader {
    pub max_version: u16,
    pub dh_pub_spki: Vec<u8>, // SPKI DER of sender's current DH ratchet key
    pub kem: KemParams,
    pub pn: u32, // messages in previous sending chain
    pub ns: u32, // message number in current sending chain
}

pub fn encode_msg_header(h: &MsgHeader) -> Vec<u8> {
    let mut o = Vec::new();
    w_u16(&mut o, h.max_version);
    w_short(&mut o, &h.dh_pub_spki).unwrap();
    crate::pq::encode_kem_params(&mut o, &h.kem).unwrap();
    w_u32(&mut o, h.pn);
    w_u32(&mut o, h.ns);
    o
}

pub fn decode_msg_header(r: &mut Reader) -> Result<MsgHeader, EncodeError> {
    let max_version = r.u16()?;
    let dh_pub_spki = r.short()?;
    let kem = crate::pq::decode_kem_params(r)?;
    let pn = r.u32()?;
    let ns = r.u32()?;
    Ok(MsgHeader { max_version, dh_pub_spki, kem, pn, ns })
}

/// Full ratchet message: u16 len + header + secretbox body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RatchetMsg {
    pub header: MsgHeader,
    pub body: Vec<u8>, // XSalsa20-Poly1305(mk, iv1||ns, plaintext)
}

pub fn encode_ratchet_msg(m: &RatchetMsg) -> Vec<u8> {
    let h = encode_msg_header(&m.header);
    let mut o = Vec::new();
    w_u16(&mut o, h.len() as u16);
    o.extend_from_slice(&h);
    o.extend_from_slice(&m.body);
    o
}

pub fn decode_ratchet_msg(b: &[u8]) -> Result<RatchetMsg, EncodeError> {
    let mut r = Reader { buf: b, pos: 0 };
    let hlen = r.u16()? as usize;
    if r.pos + hlen > b.len() {
        return Err(EncodeError("ratchet msg: header len".into()));
    }
    let header = decode_msg_header(&mut r)?;
    if r.pos != 2 + hlen {
        return Err(EncodeError("ratchet msg: header length mismatch".into()));
    }
    Ok(RatchetMsg { header, body: b[2 + hlen..].to_vec() })
}

// ---------- ratchet state ----------

#[derive(Clone)]
pub struct PqdrRatchet {
    pub ad: Vec<u8>,
    pub rk: [u8; 32],
    pub dh_s: X25519Keypair, // our current DH ratchet private key
    pub dh_r: XPublic,       // peer's current DH ratchet public key
    pub cks: [u8; 32],       // sending chain key
    pub ckr: Option<[u8; 32]>, // receiving chain key
    pub nhks: [u8; 32],      // next header key (sending)
    pub nhkr: Option<[u8; 32]>,
    pub kem_s: KemKeypair,   // our current KEM keypair
    pub kem_r: Vec<u8>,      // peer's current KEM encapsulation key
    /// outstanding encapsulation we sent in the last header: (ct, ss, our new pk)
    pending: Option<(Vec<u8>, [u8; 32], Vec<u8>)>,
    pub pn: u32,
    pub ns: u32,
    pub nr: u32,
    /// skipped message keys: (dh_pub_raw, n) -> mk
    skipped: Vec<([u8; 32], u32, [u8; 32], [u8; 16])>,
}

fn dh_pub_raw(kp: &X25519Keypair) -> [u8; 32] {
    kp.public.to_bytes()
}

impl PqdrRatchet {
    /// Sender init (Alice): SK = initial shared secret from X3DH-style key agreement.
    /// Bob's DH pub `dh_r` and KEM pub `kem_r` come from the connection request.
    pub fn init_sender(sk: &[u8; 32], ad: Vec<u8>, dh_r: XPublic, kem_r: Vec<u8>) -> PqdrRatchet {
        let dh_s = x25519_keypair();
        let kem_s = kem_keypair();
        // KEM #1 at init: encapsulate against Bob's KEM key
        let (ct, ss) = kem_encaps_pub(&kem_r);
        let dh = x25519_dh(&dh_s.secret, &dh_r);
        let (rk, cks, nhks) = root_kdf(sk, &dh, Some(&ss));
        let kem_pk = kem_s.ek.as_ref().to_vec();
        PqdrRatchet {
            ad,
            rk,
            dh_s,
            dh_r,
            cks,
            ckr: None,
            nhks,
            nhkr: None,
            kem_s,
            kem_r,
            pending: Some((ct, ss, kem_pk)),
            pn: 0,
            ns: 0,
            nr: 0,
            skipped: Vec::new(),
        }
    }

    /// Receiver init (Bob): SK, own DH `dh_s` and own KEM `kem_s` (the pair Alice already
    /// encapsulated to). Per the double-ratchet spec, Bob's first decrypt performs the
    /// DH ratchet step using Alice's DH/KEM params from her first header — so `dh_r`
    /// starts as a placeholder (own pub) that never matches.
    pub fn init_receiver(sk: &[u8; 32], ad: Vec<u8>, dh_s: X25519Keypair, kem_s: KemKeypair, kem_r: Vec<u8>) -> PqdrRatchet {
        let rk = *sk;
        let dh_r = dh_s.public;
        PqdrRatchet {
            ad,
            rk,
            dh_s,
            dh_r,
            cks: [0u8; 32],
            ckr: None,
            nhks: [0u8; 32],
            nhkr: None,
            kem_s,
            kem_r,
            pending: None,
            pn: 0,
            ns: 0,
            nr: 0,
            skipped: Vec::new(),
        }
    }

    fn header_kem(&self) -> KemParams {
        match &self.pending {
            // acceptedKEM: "A" ct pk — we have an outstanding encapsulation + new pk
            Some((ct, _, pk)) => KemParams::CtPk(ct.clone(), pk.clone()),
            None => KemParams::Pk(self.kem_s.ek.as_ref().to_vec()),
        }
    }

    /// Encrypt one message; returns the wire bytes.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Vec<u8> {
        let (cks, mk, iv1, _iv2) = chain_kdf(&self.cks);
        self.cks = cks;
        let n = self.ns;
        self.ns += 1;
        let mut nonce = [0u8; 24];
        nonce[..16].copy_from_slice(&iv1);
        nonce[16..].copy_from_slice(&(n as u64).to_be_bytes());
        let body = secretbox_encrypt(&mk, &nonce, plaintext);
        let hdr = MsgHeader {
            max_version: PQDR_VERSION,
            dh_pub_spki: crate::crypto::spki_x25519(&dh_pub_raw(&self.dh_s)),
            kem: self.header_kem(),
            pn: self.pn,
            ns: n,
        };
        encode_ratchet_msg(&RatchetMsg { header: hdr, body })
    }

    /// Decrypt one message; returns plaintext or error string.
    pub fn decrypt(&mut self, wire: &[u8]) -> Result<Vec<u8>, String> {
        let msg = decode_ratchet_msg(wire).map_err(|e| e.to_string())?;
        let hdr = &msg.header;
        let (_, dh_raw) = crate::crypto::parse_spki(&hdr.dh_pub_spki).map_err(|e| e.to_string())?;
        let dh_pub = x25519_public(dh_raw);

        // 1) try skipped message keys first
        if let Some(pos) = self.skipped.iter().position(|(d, n, _, _)| *d == dh_raw && *n == hdr.ns) {
            let (_, _, mk, iv1) = self.skipped.remove(pos);
            let mut nonce = [0u8; 24];
            nonce[..16].copy_from_slice(&iv1);
            nonce[16..].copy_from_slice(&(hdr.ns as u64).to_be_bytes());
            return secretbox_decrypt(&mk, &nonce, &msg.body).ok_or_else(|| "AUTH".to_string());
        }

        // 2) DH ratchet step if the header carries a new DH key
        let new_dh = dh_raw != self.dh_r.to_bytes();
        if new_dh {
            // skip message keys in the previous receiving chain up to pn
            self.skip_message_keys(hdr.pn)?;
            // KEM #2: decapsulate incoming ct (acceptedKEM) with our current KEM sk
            let kem_ss = match &hdr.kem {
                KemParams::CtPk(ct, _pk) => {
                    if ct.len() != KEM_CT_LEN {
                        return Err("KEM ct len".into());
                    }
                    Some(kem_decaps(&self.kem_s.dk, ct).map_err(|e| e.to_string())?)
                }
                _ => None,
            };
            // DHRatchetPQ2HE: state.RK, CKr, NHKr = rootKdf(RK, DH(newDHRs, DHRr) || ss)
            let dh1 = x25519_dh(&self.dh_s.secret, &dh_pub);
            let (rk1, ckr, nhkr) = root_kdf(&self.rk, &dh1, kem_ss.as_ref());
            // new DH key + KEM #1: encapsulate against the incoming KEM pk
            self.dh_s = x25519_keypair();
            self.kem_s = kem_keypair();
            let new_kem_pk = match &hdr.kem {
                KemParams::CtPk(_, pk) | KemParams::Pk(pk) => pk.clone(),
                KemParams::None => return Err("KEM required".into()),
            };
            if new_kem_pk.len() != KEM_PK_LEN {
                return Err("KEM pk len".into());
            }
            let (ct, ss) = kem_encaps_pub(&new_kem_pk);
            let dh2 = x25519_dh(&self.dh_s.secret, &dh_pub);
            let (rk2, cks, nhks) = root_kdf(&rk1, &dh2, Some(&ss));
            self.rk = rk2;
            self.ckr = Some(ckr);
            self.nhkr = Some(nhkr);
            self.cks = cks;
            self.nhks = nhks;
            self.dh_r = dh_pub;
            self.kem_r = new_kem_pk;
            self.pending = Some((ct, ss, self.kem_s.ek.as_ref().to_vec()));
            self.pn = self.ns;
            self.ns = 0;
            self.nr = 0;
        }

        // 3) skip message keys in the current receiving chain up to ns
        self.skip_message_keys(hdr.ns)?;

        let ckr = self.ckr.ok_or("no receiving chain")?;
        let (ckr2, mk, iv1, _) = chain_kdf(&ckr);
        self.ckr = Some(ckr2);
        self.nr += 1;
        let mut nonce = [0u8; 24];
        nonce[..16].copy_from_slice(&iv1);
        nonce[16..].copy_from_slice(&(hdr.ns as u64).to_be_bytes());
        secretbox_decrypt(&mk, &nonce, &msg.body).ok_or_else(|| "AUTH".to_string())
    }

    fn skip_message_keys(&mut self, until: u32) -> Result<(), String> {
        let nr = if self.ckr.is_some() { self.nr } else { 0 };
        if nr + MAX_SKIP < until {
            return Err("too many skipped messages".into());
        }
        if self.ckr.is_none() {
            // v0.24: no receiving chain yet (e.g. first message after a DH ratchet on the
            // sender side) — nothing to skip, the incoming ns indexes the fresh chain.
            return Ok(());
        }
        if nr == until {
            return Ok(());
        }
        let dh_raw = self.dh_r.to_bytes();
        let mut ckr = self.ckr.unwrap();
        let mut n = nr;
        while n < until {
            let (ckr2, mk, iv1, _) = chain_kdf(&ckr);
            ckr = ckr2;
            self.skipped.push((dh_raw, n, mk, iv1));
            n += 1;
        }
        self.ckr = Some(ckr);
        self.nr = n;
        Ok(())
    }
}

/// Encapsulate against a raw KEM public key (1158 bytes).
pub fn kem_encaps_pub(pk: &[u8]) -> (Vec<u8>, [u8; 32]) {
    let ek = sntrup761::EncapsulationKey::try_from(pk).expect("kem pk len");
    kem_encaps(&ek)
}
