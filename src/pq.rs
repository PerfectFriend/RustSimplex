//! PQDR post-quantum KEM layer, matching `Simplex.Messaging.Crypto.SNTRUP761`:
//!   - SNTRUP761 KEM (reference parameter set: pk 1158 B, sk 1763 B, ct 1039 B, ss 32 B)
//!     via the `sntrup761` crate (pure-Rust port of the reference implementation).
//!   - Hybrid secret: `kemHybridSecret = SHA3-256(DHSecretX25519 || KEMSharedKey)`
//!     (draft-josefsson-ntruprime-hybrid style, see SNTRUP761.hs).
//!   - `kemParams` wire format (agent-protocol.md):
//!       kemParams        = %s"0" / (%s"1" ratchetKEMParams)
//!       ratchetKEMParams = %s"P" kemPublicKey / %s"A" kemCiphertext kemPublicKey
//!       kemPublicKey     = largeString ; sntrup761 public key
//!       kemCiphertext    = largeString ; sntrup761 ciphertext
//!   - `kcbEncrypt`/`kcbDecrypt` = NaCl secretbox with the hybrid key used DIRECTLY
//!     as the XSalsa20-Poly1305 key (no HSalsa20 beforenm — LC.sbInit_ uses the key as-is),
//!     NaCl output order: 16-byte MAC || ciphertext.

use rand::RngCore;
use rand::rngs::OsRng;
use sha3::{Digest, Sha3_256};
use sntrup761::{Ciphertext, DecapsulationKey, EncapsulationKey, SharedSecret};

use crate::crypto::{raw_secretbox_decrypt, raw_secretbox_encrypt};
use crate::encoding::{w_large, w_short, w_u16, EncodeError, Reader};

pub const KEM_PK_LEN: usize = sntrup761::PUBLIC_KEY_SIZE; // 1158
pub const KEM_SK_LEN: usize = sntrup761::SECRET_KEY_SIZE; // 1763
pub const KEM_CT_LEN: usize = sntrup761::CIPHERTEXT_SIZE; // 1039
pub const KEM_SS_LEN: usize = sntrup761::SHARED_SECRET_SIZE; // 32

#[derive(Clone)]
pub struct KemKeypair {
    pub ek: EncapsulationKey,
    pub dk: DecapsulationKey,
}

fn rng_seed() -> [u8; 32] {
    let mut s = [0u8; 32];
    OsRng.fill_bytes(&mut s);
    s
}

/// SNTRUP761 keypair (deterministic API fed by OsRng seed).
pub fn kem_keypair() -> KemKeypair {
    let (ek, dk) = sntrup761::generate_key_from_seed(rng_seed());
    KemKeypair { ek, dk }
}

/// Encapsulate against `ek`: returns (ciphertext bytes, shared secret).
pub fn kem_encaps(ek: &EncapsulationKey) -> (Vec<u8>, [u8; 32]) {
    let (ct, ss) = ek.encapsulate_deterministic(rng_seed());
    (ct.as_ref().to_vec(), ss.as_ref().try_into().unwrap_or([0u8; 32]))
}

/// Decapsulate: returns the shared secret (always succeeds; wrong ct => wrong key).
pub fn kem_decaps(dk: &DecapsulationKey, ct: &[u8]) -> Result<[u8; 32], EncodeError> {
    let ct = Ciphertext::try_from(ct).map_err(|e| EncodeError(format!("kem ct: {e}")))?;
    let ss: [u8; 32] = dk.decapsulate(&ct).as_ref().try_into().unwrap_or([0u8; 32]);
    Ok(ss)
}

/// KEMHybridSecret = SHA3-256(dh_secret || kem_shared_key)  (SNTRUP761.hs `kemHybridSecret`).
pub fn kem_hybrid_secret(dh: &[u8; 32], kem_ss: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(dh);
    h.update(kem_ss);
    h.finalize().into()
}

/// NaCl secretbox with the hybrid key used directly (kcbEncrypt/kcbDecrypt, NaCl mac||ct order).
pub fn kcb_encrypt(hybrid: &[u8; 32], nonce24: &[u8; 24], plaintext: &[u8]) -> Vec<u8> {
    raw_secretbox_encrypt(hybrid, nonce24, plaintext)
}
pub fn kcb_decrypt(hybrid: &[u8; 32], nonce24: &[u8; 24], nacl: &[u8]) -> Option<Vec<u8>> {
    raw_secretbox_decrypt(hybrid, nonce24, nacl)
}

// ---------- kemParams wire format ----------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KemParams {
    None,
    Pk(Vec<u8>),                 // "P" largeString(pk)
    CtPk(Vec<u8>, Vec<u8>),       // "A" largeString(ct) largeString(pk)
}

pub fn encode_kem_params(out: &mut Vec<u8>, kp: &KemParams) -> Result<(), EncodeError> {
    match kp {
        KemParams::None => out.push(b'0'),
        KemParams::Pk(pk) => {
            out.push(b'1');
            out.push(b'P');
            w_large(out, pk)?;
        }
        KemParams::CtPk(ct, pk) => {
            out.push(b'1');
            out.push(b'A');
            w_large(out, ct)?;
            w_large(out, pk)?;
        }
    }
    Ok(())
}

pub fn decode_kem_params(r: &mut Reader) -> Result<KemParams, EncodeError> {
    match r.u8()? {
        b'0' => Ok(KemParams::None),
        b'1' => match r.u8()? {
            b'P' => Ok(KemParams::Pk(r.large()?)),
            b'A' => {
                let ct = r.large()?;
                let pk = r.large()?;
                Ok(KemParams::CtPk(ct, pk))
            }
            c => Err(EncodeError(format!("kemParams tag {c:#x}"))),
        },
        c => Err(EncodeError(format!("kemParams {c:#x}"))),
    }
}

// re-export for tests
pub use sntrup761 as sntrup;
pub type KemSharedSecret = SharedSecret;

// ---------- e2eRatchetParams (agent-protocol.md) ----------
// e2eRatchetParams = e2eVersionRange e2eDhKey e2eDhKey kemParams
// e2eVersionRange = u16 min, u16 max ; e2eDhKey = shortString(SPKI DER)

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct E2eRatchetParams {
    pub v_min: u16,
    pub v_max: u16,
    pub snd_dh_spki: Vec<u8>,
    pub rcv_dh_spki: Vec<u8>,
    pub kem: KemParams,
}

pub fn encode_e2e_ratchet_params(out: &mut Vec<u8>, p: &E2eRatchetParams) -> Result<(), EncodeError> {
    w_u16(out, p.v_min);
    w_u16(out, p.v_max);
    w_short(out, &p.snd_dh_spki)?;
    w_short(out, &p.rcv_dh_spki)?;
    encode_kem_params(out, &p.kem)
}

pub fn decode_e2e_ratchet_params(r: &mut Reader) -> Result<E2eRatchetParams, EncodeError> {
    let v_min = r.u16()?;
    let v_max = r.u16()?;
    let snd_dh_spki = r.short()?;
    let rcv_dh_spki = r.short()?;
    let kem = decode_kem_params(r)?;
    Ok(E2eRatchetParams { v_min, v_max, snd_dh_spki, rcv_dh_spki, kem })
}
