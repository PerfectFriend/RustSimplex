//! X3DH (X25519 variant) initial key agreement — **dual-mode handshake** (ADR D1(a), 2026-11-26).
//!
//! Stock SimpleX Chat uses X3DH/X448 for the first E2E key agreement; PQDR remains our
//! default ratchet. This module provides the X3DH *primitive* so a stock-compatible
//! peer can derive the same 32-byte seed that then feeds the ratchet (wire-parity of
//! the full agent protocol is a follow-up after D1).
//!
//! Construction (Signal X3DH adapted to X25519):
//!   DH1 = DH(IKa, SPKb)   DH2 = DH(EKa, IKb)   DH3 = DH(EKa, SPKb)   DH4 = DH(EKa, OPKb)?
//!   SK  = SHA-512(DH1 || DH2 || DH3 [|| DH4])[:32]
//! SPK is signed by the long-term Ed25519 identity key and verified on receipt.
//! Every DH goes through `x25519_dh_checked` — low-order/non-contributory public
//! keys are rejected (U-07), never silently accepted.

use crate::crypto::{
    ed25519_keypair, ed25519_sign, ed25519_verify, x25519_dh_checked, x25519_keypair, x25519_public,
    Ed25519Keypair, X25519Keypair, SIG_LEN,
};
use sha2::{Digest, Sha512};

/// Long-term X3DH identity: Ed25519 signing key + X25519 identity DH key + prekeys.
pub struct X3dhIdentity {
    pub ik_ed: Ed25519Keypair,
    pub ik_x: X25519Keypair,
    pub spk: X25519Keypair,
    pub spk_sig: [u8; SIG_LEN],
    pub opks: Vec<X25519Keypair>,
}

impl X3dhIdentity {
    pub fn new() -> Self {
        let ik_ed = ed25519_keypair();
        let ik_x = x25519_keypair();
        let spk = x25519_keypair();
        let spk_sig = ed25519_sign(&ik_ed, &spk.public.to_bytes());
        X3dhIdentity { ik_ed, ik_x, spk, spk_sig, opks: Vec::new() }
    }

    /// Publishable prekey bundle (what a peer downloads before initiating).
    pub fn bundle(&self, opk: Option<&X25519Keypair>) -> PreKeyBundle {
        PreKeyBundle {
            ik_ed_pub: self.ik_ed.verifying.to_bytes(),
            ik_x_pub: self.ik_x.public.to_bytes(),
            spk_pub: self.spk.public.to_bytes(),
            spk_sig: self.spk_sig,
            opk_pub: opk.map(|k| k.public.to_bytes()),
        }
    }
}

impl Default for X3dhIdentity {
    fn default() -> Self {
        Self::new()
    }
}

/// What the initiator downloads from the responder.
pub struct PreKeyBundle {
    pub ik_ed_pub: [u8; 32],
    pub ik_x_pub: [u8; 32],
    pub spk_pub: [u8; 32],
    pub spk_sig: [u8; SIG_LEN],
    pub opk_pub: Option<[u8; 32]>,
}

/// First message from initiator to responder (carried inside the SMP/agent handshake).
pub struct X3dhInitiatorMsg {
    pub ik_ed_pub: [u8; 32],
    pub ik_x_pub: [u8; 32],
    pub ek_pub: [u8; 32],
    pub opk_pub: Option<[u8; 32]>,
}

fn derive(dhs: &[[u8; 32]]) -> [u8; 32] {
    let mut h = Sha512::new();
    for d in dhs {
        h.update(d);
    }
    let out = h.finalize();
    let mut sk = [0u8; 32];
    sk.copy_from_slice(&out[..32]);
    sk
}

/// Initiator side: returns (SK, first message). Verifies the responder's SPK signature.
pub fn x3dh_initiate(
    own: &X3dhIdentity,
    ek: &X25519Keypair,
    b: &PreKeyBundle,
) -> Result<([u8; 32], X3dhInitiatorMsg), String> {
    if !ed25519_verify(&b.ik_ed_pub, &b.spk_pub, &b.spk_sig) {
        return Err("x3dh: bad SPK signature".into());
    }
    let dh1 = x25519_dh_checked(&own.ik_x.secret, &x25519_public(b.spk_pub))?;
    let dh2 = x25519_dh_checked(&ek.secret, &x25519_public(b.ik_x_pub))?;
    let dh3 = x25519_dh_checked(&ek.secret, &x25519_public(b.spk_pub))?;
    let mut dhs = vec![dh1, dh2, dh3];
    if let Some(opk) = b.opk_pub {
        dhs.push(x25519_dh_checked(&ek.secret, &x25519_public(opk))?);
    }
    let sk = derive(&dhs);
    Ok((sk, X3dhInitiatorMsg {
        ik_ed_pub: own.ik_ed.verifying.to_bytes(),
        ik_x_pub: own.ik_x.public.to_bytes(),
        ek_pub: ek.public.to_bytes(),
        opk_pub: b.opk_pub,
    }))
}

/// Responder side: `opk_idx` selects which one-time prekey the initiator used.
pub fn x3dh_respond(
    id: &X3dhIdentity,
    opk_idx: Option<usize>,
    m: &X3dhInitiatorMsg,
) -> Result<[u8; 32], String> {
    let dh1 = x25519_dh_checked(&id.spk.secret, &x25519_public(m.ik_x_pub))?;
    let dh2 = x25519_dh_checked(&id.ik_x.secret, &x25519_public(m.ek_pub))?;
    let dh3 = x25519_dh_checked(&id.spk.secret, &x25519_public(m.ek_pub))?;
    let mut dhs = vec![dh1, dh2, dh3];
    if let Some(i) = opk_idx {
        let opk = id.opks.get(i).ok_or("x3dh: opk index out of range")?;
        if m.opk_pub != Some(opk.public.to_bytes()) {
            return Err("x3dh: opk mismatch".into());
        }
        dhs.push(x25519_dh_checked(&opk.secret, &x25519_public(m.ek_pub))?);
    }
    Ok(derive(&dhs))
}
