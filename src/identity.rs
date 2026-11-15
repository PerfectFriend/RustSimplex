//! Router identity: self-signed 2-cert chain (offline + online, both Ed25519),
//! matching simplexmq's router certificate model. Router identity (keyHash) =
//! SHA-256 of the offline certificate's SPKI DER — this is the `smp://` address key.

use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, PKCS_ED25519,
};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};

use crate::crypto::{base64url_nopad, sha256};

#[derive(Clone)]
pub struct RouterIdentity {
    pub key_hash: [u8; 32],
    pub offline_der: Vec<u8>,
    pub online_der: Vec<u8>,
    pub online_key_pkcs8: Vec<u8>,
}

impl RouterIdentity {
    /// Generate a fresh router identity for `host`.
    pub fn generate(host: &str) -> Result<RouterIdentity, String> {
        // offline (root) CA cert — self-signed, owns the offline signing key
        let offline_kp = KeyPair::generate_for(&PKCS_ED25519).map_err(|e| e.to_string())?;
        let mut off =
            CertificateParams::new(vec!["simplex-offline".to_string()]).map_err(|e| e.to_string())?;
        off.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        off.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::DigitalSignature];
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "simplex-rs offline router");
        off.distinguished_name = dn;
        let ca = CertifiedIssuer::self_signed(off, offline_kp).map_err(|e| e.to_string())?;
        let offline_der = ca.der().to_vec();
        // keyHash = SHA-256 of the FULL offline CA certificate DER (x509 getFingerprint HashSHA256)
        let key_hash = sha256(&offline_der);

        // online (leaf) cert — signed by the offline CA, ServerAuth, SAN = host
        let online_kp = KeyPair::generate_for(&PKCS_ED25519).map_err(|e| e.to_string())?;
        let mut on = CertificateParams::new(vec![host.to_string()]).map_err(|e| e.to_string())?;
        let mut dn2 = DistinguishedName::new();
        dn2.push(DnType::CommonName, host);
        on.distinguished_name = dn2;
        on.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        on.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let online_cert = on.signed_by(&online_kp, &ca).map_err(|e| e.to_string())?;
        let online_der = online_cert.der().to_vec();
        let online_key_pkcs8 = online_kp.serialize_der();

        Ok(RouterIdentity {
            key_hash,
            offline_der,
            online_der,
            online_key_pkcs8,
        })
    }

    pub fn cert_chain(&self) -> Vec<CertificateDer<'static>> {
        vec![
            CertificateDer::from(self.online_der.clone()),
            CertificateDer::from(self.offline_der.clone()),
        ]
    }
    pub fn private_key(&self) -> PrivatePkcs8KeyDer<'static> {
        PrivatePkcs8KeyDer::from(self.online_key_pkcs8.clone())
    }
    /// smp://<keyHashB64>@<host>:<port>
    pub fn address(&self, host: &str, port: u16) -> String {
        format!(
            "smp://{}@{}:{}",
            base64url_nopad(&self.key_hash),
            host,
            port
        )
    }
}

/// Fingerprint of a certificate = SHA-256 of its full DER (matches x509 `getFingerprint` HashSHA256,
/// which is what simplexmq puts in the `smp://` keyHash). Used by the client to pin the router.
pub fn cert_fingerprint(cert_der: &[u8]) -> [u8; 32] {
    sha256(cert_der)
}
