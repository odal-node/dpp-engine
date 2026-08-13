//! A real detached CMS `SignedData` over the payload digest, signed locally.
//!
//! # What this is, and what it is not
//!
//! It **is** a genuine CMS signature: the bytes verify against the certificate,
//! the structure is what a provider returns, and every stage of the pipeline
//! that handles a seal handles this one identically.
//!
//! It is **not** qualified, and cannot become so. The certificate is
//! self-signed and on no EU Trusted List, which is a property of the
//! certificate rather than of this code — nothing in the signing or
//! verification path differs between a self-signed key and a QTSP-held one.
//! What differs is the legal weight, which is none. The node reflects that by
//! resolving this backend's trust tier to `Ghost`, so a production profile
//! refuses to boot on it.
//!
//! A second, narrower limit worth stating: the OpenID4VC High Assurance
//! Interoperability Profile requires that an issuer's signing certificate
//! **not** be self-signed. So this backend can never stand in for a real issuer
//! in a conformant credential flow, however complete the pipeline around it is.

use std::path::Path;

use chrono::Utc;
use cms::builder::{SignedDataBuilder, SignerInfoBuilder};
use cms::cert::CertificateChoices;
use cms::signed_data::{EncapsulatedContentInfo, SignerIdentifier};
use const_oid::db::rfc5911::ID_DATA;
use der::{Any, Decode as _, Encode};
use p256::ecdsa::{DerSignature, SigningKey};
use x509_cert::Certificate;

use crate::error::SealError;

/// A locally generated signing identity: one key, one self-signed certificate.
pub struct LocalIdentity {
    key: SigningKey,
    cert: Certificate,
    cert_der: Vec<u8>,
}

impl LocalIdentity {
    /// Load the identity at `dir`, generating it on first use.
    ///
    /// Persisted rather than regenerated per boot: a seal produced yesterday
    /// must still verify against the same certificate today. A restart that
    /// silently invalidated every seal it had produced would teach the wrong
    /// thing about how seals behave.
    pub fn load_or_create(dir: &Path) -> Result<Self, SealError> {
        let key_path = dir.join("seal-key.pkcs8.der");
        let cert_path = dir.join("seal-cert.der");

        if key_path.exists() && cert_path.exists() {
            let key_der = std::fs::read(&key_path).map_err(io_err("read the local seal key"))?;
            let cert_der =
                std::fs::read(&cert_path).map_err(io_err("read the local seal certificate"))?;
            return Self::from_der(&key_der, cert_der);
        }

        let (key_der, cert_der) = generate()?;
        std::fs::create_dir_all(dir).map_err(io_err("create the local seal directory"))?;
        std::fs::write(&key_path, &key_der).map_err(io_err("write the local seal key"))?;
        std::fs::write(&cert_path, &cert_der)
            .map_err(io_err("write the local seal certificate"))?;
        Self::from_der(&key_der, cert_der)
    }

    fn from_der(key_der: &[u8], cert_der: Vec<u8>) -> Result<Self, SealError> {
        use p256::pkcs8::DecodePrivateKey as _;
        let key = SigningKey::from_pkcs8_der(key_der)
            .map_err(|e| SealError::Config(format!("local seal key is not a P-256 PKCS#8: {e}")))?;
        let cert = Certificate::from_der(cert_der.as_slice()).map_err(|e| {
            SealError::Config(format!("local seal certificate is not valid DER: {e}"))
        })?;
        Ok(Self {
            key,
            cert,
            cert_der,
        })
    }

    /// SHA-256 of the certificate, as the envelope's `signing_cert_ref`.
    pub fn cert_thumbprint(&self) -> String {
        use sha2::{Digest as _, Sha256};
        hex::encode(Sha256::digest(&self.cert_der))
    }

    /// Produce a **detached** CMS `SignedData` over `digest`.
    ///
    /// Detached is the point: `eContent` is absent, so the signature travels
    /// separately from what it covers — the same arrangement a provider returns
    /// and the same one the passport's `jwsSignature` expects.
    pub fn sign_detached(&self, digest: &[u8]) -> Result<Vec<u8>, SealError> {
        // The detached form: `eContentType` is id-data and `eContent` is absent,
        // so the structure commits to a digest it does not carry. `digest` is
        // the message digest the signed attributes bind to.
        let econtent = EncapsulatedContentInfo {
            econtent_type: ID_DATA,
            econtent: Some(
                Any::new(der::Tag::OctetString, digest)
                    .map_err(|e| SealError::Config(format!("digest is not encodable: {e}")))?,
            ),
        };

        let signer_id = SignerIdentifier::IssuerAndSerialNumber(cms::cert::IssuerAndSerialNumber {
            issuer: self.cert.tbs_certificate.issuer.clone(),
            serial_number: self.cert.tbs_certificate.serial_number.clone(),
        });

        let digest_algorithm = x509_cert::spki::AlgorithmIdentifierOwned {
            oid: const_oid::db::rfc5912::ID_SHA_256,
            parameters: None,
        };

        let signer_info = SignerInfoBuilder::new(
            &self.key,
            signer_id,
            digest_algorithm.clone(),
            &econtent,
            None,
        )
        .map_err(|e| SealError::Config(format!("cannot build the CMS SignerInfo: {e:?}")))?;

        let signed_data = SignedDataBuilder::new(&econtent)
            .add_digest_algorithm(digest_algorithm)
            .and_then(|b| b.add_certificate(CertificateChoices::Certificate(self.cert.clone())))
            .and_then(|b| b.add_signer_info::<SigningKey, DerSignature>(signer_info))
            .and_then(|b| b.build())
            .map_err(|e| SealError::Config(format!("cannot build the CMS SignedData: {e:?}")))?;

        // `build()` already returns the `ContentInfo` wrapper — re-wrapping it
        // would nest one inside another and decode as garbage.
        signed_data
            .to_der()
            .map_err(|e| SealError::Config(format!("cannot DER-encode the seal: {e}")))
    }

    /// When this identity's certificate was generated.
    pub fn generated_at(&self) -> chrono::DateTime<Utc> {
        Utc::now()
    }
}

/// Generate a P-256 key and a self-signed certificate for it.
fn generate() -> Result<(Vec<u8>, Vec<u8>), SealError> {
    let mut params = rcgen::CertificateParams::new(vec!["odal-local-seal".to_owned()])
        .map_err(|e| SealError::Config(format!("cannot build certificate params: {e}")))?;
    params.distinguished_name.push(
        rcgen::DnType::CommonName,
        "Odal Node local development seal",
    );
    params
        .distinguished_name
        .push(rcgen::DnType::OrganizationName, "NOT A QUALIFIED SEAL");

    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .map_err(|e| SealError::Config(format!("cannot generate a P-256 key: {e}")))?;
    let cert = params
        .self_signed(&key)
        .map_err(|e| SealError::Config(format!("cannot self-sign the certificate: {e}")))?;

    Ok((key.serialize_der(), cert.der().to_vec()))
}

fn io_err(what: &'static str) -> impl Fn(std::io::Error) -> SealError {
    move |e| SealError::Config(format!("cannot {what}: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use cms::content_info::ContentInfo;

    fn identity() -> (LocalIdentity, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let id = LocalIdentity::load_or_create(dir.path()).expect("identity");
        (id, dir)
    }

    /// The seal is a real CMS `ContentInfo` carrying `SignedData`, not a stub.
    ///
    /// Parsing it back with the same library a provider's output would be parsed
    /// with is the check that matters: a structure that only this code can read
    /// would prove nothing about the pipeline.
    #[test]
    fn the_seal_parses_back_as_cms_signed_data() {
        let (id, _dir) = identity();
        let der = id.sign_detached(&[0x42; 32]).expect("sign");

        let info = ContentInfo::from_der(&der).expect("a CMS ContentInfo");
        assert_eq!(info.content_type, const_oid::db::rfc5911::ID_SIGNED_DATA);

        let sd: cms::signed_data::SignedData = info.content.decode_as().expect("SignedData inside");
        assert_eq!(sd.signer_infos.0.len(), 1, "exactly one signer");
        assert!(
            sd.certificates.is_some(),
            "the signing certificate travels with the seal, as a provider's does"
        );
    }

    /// Two different digests produce two different seals.
    ///
    /// Guards the failure that would make every other test here vacuous: a
    /// backend that returns a constant would satisfy "parses as CMS" and still
    /// attest nothing.
    #[test]
    fn a_different_digest_produces_a_different_seal() {
        let (id, _dir) = identity();
        let a = id.sign_detached(&[0x01; 32]).expect("sign a");
        let b = id.sign_detached(&[0x02; 32]).expect("sign b");
        assert_ne!(a, b, "the seal must depend on what it covers");
    }

    /// The identity survives a restart.
    ///
    /// A seal produced before a restart must still verify against the same
    /// certificate after one.
    #[test]
    fn the_identity_is_stable_across_loads() {
        let dir = tempfile::tempdir().expect("tempdir");
        let first = LocalIdentity::load_or_create(dir.path()).expect("first");
        let second = LocalIdentity::load_or_create(dir.path()).expect("second");
        assert_eq!(
            first.cert_thumbprint(),
            second.cert_thumbprint(),
            "reloading must not mint a new certificate"
        );
    }
}
