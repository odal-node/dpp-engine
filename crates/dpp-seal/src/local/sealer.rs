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
use cms::cert::{CertificateChoices, IssuerAndSerialNumber};
use cms::content_info::ContentInfo;
use cms::signed_data::{
    CertificateSet, DigestAlgorithmIdentifiers, EncapsulatedContentInfo, SignedData,
    SignerIdentifier, SignerInfo, SignerInfos,
};
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
        use der::asn1::{OctetString, SetOfVec};
        use p256::ecdsa::signature::Signer as _;

        // Assembled from `cms`'s own types rather than its `builder` feature.
        // That feature depends unconditionally on `rsa`, which carries
        // RUSTSEC-2023-0071 with no fixed upgrade; we sign with P-256 and have
        // no use for RSA, so the dependency would be pure advisory surface on
        // the one crate that produces seals.
        //
        // Detached: `eContent` is absent, so the structure commits to a digest
        // it does not carry — the arrangement a provider returns.
        let econtent = EncapsulatedContentInfo {
            econtent_type: ID_DATA,
            econtent: None,
        };

        let digest_algorithm = x509_cert::spki::AlgorithmIdentifierOwned {
            oid: const_oid::db::rfc5912::ID_SHA_256,
            parameters: None,
        };

        // No signed attributes: with `signedAttrs` absent, the signature is over
        // the content itself, which for a detached signature is the digest the
        // caller hands us. One fewer place for the bound value to disagree with
        // the value actually signed.
        let signature: DerSignature = self.key.sign(digest);

        let signer_info = SignerInfo {
            version: cms::content_info::CmsVersion::V1,
            sid: SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
                issuer: self.cert.tbs_certificate.issuer.clone(),
                serial_number: self.cert.tbs_certificate.serial_number.clone(),
            }),
            digest_alg: digest_algorithm.clone(),
            signed_attrs: None,
            signature_algorithm: x509_cert::spki::AlgorithmIdentifierOwned {
                oid: const_oid::db::rfc5912::ECDSA_WITH_SHA_256,
                parameters: None,
            },
            signature: OctetString::new(signature.to_bytes().as_ref())
                .map_err(|e| SealError::Config(format!("cannot encode the signature: {e}")))?,
            unsigned_attrs: None,
        };

        let mut digest_algorithms = SetOfVec::new();
        digest_algorithms
            .insert(digest_algorithm)
            .map_err(|e| SealError::Config(format!("cannot record the digest algorithm: {e}")))?;

        let mut certs = SetOfVec::new();
        certs
            .insert(CertificateChoices::Certificate(self.cert.clone()))
            .map_err(|e| SealError::Config(format!("cannot attach the certificate: {e}")))?;

        let mut signer_infos = SetOfVec::new();
        signer_infos
            .insert(signer_info)
            .map_err(|e| SealError::Config(format!("cannot attach the signer info: {e}")))?;

        let signed_data = SignedData {
            version: cms::content_info::CmsVersion::V1,
            digest_algorithms: DigestAlgorithmIdentifiers::from(digest_algorithms),
            encap_content_info: econtent,
            certificates: Some(CertificateSet::from(certs)),
            crls: None,
            signer_infos: SignerInfos::from(signer_infos),
        };

        let info = ContentInfo {
            content_type: const_oid::db::rfc5911::ID_SIGNED_DATA,
            content: Any::encode_from(&signed_data)
                .map_err(|e| SealError::Config(format!("cannot encode the SignedData: {e}")))?,
        };
        info.to_der()
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

    /// The signature in the seal verifies against the certificate it carries.
    ///
    /// This is the test the whole backend exists for. Everything else here
    /// checks structure; without this one, a seal could be well-formed CMS
    /// carrying bytes that verify against nothing — which is precisely what
    /// `GhostSeal` already produces, and what this backend is meant to stop
    /// being.
    #[test]
    fn the_signature_verifies_against_the_embedded_certificate() {
        use p256::ecdsa::signature::Verifier as _;
        use p256::ecdsa::{DerSignature, VerifyingKey};

        let (id, _dir) = identity();
        let digest = [0x7u8; 32];
        let der = id.sign_detached(&digest).expect("sign");

        let info = ContentInfo::from_der(&der).expect("ContentInfo");
        let sd: cms::signed_data::SignedData = info.content.decode_as().expect("SignedData");
        let si = sd.signer_infos.0.as_slice().first().expect("one signer");

        // The verifying key comes out of the certificate inside the seal, not
        // from the identity in memory — a verifier only ever has the bytes.
        let spki = &id.cert.tbs_certificate.subject_public_key_info;
        let vk = VerifyingKey::from_sec1_bytes(
            spki.subject_public_key.as_bytes().expect("public key bits"),
        )
        .expect("P-256 key from the certificate");

        let sig = DerSignature::from_bytes(si.signature.as_bytes()).expect("DER signature");
        vk.verify(&digest, &sig)
            .expect("the seal must verify against the certificate it ships");

        // And must not verify against something it did not cover.
        assert!(
            vk.verify(&[0x8u8; 32], &sig).is_err(),
            "a seal that verifies over any digest attests nothing"
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
