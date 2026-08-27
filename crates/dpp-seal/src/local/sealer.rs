//! A real detached CMS `SignedData` over the payload digest, signed locally.
//!
//! # What this is, and what it is not
//!
//! It **is** a genuine CMS signature: the bytes verify against the certificate,
//! the structure is what a provider returns, and every stage of the pipeline
//! that handles a seal handles this one identically. The digest travels in
//! `signedAttrs`, as CAdES requires, so the envelope is self-checking — a holder
//! of the bytes alone can confirm the signature, which is what lets this backend
//! answer `verify()` when the hosted one cannot.
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

use async_trait::async_trait;
use base64::Engine as _;
use chrono::Utc;
use cms::cert::{CertificateChoices, IssuerAndSerialNumber};
use cms::content_info::ContentInfo;
use cms::signed_data::{
    CertificateSet, DigestAlgorithmIdentifiers, EncapsulatedContentInfo, SignedAttributes,
    SignedData, SignerIdentifier, SignerInfo, SignerInfos,
};
use const_oid::db::rfc5911::ID_DATA;
use der::{Any, Decode as _, Encode};
use dpp_domain::seal::{
    SealCapabilities, SealChecks, SealConformanceLevel, SealEnvelope, SealFormat, SealMode,
    SealRequest, SealVerification, SealedEnvelope,
};
use p256::ecdsa::{DerSignature, SigningKey};
use x509_cert::Certificate;
use x509_cert::attr::Attribute;

use crate::backend::SealBackend;
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
        // Detached: `eContent` is absent, so what was signed travels separately
        // from the signature — the arrangement a provider returns. The *digest*
        // does travel, in `signedAttrs` below; that is what detached CAdES does,
        // and it is the difference between a seal that can be checked and one
        // that cannot.
        let econtent = EncapsulatedContentInfo {
            econtent_type: ID_DATA,
            econtent: None,
        };

        let digest_algorithm = x509_cert::spki::AlgorithmIdentifierOwned {
            oid: const_oid::db::rfc5912::ID_SHA_256,
            parameters: None,
        };

        // Signed attributes carry the digest *inside* the signature, which is
        // what makes the seal checkable at all. With `signedAttrs` absent the
        // signature covers the digest directly, and a verifier holding only the
        // envelope — which is all `SealPort::verify` is given — has no way to
        // reconstruct what was signed. Attaching `messageDigest` is also what
        // CAdES requires, so this is the faithful shape rather than a
        // concession.
        let signed_attrs = signed_attributes(digest)?;

        // RFC 5652 §5.4: the signature is computed over the DER **SET OF**
        // encoding of the signed attributes, not over the `[0] IMPLICIT` form
        // they take inside `SignerInfo`. Encoding the wrong one produces a
        // signature that verifies nowhere, including here.
        let to_sign = signed_attrs
            .to_der()
            .map_err(|e| SealError::Config(format!("cannot encode the signed attributes: {e}")))?;
        let signature: DerSignature = self.key.sign(&to_sign);

        let signer_info = SignerInfo {
            version: cms::content_info::CmsVersion::V1,
            sid: SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
                issuer: self.cert.tbs_certificate.issuer.clone(),
                serial_number: self.cert.tbs_certificate.serial_number.clone(),
            }),
            digest_alg: digest_algorithm.clone(),
            signed_attrs: Some(signed_attrs),
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

#[async_trait]
impl SealBackend for LocalIdentity {
    async fn seal(&self, req: SealRequest) -> Result<SealedEnvelope, SealError> {
        let digest = hex::decode(&req.payload_hash)
            .map_err(|e| SealError::Config(format!("payload hash is not hex: {e}")))?;
        let der = self.sign_detached(&digest)?;

        Ok(SealedEnvelope {
            format: SealFormat::Cades,
            seal_value: base64::engine::general_purpose::STANDARD.encode(&der),
            signing_cert_ref: Some(self.cert_thumbprint()),
            sealed_at: Utc::now(),
            // Not a placeholder: these bytes verify. Legal standing is the trust
            // tier's business, not the envelope's.
            placeholder: false,
        })
    }

    fn capabilities(&self) -> SealCapabilities {
        // Real detached CAdES bytes. `OperatorSeal` because the certificate is
        // generated per node rather than held centrally on operators' behalf —
        // this backend rehearses the shape the hosted arrangement takes.
        SealCapabilities {
            supported_formats: vec![SealFormat::Cades],
            supported_modes: vec![SealMode::OperatorSeal],
            // `BaselineB` and no further, read off what `sign_detached`
            // actually emits: the signature alone. No signature timestamp
            // (`BaselineT`), no certificates or revocation data
            // (`BaselineLt`), no archival timestamp (`BaselineLta`). Claiming a
            // higher level would claim evidence these bytes do not carry — and
            // `BaselineB` is documented as not suiting a retention-locked
            // document, which is the honest position for a self-signed
            // development sealer.
            supported_levels: vec![SealConformanceLevel::BaselineB],
            // Detached: the signature travels beside the digest it covers and
            // never wraps it.
            supported_envelopes: vec![SealEnvelope::Detached],
        }
    }

    /// Overrides the refusing default, because this backend can answer honestly.
    ///
    /// The default exists so that no backend claims a verdict it did not
    /// compute, and the reason a hosted QTSP's seal cannot be answered here is
    /// independence: a verdict from the node that bought the seal attests
    /// nothing. Neither objection applies to this backend. Its seals make no
    /// trust claim at all beyond "this key signed this digest", so a
    /// cryptographic check *is* the whole truth about them, and there is no
    /// authority whose independence could be borrowed or faked.
    ///
    /// So a pass here is founded on [`SealChecks::SignatureOnly`] and says
    /// exactly what that documents — the signature was checked against the
    /// certificate carried inside the seal, and nothing else. No certificate
    /// path, no revocation, no timestamp, no Trusted List. It carries no legal
    /// weight, because the certificate is self-signed, and
    /// [`SealVerification::is_qualified_pass`] is false on it for that reason.
    /// The node says the same thing separately and structurally, by resolving
    /// this backend to the `Ghost` trust tier so a production profile refuses to
    /// boot on it.
    async fn verify(&self, env: &SealedEnvelope) -> Result<SealVerification, SealError> {
        use base64::engine::general_purpose::STANDARD as BASE64;

        // A placeholder envelope was never validated by anyone, so there is no
        // verdict to reach — reporting one either way would invent it.
        if env.placeholder {
            return Ok(SealVerification::placeholder(
                "placeholder envelope: no seal to validate",
            ));
        }

        let der = BASE64
            .decode(&env.seal_value)
            .map_err(|e| SealError::Backend(format!("seal value is not base64: {e}")))?;

        Ok(
            if crate::cades::verify_against_embedded_certificate(&der)? {
                SealVerification::passed(SealChecks::SignatureOnly)
            } else {
                SealVerification::failed(
                    SealChecks::SignatureOnly,
                    "signature does not verify against the certificate embedded in the seal",
                )
            },
        )
    }
}

/// The attributes the signature covers: what was signed, and its digest.
///
/// Two, both mandatory under RFC 5652 §11 for a signature carrying signed
/// attributes: `contentType`, and `messageDigest` holding the digest the caller
/// asked to seal. The second is the one that matters here — it is what puts the
/// sealed value inside the signature, so a holder of the bytes alone can check
/// them.
fn signed_attributes(digest: &[u8]) -> Result<SignedAttributes, SealError> {
    use der::asn1::{OctetString, SetOfVec};

    let attr = |oid, value: Any| -> Result<Attribute, SealError> {
        let mut values = SetOfVec::new();
        values
            .insert(value)
            .map_err(|e| SealError::Config(format!("cannot build a signed attribute: {e}")))?;
        Ok(Attribute { oid, values })
    };

    let content_type = attr(
        const_oid::db::rfc5911::ID_CONTENT_TYPE,
        Any::encode_from(&ID_DATA)
            .map_err(|e| SealError::Config(format!("cannot encode the content type: {e}")))?,
    )?;
    let message_digest = attr(
        const_oid::db::rfc5911::ID_MESSAGE_DIGEST,
        Any::encode_from(
            &OctetString::new(digest)
                .map_err(|e| SealError::Config(format!("cannot encode the digest: {e}")))?,
        )
        .map_err(|e| SealError::Config(format!("cannot encode the digest attribute: {e}")))?,
    )?;

    let mut attrs = SetOfVec::new();
    for a in [content_type, message_digest] {
        attrs
            .insert(a)
            .map_err(|e| SealError::Config(format!("cannot collect signed attributes: {e}")))?;
    }
    Ok(attrs)
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
    use dpp_domain::seal::SealIndication;

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
        let (id, _dir) = identity();
        let der = id.sign_detached(&[0x7u8; 32]).expect("sign");

        // Checked through the same function production uses, which is handed
        // bytes and nothing else — the identity in memory is not consulted.
        assert!(
            crate::cades::verify_against_embedded_certificate(&der)
                .expect("the seal is well-formed"),
            "the seal must verify against the certificate it ships"
        );
    }

    /// The seal commits to the digest it was asked to seal, not to some other.
    ///
    /// `cades::verify_against_embedded_certificate` proves the signature covers the signed attributes; this
    /// proves the signed attributes carry the right value. Without it the
    /// backend could sign a constant attribute set perfectly and attest nothing
    /// about the passport — internally valid, externally meaningless.
    #[test]
    fn the_signed_attributes_carry_the_requested_digest() {
        use der::asn1::OctetString;

        let (id, _dir) = identity();
        let digest = [0x5u8; 32];
        let der = id.sign_detached(&digest).expect("sign");

        let info = ContentInfo::from_der(&der).expect("ContentInfo");
        let sd: cms::signed_data::SignedData = info.content.decode_as().expect("SignedData");
        let si = sd.signer_infos.0.as_slice().first().expect("one signer");
        let attrs = si.signed_attrs.as_ref().expect("signed attributes present");

        let found = attrs
            .as_slice()
            .iter()
            .find(|a| a.oid == const_oid::db::rfc5911::ID_MESSAGE_DIGEST)
            .expect("a messageDigest attribute");
        let carried: OctetString = found
            .values
            .as_slice()
            .first()
            .expect("one value")
            .decode_as()
            .expect("an OCTET STRING");

        assert_eq!(
            carried.as_bytes(),
            digest,
            "the seal must commit to the digest it was handed"
        );
    }

    /// A tampered seal does not verify.
    ///
    /// The check that makes the others mean something: if flipping a byte of the
    /// signature still verified, `cades::verify_against_embedded_certificate` would be reporting a constant
    /// rather than performing a check.
    #[test]
    fn a_tampered_signature_does_not_verify() {
        let (id, _dir) = identity();
        let der = id.sign_detached(&[0x9u8; 32]).expect("sign");

        // Flip a byte deep inside the structure. Some positions corrupt the DER
        // and produce a parse error rather than `false`; both are refusals, and
        // neither may be a pass.
        let mut tampered = der.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0xff;

        assert!(
            !matches!(
                crate::cades::verify_against_embedded_certificate(&tampered),
                Ok(true)
            ),
            "a tampered seal must never verify"
        );
    }

    /// A seal with no signed attributes is refused, not called invalid.
    ///
    /// The digest is not inside such a seal, so nothing can be checked from the
    /// envelope alone. Reporting `valid: false` would brand it broken on the
    /// strength of a check that never ran — the distinction this crate exists to
    /// keep.
    #[test]
    fn a_seal_without_signed_attributes_is_refused() {
        let (id, _dir) = identity();
        let der = id.sign_detached(&[0x1u8; 32]).expect("sign");

        let info = ContentInfo::from_der(&der).expect("ContentInfo");
        let mut sd: cms::signed_data::SignedData = info.content.decode_as().expect("SignedData");
        let mut signers = sd.signer_infos.0.as_slice().to_vec();
        signers[0].signed_attrs = None;
        let mut rebuilt = der::asn1::SetOfVec::new();
        rebuilt.insert(signers.remove(0)).expect("one signer");
        sd.signer_infos = SignerInfos::from(rebuilt);

        let stripped = ContentInfo {
            content_type: const_oid::db::rfc5911::ID_SIGNED_DATA,
            content: Any::encode_from(&sd).expect("re-encode"),
        }
        .to_der()
        .expect("DER");

        let err = crate::cades::verify_against_embedded_certificate(&stripped)
            .expect_err("must refuse rather than answer");
        assert!(err.to_string().contains("signed attributes"), "{err}");
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

    fn seal_request(payload_hash: &str) -> SealRequest {
        SealRequest {
            payload_hash: payload_hash.to_owned(),
            mode: SealMode::OperatorSeal,
            key_ref: dpp_domain::seal::SealCredentialRef {
                qtsp_id: "local".into(),
                credential_id: "dev".into(),
            },
            sig_format: SealFormat::Cades,
            // The only level this backend claims: a bare signature, detached.
            conformance_level: SealConformanceLevel::BaselineB,
            envelope: SealEnvelope::Detached,
        }
    }

    /// The envelope this backend hands the port carries the real signature and
    /// says so.
    ///
    /// `placeholder: false` is the load-bearing field: the drain, the trust
    /// report and the passport all read it, and marking these bytes as a
    /// placeholder would hide a seal that genuinely verifies — while marking a
    /// ghost's bytes as real would do far worse.
    #[tokio::test]
    async fn the_envelope_carries_the_signature_and_the_certificate() {
        use base64::engine::general_purpose::STANDARD as BASE64;

        let (id, _dir) = identity();
        let digest = [0x33u8; 32];
        let env = SealBackend::seal(&id, seal_request(&hex::encode(digest)))
            .await
            .expect("the local backend seals");

        assert_eq!(env.format, SealFormat::Cades);
        assert!(!env.placeholder, "these bytes verify — they are not a stub");
        assert_eq!(
            env.signing_cert_ref.as_deref(),
            Some(id.cert_thumbprint().as_str()),
            "the envelope must name the certificate that signed it"
        );

        // The seal value is the base64 of the same CMS the direct path produces.
        let der = BASE64.decode(&env.seal_value).expect("base64 seal value");
        ContentInfo::from_der(&der).expect("a CMS ContentInfo");
        assert_eq!(der, id.sign_detached(&digest).expect("sign"));
    }

    /// Seal, then verify, through the port — the round trip an operator gets.
    ///
    /// Every other test here reaches into the structure. This one only uses what
    /// a caller has: a request in, an envelope out, and that envelope back in.
    /// It is the whole point of a development backend — the pipeline is
    /// exercised end to end without a provider account.
    #[tokio::test]
    async fn a_sealed_envelope_verifies_through_the_port() {
        let (id, _dir) = identity();
        let digest = hex::encode([0x2Au8; 32]);

        let env = SealBackend::seal(&id, seal_request(&digest))
            .await
            .expect("seal");
        let verdict = SealBackend::verify(&id, &env).await.expect("verify");

        assert_eq!(
            verdict.indication,
            SealIndication::TotalPassed,
            "a seal this backend just produced must verify"
        );
        assert_eq!(
            verdict.checks,
            SealChecks::SignatureOnly,
            "and must say that a signature check is all it rests on"
        );
        assert!(
            !verdict.placeholder,
            "these bytes are real; only the trust behind them is absent"
        );
        assert!(
            !verdict.is_qualified_pass(),
            "a self-signed development seal is never a qualified pass"
        );
    }

    /// A seal whose value was altered in storage fails the round trip.
    ///
    /// Without this, `a_sealed_envelope_verifies_through_the_port` would pass
    /// against a `verify` that returned `true` unconditionally.
    #[tokio::test]
    async fn a_corrupted_envelope_does_not_verify_through_the_port() {
        use base64::engine::general_purpose::STANDARD as BASE64;

        let (id, _dir) = identity();
        let mut env = SealBackend::seal(&id, seal_request(&hex::encode([0x2Au8; 32])))
            .await
            .expect("seal");

        let mut raw = BASE64.decode(&env.seal_value).expect("base64");
        let last = raw.len() - 1;
        raw[last] ^= 0xff;
        env.seal_value = BASE64.encode(&raw);

        let verdict = SealBackend::verify(&id, &env).await;
        assert!(
            !matches!(
                verdict.map(|v| v.indication),
                Ok(SealIndication::TotalPassed)
            ),
            "a corrupted seal must never verify"
        );
    }

    /// A digest that is not hex fails before any signing happens.
    #[tokio::test]
    async fn a_payload_hash_that_is_not_hex_is_refused() {
        let (id, _dir) = identity();
        let err = SealBackend::seal(&id, seal_request("not-a-digest"))
            .await
            .expect_err("a malformed digest must not be signed over");
        assert!(err.to_string().contains("not hex"), "{err}");
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
