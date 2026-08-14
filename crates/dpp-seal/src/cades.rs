//! Reading what a detached CAdES says about itself.
//!
//! Shared by the backends because the parsing is plain CMS and belongs to
//! neither: a backend module may not reach into another's, and duplicating
//! ASN.1 handling across two of them is how the two quietly stop agreeing about
//! what a seal contains.
//!
//! # Everything here is *reported*, never *verified*
//!
//! This module reads a structure. It builds no certificate chain, contacts no
//! Trusted List, and checks no revocation — so a certificate it names is the one
//! the seal **claims** signed it, on the seal's own word. For a qualified seal
//! that claim is worth checking and this module cannot check it; establishing
//! that the certificate was qualified, and current, at the moment of sealing is
//! an independent AdES validator's job.
//!
//! The distinction is the whole reason this is a separate module with its own
//! vocabulary. A convenience field that reads as verification while verifying
//! nothing is worse than an absent one, because an absent field prompts the
//! question and a populated one settles it wrongly.

use cms::cert::CertificateChoices;
use cms::content_info::ContentInfo;
use cms::signed_data::{SignedData, SignerInfo};
use der::{Decode as _, Encode as _};
use x509_cert::Certificate;

use crate::error::SealError;

fn malformed(what: impl std::fmt::Display) -> SealError {
    SealError::Backend(format!("cannot read the seal: {what}"))
}

/// The one signer and the certificate it travels with.
struct Signed {
    signer: SignerInfo,
    certificate: Certificate,
}

/// Parse a detached CMS `SignedData` down to its single signer and certificate.
///
/// One signer is not a simplification: this crate sends one digest per request
/// and a response bearing more than one signature does not answer the request
/// that was made. Reaching into `[0]` and hoping would turn that into a silent
/// mismatch.
fn parse(seal_der: &[u8]) -> Result<Signed, SealError> {
    let info = ContentInfo::from_der(seal_der).map_err(|e| malformed(format!("not CMS: {e}")))?;
    let sd: SignedData = info
        .content
        .decode_as()
        .map_err(|e| malformed(format!("not SignedData: {e}")))?;

    let signers = sd.signer_infos.0.as_slice();
    let [signer] = signers else {
        return Err(malformed(format!(
            "expected exactly one signer, found {}",
            signers.len()
        )));
    };

    let certs = sd
        .certificates
        .as_ref()
        .ok_or_else(|| malformed("it carries no certificate"))?;
    let Some(CertificateChoices::Certificate(certificate)) = certs.0.as_slice().first() else {
        return Err(malformed("it carries no X.509 certificate"));
    };

    Ok(Signed {
        signer: signer.clone(),
        certificate: certificate.clone(),
    })
}

/// Hex SHA-256 over the DER of the certificate the seal carries.
///
/// **Reported by the seal, not verified.** This identifies *which* certificate
/// the seal names, so an auditor can ask whether it was on the EU Trusted List
/// at the sealing time without first being handed the `.p7s` and parsing it.
/// Answering that question is the validator's job, not this function's.
///
/// A thumbprint rather than issuer+serial or a subject key identifier: it is one
/// fixed-length value that names exactly one certificate, needs no parsing to
/// compare, and is what the local backend already reports — so the two backends
/// put the same kind of thing in the same field.
///
/// `Ok(None)` when the bytes are not a seal this module can read. A seal that
/// arrived and stored fine must not be lost to a parse failure on a convenience
/// field, so the caller degrades to an unpopulated reference rather than failing
/// the seal.
pub fn signer_certificate_thumbprint(seal_der: &[u8]) -> Result<Option<String>, SealError> {
    use sha2::{Digest as _, Sha256};

    let Ok(signed) = parse(seal_der) else {
        return Ok(None);
    };
    let der = signed
        .certificate
        .to_der()
        .map_err(|e| malformed(format!("cannot re-encode the certificate: {e}")))?;
    Ok(Some(hex::encode(Sha256::digest(&der))))
}

/// Check the signature against the certificate the seal carries.
///
/// A `true` means the signature over the signed attributes verifies under the
/// public key in the certificate travelling inside the seal — the structure is
/// internally consistent. It says **nothing** about trust: no chain was built and
/// no authority was consulted. Whether that is the whole truth about a seal or
/// only a fragment of it depends on the certificate, which is why the decision to
/// report it as a verdict belongs to the backend rather than here.
///
/// Only P-256 is understood, which is what this crate's local backend produces.
pub fn verify_against_embedded_certificate(seal_der: &[u8]) -> Result<bool, SealError> {
    use p256::ecdsa::VerifyingKey;
    use p256::ecdsa::signature::Verifier as _;

    let signed = parse(seal_der)?;

    // Absent signed attributes means the digest is not inside the seal, so
    // nothing can be checked without the original payload — which this function
    // is not given. That is a different answer from "invalid", and conflating the
    // two would brand a seal broken on the strength of a check that never ran.
    let Some(signed_attrs) = signed.signer.signed_attrs.as_ref() else {
        return Err(SealError::Backend(
            "this seal carries no signed attributes, so the digest it covers is not inside it \
             and cannot be checked from the envelope alone"
                .to_owned(),
        ));
    };

    let spki = &signed.certificate.tbs_certificate.subject_public_key_info;
    let key_bits = spki
        .subject_public_key
        .as_bytes()
        .ok_or_else(|| malformed("the certificate's public key is not whole bytes"))?;
    let vk = VerifyingKey::from_sec1_bytes(key_bits)
        .map_err(|e| malformed(format!("the certificate holds no P-256 key: {e}")))?;

    // Re-encode as SET OF, matching what was signed (RFC 5652 §5.4).
    let to_verify = signed_attrs
        .to_der()
        .map_err(|e| malformed(format!("cannot re-encode the signed attributes: {e}")))?;
    let sig = p256::ecdsa::DerSignature::from_bytes(signed.signer.signature.as_bytes())
        .map_err(|e| malformed(format!("not a DER ECDSA signature: {e}")))?;

    Ok(vk.verify(&to_verify, &sig).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Unreadable bytes yield no reference rather than an error.
    ///
    /// The seal itself is fine — it was produced, paid for, and stored. Losing it
    /// because a convenience field could not be filled would trade something that
    /// matters for something that does not.
    #[test]
    fn unreadable_bytes_yield_no_thumbprint() {
        assert_eq!(
            signer_certificate_thumbprint(b"not a CMS structure at all").unwrap(),
            None
        );
        assert_eq!(signer_certificate_thumbprint(&[]).unwrap(), None);
    }

    /// Reading the certificate out of a seal agrees with the identity that
    /// signed it.
    ///
    /// This is the claim that makes `signing_cert_ref` comparable across
    /// backends. One backend knows its own certificate and reports it directly;
    /// the other can only read it back out of the bytes a provider returned. If
    /// those two ever produced different values for the same certificate, the
    /// field would silently stop being a key an auditor can match on.
    ///
    /// The local backend supplies realistic bytes here because it is the only
    /// source of a genuine CMS structure in this crate — a hand-rolled fixture
    /// would prove that the parser agrees with the fixture, not with reality.
    #[test]
    fn the_thumbprint_matches_the_identity_that_signed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let id = crate::local::LocalIdentity::load_or_create(dir.path()).expect("identity");
        let seal = id.sign_detached(&[0x11; 32]).expect("sign");

        assert_eq!(
            signer_certificate_thumbprint(&seal).unwrap(),
            Some(id.cert_thumbprint()),
            "the certificate read out of a seal must be the one that signed it"
        );
    }

    /// A seal signed by a different identity reports a different certificate.
    ///
    /// Without this, the function could return a constant and the test above
    /// would still pass.
    #[test]
    fn a_different_signer_yields_a_different_thumbprint() {
        let make = || {
            let dir = tempfile::tempdir().expect("tempdir");
            let id = crate::local::LocalIdentity::load_or_create(dir.path()).expect("identity");
            let seal = id.sign_detached(&[0x11; 32]).expect("sign");
            (signer_certificate_thumbprint(&seal).unwrap(), dir)
        };

        let (a, _da) = make();
        let (b, _db) = make();
        assert!(a.is_some() && b.is_some());
        assert_ne!(a, b, "two certificates must not report the same thumbprint");
    }
}
