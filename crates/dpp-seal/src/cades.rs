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
use dpp_domain::seal::SealConformanceLevel;
use x509_cert::Certificate;

use crate::error::SealError;

fn malformed(what: impl std::fmt::Display) -> SealError {
    SealError::Backend(format!("cannot read the seal: {what}"))
}

/// The one signer and the certificate it travels with.
struct Signed {
    signer: SignerInfo,
    certificate: Certificate,
    /// Whether `SignedData.crls` carried anything.
    ///
    /// Captured here because the enclosing `SignedData` is dropped when this is
    /// built, and it is the modern home of the revocation material that
    /// distinguishes a long-term seal — see [`evidenced_level`]. A boolean
    /// rather than the values themselves: nothing in this crate reads them, and
    /// carrying them would invite a caller to treat "revocation data is present"
    /// as "revocation was checked", which is the confusion this whole module is
    /// arranged to prevent.
    crls_present: bool,
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
        crls_present: sd.crls.as_ref().is_some_and(|c| !c.0.as_slice().is_empty()),
    })
}

// ─── Conformance level, as far as the bytes show it ──────────────────────────

/// `id-aa-signatureTimeStampToken` — the timestamp that distinguishes T.
///
/// RFC 3161 / RFC 5126 §6.1.1. Not in `const-oid`'s bundled databases, so it is
/// written out here with its source rather than reached for by a path that does
/// not exist.
const ID_AA_SIGNATURE_TIME_STAMP_TOKEN: const_oid::ObjectIdentifier =
    const_oid::ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.14");

/// `id-aa-ets-revocationValues` — revocation material carried as an attribute.
///
/// RFC 5126 §6.3.4. The **older** home for the material that distinguishes a
/// long-term seal; see [`evidenced_level`] for why both homes are accepted.
const ID_AA_ETS_REVOCATION_VALUES: const_oid::ObjectIdentifier =
    const_oid::ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.24");

/// `id-aa-ets-archiveTimestampV3` — the archival timestamp that distinguishes LTA.
///
/// ETSI-assigned (`itu-t(0) identified-organization(4) etsi(0) 1733 attributes(2)
/// 4`), which is why it is not in any RFC database.
const ID_AA_ETS_ARCHIVE_TIMESTAMP_V3: const_oid::ObjectIdentifier =
    const_oid::ObjectIdentifier::new_unwrap("0.4.0.1733.2.4");

/// `id-aa-ets-archiveTimestampV2` — the predecessor of the above.
///
/// RFC 5126 §6.4.1. Accepted alongside v3 because a seal carrying either has
/// archival material; which generation it is does not change that.
const ID_AA_ETS_ARCHIVE_TIMESTAMP_V2: const_oid::ObjectIdentifier =
    const_oid::ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.48");

/// The highest baseline level whose material is actually present in the seal.
///
/// # Why this exists
///
/// The level is chosen on the request and, until this function, nothing ever
/// looked at what came back. A provider that returns `CAdES_BASELINE_T` when
/// asked for `LT` — a client enabled for the wrong profile, a plan change, a
/// provider-side default — produces a seal that is correct in every record this
/// node keeps and stops verifying when the signing certificate expires, years
/// after the passport was retention-locked and long after anything could be
/// done about it.
///
/// # This is a floor, not a verdict
///
/// It reports that the *distinguishing material* for a level is present. It does
/// **not** report conformance. Conforming to a baseline level means satisfying
/// every row of the profile's requirements table — `signing-time` present,
/// `content-type` equal to `id-data`, the ESS signing-certificate reference, and
/// much more — and none of that is checked here. Nor is any of the material
/// validated: a timestamp token is counted because it is there, not because
/// anybody confirmed it timestamps this signature or that its TSA is trusted.
///
/// So a `BaselineLt` from this function means "the material an LT seal carries
/// is in these bytes", and the honest use of it is to notice when *less* is
/// present than was paid for. Establishing the converse is an AdES validator's
/// job, as everywhere else in this module.
///
/// # Cumulative, deliberately
///
/// A level is reported only when the material for it *and every level below it*
/// is present. Under-reporting is safe — it prompts a look at a seal that may be
/// fine. Over-reporting hides exactly the downgrade this function exists to
/// catch, so a stray archival timestamp over a seal with no revocation material
/// yields `BaselineT`, not `BaselineLta`.
///
/// # Two homes for the long-term material, and both count
///
/// This is the part that is easy to get wrong, because the two profiles in play
/// disagree — and **both are lawful right now**, which is what makes reading
/// only one of them a live defect rather than a theoretical one.
///
/// Commission Implementing Regulation (EU) 2026/248 lists the formats public
/// sector bodies must recognise. It carries two annexes:
///
/// - **Annex I** — the current set, which for CAdES is ETSI EN 319 122-1. That
///   standard puts an LT seal's revocation material in `SignedData.crls`, and
///   marks the `revocation-values` attribute **`shall not be present`** at that
///   level.
/// - **Annex II** — the superseded set, which for CAdES is ETSI TS 103 173.
///   That profile's LT-Level clause has a `Revocation values` subclause: the
///   CAdES-X Long attribute, in the very place Annex I's standard forbids it.
///
/// Annex II is not history. Article 3(2) obliges recognition of seals in those
/// formats where they were **created before 23 February 2028**, so seals of both
/// shapes are being produced and must both be read correctly until then — and,
/// since a passport's seal is retention-locked, long after.
///
/// Reading only `SignedData.crls` would misreport an Annex II seal as
/// `BaselineT` and raise a downgrade alarm against a provider that did nothing
/// wrong. Both are accepted.
///
/// `Ok(None)` when the bytes are not a seal this module can read, matching
/// [`signer_certificate_thumbprint`]: a stored seal must not be lost to a parse
/// failure on a field that describes it.
pub fn evidenced_level(seal_der: &[u8]) -> Result<Option<SealConformanceLevel>, SealError> {
    let Ok(signed) = parse(seal_der) else {
        return Ok(None);
    };

    let has = |oid: const_oid::ObjectIdentifier| {
        signed
            .signer
            .unsigned_attrs
            .as_ref()
            .is_some_and(|attrs| attrs.iter().any(|a| a.oid == oid))
    };

    let timestamped = has(ID_AA_SIGNATURE_TIME_STAMP_TOKEN);
    let long_term = signed.crls_present || has(ID_AA_ETS_REVOCATION_VALUES);
    let archived = has(ID_AA_ETS_ARCHIVE_TIMESTAMP_V3) || has(ID_AA_ETS_ARCHIVE_TIMESTAMP_V2);

    Ok(Some(match (timestamped, long_term, archived) {
        (true, true, true) => SealConformanceLevel::BaselineLta,
        (true, true, false) => SealConformanceLevel::BaselineLt,
        (true, false, _) => SealConformanceLevel::BaselineT,
        (false, _, _) => SealConformanceLevel::BaselineB,
    }))
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

    // ─── evidenced_level ─────────────────────────────────────────────────────

    /// A real seal from the local backend, and the same seal with material added.
    ///
    /// Built by decorating genuine bytes rather than assembling a fixture from
    /// nothing, for the reason given above: a hand-rolled structure would prove
    /// the reader agrees with the fixture. Decorating leaves the signature
    /// invalid — nothing here re-signs — which is correct for this function,
    /// because it reports what a seal *carries* and validates none of it.
    fn decorated(
        attrs: &[const_oid::ObjectIdentifier],
        with_crls: bool,
    ) -> (Vec<u8>, tempfile::TempDir) {
        use der::asn1::SetOfVec;

        let dir = tempfile::tempdir().expect("tempdir");
        let id = crate::local::LocalIdentity::load_or_create(dir.path()).expect("identity");
        let der = id.sign_detached(&[0x11; 32]).expect("sign");

        let info = ContentInfo::from_der(&der).expect("CMS");
        let mut sd: SignedData = info.content.decode_as().expect("SignedData");

        if !attrs.is_empty() {
            let mut unsigned = SetOfVec::new();
            for oid in attrs {
                let mut values = SetOfVec::new();
                // The content is irrelevant: presence is the whole signal, and
                // a real token would still not be validated by anything here.
                values
                    .insert(der::Any::from(der::asn1::Null))
                    .expect("attribute value");
                unsigned
                    .insert(x509_cert::attr::Attribute { oid: *oid, values })
                    .expect("unsigned attribute");
            }
            let mut signers = sd.signer_infos.0.as_slice().to_vec();
            signers[0].unsigned_attrs = Some(unsigned);
            let mut set = SetOfVec::new();
            set.insert(signers.remove(0)).expect("signer");
            sd.signer_infos = cms::signed_data::SignerInfos::from(set);
        }

        if with_crls {
            // One CRL entry stands for "the revocation material an LT seal
            // carries". Its contents are never read — `crls_present` is a
            // boolean by design.
            let crl = x509_cert::crl::CertificateList {
                tbs_cert_list: x509_cert::crl::TbsCertList {
                    version: x509_cert::Version::V2,
                    signature: sd.signer_infos.0.as_slice()[0].signature_algorithm.clone(),
                    issuer: match &sd.signer_infos.0.as_slice()[0].sid {
                        cms::signed_data::SignerIdentifier::IssuerAndSerialNumber(ias) => {
                            ias.issuer.clone()
                        }
                        other => panic!("the local backend identifies by issuer+serial: {other:?}"),
                    },
                    this_update: x509_cert::time::Time::UtcTime(
                        der::asn1::UtcTime::from_unix_duration(core::time::Duration::from_secs(0))
                            .expect("time"),
                    ),
                    next_update: None,
                    revoked_certificates: None,
                    crl_extensions: None,
                },
                signature_algorithm: sd.signer_infos.0.as_slice()[0].signature_algorithm.clone(),
                signature: der::asn1::BitString::from_bytes(&[0]).expect("bits"),
            };
            let mut set = SetOfVec::new();
            set.insert(cms::revocation::RevocationInfoChoice::Crl(crl))
                .expect("crl");
            sd.crls = Some(cms::revocation::RevocationInfoChoices(set));
        }

        let info = ContentInfo {
            content_type: const_oid::db::rfc5911::ID_SIGNED_DATA,
            content: der::Any::encode_from(&sd).expect("encode"),
        };
        (info.to_der().expect("der"), dir)
    }

    /// Unreadable bytes yield no level rather than a wrong one.
    #[test]
    fn unreadable_bytes_evidence_no_level() {
        assert_eq!(evidenced_level(b"not a CMS structure").unwrap(), None);
        assert_eq!(evidenced_level(&[]).unwrap(), None);
    }

    /// The local backend's seal evidences `BaselineB`, and that is what it
    /// advertises.
    ///
    /// The one place in this crate where the claim and the bytes can be checked
    /// against each other end to end: `sign_detached` sets `unsigned_attrs:
    /// None`, `capabilities()` advertises `BaselineB` only, and this asserts the
    /// two agree. If the sealer ever grew a timestamp without its advertisement
    /// following, this fails.
    #[test]
    fn the_local_seal_evidences_baseline_b() {
        let (der, _dir) = decorated(&[], false);
        assert_eq!(
            evidenced_level(&der).unwrap(),
            Some(SealConformanceLevel::BaselineB)
        );
    }

    /// A signature timestamp, and nothing more, evidences `BaselineT`.
    #[test]
    fn a_signature_timestamp_evidences_baseline_t() {
        let (der, _dir) = decorated(&[ID_AA_SIGNATURE_TIME_STAMP_TOKEN], false);
        assert_eq!(
            evidenced_level(&der).unwrap(),
            Some(SealConformanceLevel::BaselineT)
        );
    }

    /// Both homes of the long-term material evidence `BaselineLt`.
    ///
    /// The finding this test exists for. ETSI EN 319 122-1 — Annex I of
    /// Commission Implementing Regulation (EU) 2026/248 — puts an LT seal's
    /// revocation material in `SignedData.crls` and forbids the
    /// `revocation-values` attribute at that level. ETSI TS 103 173, that
    /// Regulation's Annex II, carries it in that very attribute.
    ///
    /// Both annexes are live: Article 3(2) obliges recognition of Annex II
    /// formats for seals created before 23 February 2028. So a seal produced to
    /// either profile is lawful today and carries exactly what the other
    /// forbids. Reading only one home would report an Annex II seal as
    /// `BaselineT` and raise a downgrade alarm against a provider that did
    /// nothing wrong.
    #[test]
    fn either_home_of_the_revocation_material_evidences_baseline_lt() {
        let (modern, _a) = decorated(&[ID_AA_SIGNATURE_TIME_STAMP_TOKEN], true);
        let (legacy, _b) = decorated(
            &[
                ID_AA_SIGNATURE_TIME_STAMP_TOKEN,
                ID_AA_ETS_REVOCATION_VALUES,
            ],
            false,
        );

        assert_eq!(
            evidenced_level(&modern).unwrap(),
            Some(SealConformanceLevel::BaselineLt),
            "EN 319 122-1 (2026/248 Annex I) puts the material in SignedData.crls"
        );
        assert_eq!(
            evidenced_level(&legacy).unwrap(),
            Some(SealConformanceLevel::BaselineLt),
            "TS 103 173 (2026/248 Annex II, lawful until Feb 2028) puts it in revocation-values"
        );
    }

    /// Both archival timestamp generations evidence `BaselineLta`.
    #[test]
    fn an_archival_timestamp_evidences_baseline_lta() {
        for oid in [
            ID_AA_ETS_ARCHIVE_TIMESTAMP_V3,
            ID_AA_ETS_ARCHIVE_TIMESTAMP_V2,
        ] {
            let (der, _dir) = decorated(&[ID_AA_SIGNATURE_TIME_STAMP_TOKEN, oid], true);
            assert_eq!(
                evidenced_level(&der).unwrap(),
                Some(SealConformanceLevel::BaselineLta),
                "{oid} is an archival timestamp"
            );
        }
    }

    /// Material for a high level without the levels beneath it reports the floor.
    ///
    /// The direction of this rounding is the whole point. Under-reporting
    /// prompts a look at a seal that may be fine; over-reporting hides the
    /// downgrade the function exists to catch, so an archival timestamp over a
    /// seal carrying no revocation material must not read as `BaselineLta`.
    #[test]
    fn a_level_is_never_reported_above_the_material_beneath_it() {
        let (no_revocation, _a) = decorated(
            &[
                ID_AA_SIGNATURE_TIME_STAMP_TOKEN,
                ID_AA_ETS_ARCHIVE_TIMESTAMP_V3,
            ],
            false,
        );
        assert_eq!(
            evidenced_level(&no_revocation).unwrap(),
            Some(SealConformanceLevel::BaselineT),
            "archival material without long-term material is not LTA"
        );

        let (no_timestamp, _b) = decorated(&[ID_AA_ETS_REVOCATION_VALUES], true);
        assert_eq!(
            evidenced_level(&no_timestamp).unwrap(),
            Some(SealConformanceLevel::BaselineB),
            "revocation material without a signature timestamp is not LT"
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
