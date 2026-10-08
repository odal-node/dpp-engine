//! Conformance level, as far as the bytes show it, and whether the signature
//! holds.

use cms::signed_data::SignerInfo;
use der::{Decode as _, Encode as _};
use dpp_domain::seal::SealConformanceLevel;
use x509_cert::Certificate;

use super::signed::ID_AA_ETS_ARCHIVE_TIMESTAMP_V2;
use super::signed::ID_AA_ETS_ARCHIVE_TIMESTAMP_V3;
use super::signed::ID_AA_ETS_REVOCATION_VALUES;
use super::signed::ID_AA_SIGNATURE_TIME_STAMP_TOKEN;
use super::signed::Signed;
use super::signed::malformed;
use super::signed::parse;
use crate::error::SealError;

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
    let long_term = !signed.crls.is_empty() || has(ID_AA_ETS_REVOCATION_VALUES);
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

/// The digest the seal actually covers, read out of its signed attributes.
///
/// # Why this is the binding, and the outbox row is not
///
/// A detached CAdES says what it covers in exactly one place: the
/// `messageDigest` signed attribute, RFC 5652 §11.2. Everything else is
/// bookkeeping. This node records what it *asked* a backend to seal, and that
/// record is genuinely useful — it survives when the seal does not parse, and it
/// is how a re-published passport is spotted without any AdES tooling — but it
/// is a statement about our own outbox, not about the bytes. The two can
/// disagree, and only one of them is evidence.
///
/// Reading it turns "this seal is for this passport" from a claim resting on our
/// own records into something checkable against the seal itself.
///
/// # Only meaningful alongside the signature
///
/// This attribute is *inside* the signature, which is what makes it worth
/// reading — but nothing here checks that signature. A caller comparing this
/// digest without also calling [`verify_against_embedded_certificate`] is
/// trusting a value anyone could have edited. Both, or neither.
///
/// `Ok(None)` when the bytes are not a readable seal, or carry no signed
/// attributes at all — a seal whose digest is not inside it, which is a
/// different finding from one that names the wrong digest.
///
/// # Errors
///
/// [`SealError::Backend`] when the attribute is present but malformed. That is
/// not a "no" — a caller must not read it as a mismatch.
pub fn covered_digest(seal_der: &[u8]) -> Result<Option<Vec<u8>>, SealError> {
    let Ok(signed) = parse(seal_der) else {
        return Ok(None);
    };
    let Some(attrs) = signed.signer.signed_attrs.as_ref() else {
        return Ok(None);
    };
    let Some(attr) = attrs
        .iter()
        .find(|a| a.oid == const_oid::db::rfc5911::ID_MESSAGE_DIGEST)
    else {
        return Ok(None);
    };

    // RFC 5652 §11.2: exactly one value, an OCTET STRING. More than one is
    // malformed rather than ambiguous, and picking the first would invent an
    // answer to a question the seal did not settle.
    let [value] = attr.values.as_slice() else {
        return Err(malformed(format!(
            "the messageDigest attribute carries {} values, not one",
            attr.values.len()
        )));
    };
    let octets: der::asn1::OctetString = value
        .decode_as()
        .map_err(|e| malformed(format!("the messageDigest is not an OCTET STRING: {e}")))?;
    Ok(Some(octets.as_bytes().to_vec()))
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
/// `rsaEncryption` — RFC 8017. Its `AlgorithmIdentifier` parameters must be NULL.
pub(super) const RSA_ENCRYPTION: const_oid::ObjectIdentifier =
    const_oid::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");

/// Build a verifier for a certificate's public key.
///
/// # Why this is not just `VerifyingKey::try_from`
///
/// RFC 3279 §2.3.1 requires the `AlgorithmIdentifier` parameters for
/// `rsaEncryption` to be present and NULL, and the strict SPKI decoder behind
/// the verifier enforces it. **A real listed qualified CA does not comply**: the
/// French notaries' delegated authority (`OU=REAL,OU=AC déléguée,OU=Notaires`)
/// omits the field, and every seal issued under it would otherwise report as
/// unverifiable — not as invalid, which is the safe direction, but as an answer
/// this node cannot give about a lawful seal.
///
/// So an absent NULL is supplied before decoding. **This changes no key
/// material.** The modulus and exponent live in the SPKI's BIT STRING and are
/// untouched; the parameters field is metadata about the algorithm identifier,
/// and the algorithm is already known from its OID. Nothing weaker is accepted —
/// a key that fails for any other reason still fails.
///
/// Narrow on purpose: only `rsaEncryption`, only when the field is absent, and
/// never when it is present and wrong. `every_listed_qualified_ca_yields_a_usable_verifier`
/// holds the line at **every** published CA, so a future non-conformance is
/// caught rather than quietly joining the set of authorities whose seals this
/// node cannot check.
pub(super) fn verifying_key(
    certificate: &Certificate,
) -> Result<x509_verify::VerifyingKey, SealError> {
    let spki = &certificate.tbs_certificate.subject_public_key_info;
    if spki.algorithm.oid != RSA_ENCRYPTION || spki.algorithm.parameters.is_some() {
        return x509_verify::VerifyingKey::try_from(certificate)
            .map_err(|e| malformed(format!("no verifier for this key: {e}")));
    }

    let mut normalised = spki.clone();
    normalised.algorithm.parameters = Some(
        der::Any::encode_from(&der::asn1::Null)
            .map_err(|e| malformed(format!("cannot encode the NULL parameters: {e}")))?,
    );
    let der = normalised
        .to_der()
        .map_err(|e| malformed(format!("cannot re-encode the public key: {e}")))?;
    let reparsed = x509_cert::spki::SubjectPublicKeyInfoRef::from_der(&der)
        .map_err(|e| malformed(format!("cannot re-read the public key: {e}")))?;
    x509_verify::VerifyingKey::try_from(reparsed)
        .map_err(|e| malformed(format!("no verifier for this RSA key: {e}")))
}

/// Whether this build can check signatures made by `certificate_der`'s key.
///
/// The operator-facing form of the question `verifying_key` answers: will seals
/// issued under this certificate authority be checkable here, or will they come
/// back unverifiable? A `false` is not a judgement on the CA — it says this build
/// has no verifier for its algorithm, which is a gap on our side.
///
/// # Errors
///
/// None — an unreadable certificate is one whose signatures cannot be checked,
/// which is the same answer.
#[must_use]
pub fn can_verify_signatures_of(certificate_der: &[u8]) -> bool {
    Certificate::from_der(certificate_der).is_ok_and(|c| verifying_key(&c).is_ok())
}

/// # Every algorithm the published population actually uses
///
/// This was P-256 only, which is what the local development backend emits — and
/// **none** of what a real provider does. Measured across the qualified CAs in
/// the trusted lists (`tests/ca_key_survey.rs`), 96.8% are RSA and the
/// elliptic-curve remainder is P-384 and P-521 with not one P-256.
///
/// That mattered more than a missing feature. A caller that could not check the
/// signature could not read the digest either — the digest lives in an attribute
/// inside it — so this function returning an error was the whole seal-to-passport
/// binding degrading to "unknown" on the first real provider seal, silently, at
/// exactly the point it started to matter.
///
/// It now uses the same verifier as [`check_path_to`], so the algorithms it
/// accepts are one list in `Cargo.toml` rather than two that can drift.
pub fn verify_against_embedded_certificate(seal_der: &[u8]) -> Result<bool, SealError> {
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

    // One implementation of "does this signature hold", shared with the
    // timestamp token's own check. A second copy is how two places come to
    // disagree about it, and this one decides whether a seal is bound to its
    // passport.
    let _ = signed_attrs;
    signature_holds(&signed)
}

pub(super) fn signature_holds(signed: &Signed) -> Result<bool, SealError> {
    let Some(signed_attrs) = signed.signer.signed_attrs.as_ref() else {
        return Ok(false);
    };
    let key = verifying_key(&signed.certificate)?;
    let to_verify = signed_attrs
        .to_der()
        .map_err(|e| malformed(format!("cannot re-encode the signed attributes: {e}")))?;
    let algorithm = verification_algorithm(&signed.signer);
    let signature = x509_verify::SignatureRef::new(&algorithm, signed.signer.signature.as_bytes());
    match key.verify(x509_verify::VerifyInfo::new(
        x509_verify::MessageOwned::from(to_verify),
        signature,
    )) {
        Ok(()) => Ok(true),
        Err(x509_verify::Error::Verification) => Ok(false),
        Err(e) => Err(malformed(format!(
            "the signature could not be checked: {e}"
        ))),
    }
}

/// The algorithm a `SignerInfo`'s signature is to be verified under.
///
/// # 🚨 A signer may name only `rsaEncryption`, and a real authority does
///
/// RFC 3370 §3.2 lets a CMS signer give `rsaEncryption` (1.2.840.113549.1.1.1) as
/// its `signatureAlgorithm` and leave the hash to the separate `digestAlgorithm`
/// — whereas the verifier here is told the **combined** identifier, such as
/// `sha384WithRSAEncryption`, and answers `Unknown OID` for the bare one.
/// Sectigo's public authority signs exactly that way, so before this its tokens
/// could not be verified, and a seal carrying one could not have had its time read.
///
/// Only that pairing is rewritten, and only with the digest the signer itself
/// names. Anything else — including every identifier that is already combined — is
/// passed through untouched, so this cannot turn a signature that would not verify
/// into one that does. A digest not listed leaves the bare identifier, which the
/// verifier refuses.
pub(super) fn verification_algorithm(
    signer: &SignerInfo,
) -> x509_cert::spki::AlgorithmIdentifierOwned {
    use const_oid::db::rfc5912::{
        ID_SHA_256, ID_SHA_384, ID_SHA_512, RSA_ENCRYPTION, SHA_256_WITH_RSA_ENCRYPTION,
        SHA_384_WITH_RSA_ENCRYPTION, SHA_512_WITH_RSA_ENCRYPTION,
    };

    let named = &signer.signature_algorithm;
    if named.oid != RSA_ENCRYPTION {
        return named.clone();
    }
    let combined = if signer.digest_alg.oid == ID_SHA_256 {
        SHA_256_WITH_RSA_ENCRYPTION
    } else if signer.digest_alg.oid == ID_SHA_384 {
        SHA_384_WITH_RSA_ENCRYPTION
    } else if signer.digest_alg.oid == ID_SHA_512 {
        SHA_512_WITH_RSA_ENCRYPTION
    } else {
        return named.clone();
    };
    x509_cert::spki::AlgorithmIdentifierOwned {
        oid: combined,
        // The RSA signature algorithms carry an explicit NULL (RFC 4055 §5).
        parameters: Some(der::Any::new(der::Tag::Null, [].as_slice()).expect("an empty NULL")),
    }
}

/// `bytes` hashed under the algorithm `oid` names — for the SHA-2 family a
/// signature or a timestamp can be built on, and `None` for anything else.
///
/// 🚨 **Dispatched on the algorithm the structure itself names**, never assumed to
/// be SHA-256. A `messageDigest` is computed with the signer's own
/// `digestAlgorithm`, and an imprint with the algorithm in its `MessageImprint`;
/// both were checked against SHA-256 alone, which is the one algorithm this
/// crate's own writer uses and **not** what real timestamp authorities sign with.
/// Two of them were asked: one digests with SHA-512 over an ECDSA P-384 key, the
/// other with SHA-384 over RSA, and neither token verified until this dispatched.
///
/// `None` for an algorithm not listed is a refusal, not a guess: an unknown hash
/// cannot be compared, and treating "cannot compare" as "matches" is the failure
/// this exists to avoid.
pub(super) fn hash_under(oid: &const_oid::ObjectIdentifier, bytes: &[u8]) -> Option<Vec<u8>> {
    use const_oid::db::rfc5912::{ID_SHA_256, ID_SHA_384, ID_SHA_512};
    use sha2::{Digest as _, Sha256, Sha384, Sha512};

    if *oid == ID_SHA_256 {
        Some(Sha256::digest(bytes).to_vec())
    } else if *oid == ID_SHA_384 {
        Some(Sha384::digest(bytes).to_vec())
    } else if *oid == ID_SHA_512 {
        Some(Sha512::digest(bytes).to_vec())
    } else {
        None
    }
}

/// Whether the signed `messageDigest` matches `content`, under the digest
/// algorithm the signer names.
pub(super) fn digest_matches(signed: &Signed, content: &[u8]) -> bool {
    signed
        .signer
        .signed_attrs
        .as_ref()
        .and_then(|a| {
            a.iter()
                .find(|a| a.oid == const_oid::db::rfc5911::ID_MESSAGE_DIGEST)
        })
        .and_then(|a| a.values.as_slice().first())
        .and_then(|v| v.decode_as::<der::asn1::OctetString>().ok())
        .zip(hash_under(&signed.signer.digest_alg.oid, content))
        .is_some_and(|(claimed, actual)| claimed.as_bytes() == actual.as_slice())
}

#[cfg(test)]
#[path = "signature_tests.rs"]
mod tests;
