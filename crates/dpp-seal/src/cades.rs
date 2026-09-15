//! Reading what a detached CAdES says about itself.
//!
//! Shared by the backends because the parsing is plain CMS and belongs to
//! neither: a backend module may not reach into another's, and duplicating
//! ASN.1 handling across two of them is how the two quietly stop agreeing about
//! what a seal contains.
//!
//! # What is *reported* and what is *verified*, kept apart by name
//!
//! Most of this module reads a structure and reports what it found. A
//! certificate it names is the one the seal **claims** signed it, on the seal's
//! own word — [`signer_certificate`], [`evidenced_level`] and
//! [`signer_certificate_thumbprint`] all work that way, and are named so the
//! distinction survives a skim.
//!
//! [`check_path_to`] is the exception, and the only one. It verifies signatures:
//! given a trust anchor established elsewhere, it walks from the seal's signer up
//! through the certificates the seal carries and checks that each link was really
//! signed by the one above it. That is a genuine cryptographic result, not a
//! report.
//!
//! It still does **not** make a seal qualified. No validity window is read and no
//! revocation is consulted, so a certificate that had expired or been revoked at
//! the moment of sealing passes this check. Establishing *that* remains an
//! independent AdES validator's job.
//!
//! The distinction is the whole reason this is a separate module with its own
//! vocabulary. A convenience field that reads as verification while verifying
//! nothing is worse than an absent one, because an absent field prompts the
//! question and a populated one settles it wrongly.

use chrono::{DateTime, Utc};
use cms::cert::CertificateChoices;
use cms::content_info::ContentInfo;
use cms::signed_data::{SignedData, SignerInfo};
use der::{Decode as _, Encode as _};
use dpp_domain::seal::SealConformanceLevel;
use dpp_types::{
    CertificateStanding, CreationDevice, JudgedTime, RevocationStanding, SealOrigin,
    ValidityWindow, WindowStanding,
};
use x509_cert::Certificate;

use crate::error::SealError;

fn malformed(what: impl std::fmt::Display) -> SealError {
    SealError::Backend(format!("cannot read the seal: {what}"))
}

/// The signer, its certificate, and everything else the seal carries.
struct Signed {
    signer: SignerInfo,
    certificate: Certificate,
    /// Every X.509 certificate embedded in the seal, the signer's included.
    ///
    /// A real CAdES seal usually travels with its issuing chain, which is what
    /// makes a path to a trusted list's anchor reachable without fetching
    /// anything: Italy's list publishes self-signed **roots**, so the
    /// intermediate that actually issued a seal certificate will be found here
    /// or nowhere.
    chain: Vec<Certificate>,
    /// The encapsulated content, when the structure carries one.
    ///
    /// Absent for a detached seal — that is what detached means. Present for a
    /// **time-stamp token**, which is itself a `SignedData` and carries its
    /// `TSTInfo` here; reading an attested sealing time means reaching it.
    econtent: Option<Vec<u8>>,
    /// Whatever `SignedData.crls` carried, as certificate revocation lists.
    ///
    /// Held rather than counted. This was a boolean for as long as nothing read
    /// the values — the reasoning being that carrying them would invite a caller
    /// to treat "revocation data is present" as "revocation was checked", which
    /// is the confusion this module is arranged to prevent. [`certificate_standing`]
    /// now actually reads them, so the distinction is made by what that function
    /// returns instead: presence alone reports `NotAvailable` until a CRL is
    /// found that covers this certificate and verifies under its issuer.
    ///
    /// Only the `crl` choice is kept. `other` is a container for formats this
    /// crate cannot read — an OCSP response among them — and keeping an
    /// unreadable value would have to be reported as material this node checked.
    crls: Vec<x509_cert::crl::CertificateList>,
}

/// `id-ce-subjectKeyIdentifier` — RFC 5280 §4.2.1.2.
const ID_CE_SUBJECT_KEY_IDENTIFIER: const_oid::ObjectIdentifier =
    const_oid::ObjectIdentifier::new_unwrap("2.5.29.14");

/// Which embedded certificate the `SignerInfo` actually names.
///
/// **Not simply the first.** RFC 5652 makes `SignedData.certificates` a SET, so
/// its order carries no meaning, and a seal travelling with its issuing chain
/// may well list an intermediate before the end-entity certificate. Taking
/// `[0]` happens to work for a seal carrying exactly one certificate — which is
/// every seal this crate produces — and silently reports the wrong certificate
/// for a real provider's seal, which is the case that matters.
fn signer_certificate_of<'a>(
    signer: &SignerInfo,
    certs: &'a [Certificate],
) -> Option<&'a Certificate> {
    match &signer.sid {
        cms::signed_data::SignerIdentifier::IssuerAndSerialNumber(ias) => certs.iter().find(|c| {
            c.tbs_certificate.issuer == ias.issuer
                && c.tbs_certificate.serial_number == ias.serial_number
        }),
        cms::signed_data::SignerIdentifier::SubjectKeyIdentifier(ski) => certs.iter().find(|c| {
            c.tbs_certificate
                .extensions
                .as_ref()
                .and_then(|e| e.iter().find(|e| e.extn_id == ID_CE_SUBJECT_KEY_IDENTIFIER))
                // The extension wraps the key identifier in an OCTET STRING, so
                // its DER is a 2-byte header plus the bytes the SignerInfo names.
                .is_some_and(|e| e.extn_value.as_bytes().ends_with(ski.0.as_bytes()))
        }),
    }
}

/// Parse a detached CMS `SignedData` down to its single signer and certificates.
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
    let chain: Vec<Certificate> = certs
        .0
        .as_slice()
        .iter()
        .filter_map(|c| match c {
            CertificateChoices::Certificate(c) => Some(c.clone()),
            _ => None,
        })
        .collect();
    if chain.is_empty() {
        return Err(malformed("it carries no X.509 certificate"));
    }

    // A seal naming a certificate it does not carry cannot be read: the
    // alternative is to guess, and a guess here misattributes the seal.
    let certificate = signer_certificate_of(signer, &chain)
        .ok_or_else(|| malformed("it names a signer certificate it does not carry"))?
        .clone();

    Ok(Signed {
        signer: signer.clone(),
        certificate,
        chain,
        econtent: sd
            .encap_content_info
            .econtent
            .as_ref()
            .and_then(|c| c.decode_as::<der::asn1::OctetString>().ok())
            .map(|o| o.as_bytes().to_vec()),
        crls: sd.crls.as_ref().map_or_else(Vec::new, |c| {
            c.0.as_slice()
                .iter()
                .filter_map(|choice| match choice {
                    cms::revocation::RevocationInfoChoice::Crl(crl) => Some(crl.clone()),
                    cms::revocation::RevocationInfoChoice::Other(_) => None,
                })
                .collect()
        }),
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
const RSA_ENCRYPTION: const_oid::ObjectIdentifier =
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
fn verifying_key(certificate: &Certificate) -> Result<x509_verify::VerifyingKey, SealError> {
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

// ─── When it was sealed, as attested rather than claimed ─────────────────────

/// `id-ct-TSTInfo` — the content type of a time-stamp token's payload.
///
/// RFC 3161 §2.4.2.
pub(crate) const ID_CT_TST_INFO: const_oid::ObjectIdentifier =
    const_oid::ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.1.4");

/// `MessageImprint` — RFC 3161 §2.4.1.
#[derive(der::Sequence)]
pub(crate) struct MessageImprint {
    pub(crate) hash_algorithm: x509_cert::spki::AlgorithmIdentifierOwned,
    pub(crate) hashed_message: der::asn1::OctetString,
}

/// `TSTInfo` — RFC 3161 §2.4.2.
///
/// Defined here, in the module that owns CMS and X.509 handling, and used by
/// the local timestamping authority for writing. One definition: a reader and a
/// writer with separate copies is the drift this module's header warns about,
/// and it would show up as tokens this node emits and cannot read back.
///
/// The optional tail — `accuracy`, `ordering`, `nonce`, `tsa`, `extensions` — is
/// omitted. Reading stops at `genTime` because that is the only field anything
/// here asks about; a token carrying more still parses, since DER decoding of a
/// SEQUENCE ignores what it was not asked for.
#[derive(der::Sequence)]
pub(crate) struct TstInfo {
    pub(crate) version: u8,
    pub(crate) policy: const_oid::ObjectIdentifier,
    pub(crate) message_imprint: MessageImprint,
    pub(crate) serial_number: u64,
    pub(crate) gen_time: der::asn1::GeneralizedTime,
}

/// The time a timestamp authority attests the seal was made.
///
/// # Why this is not `SealedEnvelope::sealed_at`
///
/// That field is **this node's clock when the backend answered** — an unattested
/// claim by the party that bought the seal, and the seal route says so. From
/// `B-T` upward the envelope carries an RFC 3161 token whose `genTime` is a
/// third party's statement about when the signature existed. That is the only
/// place in a seal an attested time can be, and until now nothing read it.
///
/// # The token's own signature is checked first, and it has to be
///
/// The `signature-time-stamp` attribute is an **unsigned** attribute: the seal's
/// own signature does not cover it, so anyone holding the bytes can replace the
/// whole token. What stops a forged time is the token's own signature over its
/// own content — so that is verified, and the `messageDigest` binding the
/// signature to the `TSTInfo` is checked, before `genTime` is read.
///
/// # What this still does not establish
///
/// That the authority is **trusted**, or **qualified**. Regulation (EU)
/// No 910/2014 Art. 42 makes a qualified electronic time stamp a service of a
/// QTSP, and Art. 41(2) attaches the presumption of accuracy to that — which is
/// a Trusted List question about the `TSA/QTST` service type, and is not asked
/// here. A self-signed authority's token verifies perfectly and means nothing,
/// which is exactly what this crate's own development sealer produces.
///
/// `Ok(None)` when there is no timestamp at all (a `B-B` seal), when the token
/// cannot be read, or when its signature does not hold. A time that failed its
/// check must never be reported as a time.
///
/// # Errors
///
/// [`SealError::Backend`] when the seal itself cannot be read.
pub fn attested_sealing_time(seal_der: &[u8]) -> Result<Option<DateTime<Utc>>, SealError> {
    let signed = parse(seal_der)?;
    let Some(attrs) = signed.signer.unsigned_attrs.as_ref() else {
        return Ok(None);
    };
    let Some(attr) = attrs
        .iter()
        .find(|a| a.oid == ID_AA_SIGNATURE_TIME_STAMP_TOKEN)
    else {
        return Ok(None);
    };
    let [value] = attr.values.as_slice() else {
        return Ok(None);
    };
    let Ok(token_der) = value.to_der() else {
        return Ok(None);
    };
    let Ok(token) = parse(&token_der) else {
        return Ok(None);
    };

    // The token signs its own payload, so both legs have to hold: the signature
    // over the signed attributes, and the digest inside them over the content.
    // Checking only the first would let the TSTInfo be swapped for another.
    if !signature_holds(&token).unwrap_or(false) {
        return Ok(None);
    }
    let Some(content) = token.econtent.as_ref() else {
        return Ok(None);
    };
    if !digest_matches(&token, content) {
        return Ok(None);
    }

    let Ok(info) = TstInfo::from_der(content) else {
        return Ok(None);
    };

    // And that it is a timestamp **of this signature**, not merely a valid one.
    //
    // EN 319 122-1 clause 5.3: the imprint is over the `SignerInfo` signature
    // value, without its ASN.1 tag and length. Without this leg a genuine token
    // lifted from another seal — internally sound, signed by a real authority,
    // saying a different time — would be accepted, and an unsigned attribute is
    // exactly where such a swap is free to make.
    {
        use sha2::{Digest as _, Sha256};
        if info.message_imprint.hashed_message.as_bytes()
            != Sha256::digest(signed.signer.signature.as_bytes()).as_slice()
        {
            return Ok(None);
        }
    }
    Ok(to_utc(info.gen_time.to_unix_duration().as_secs()))
}

/// Whether a parsed structure's signature holds under its own certificate.
fn signature_holds(signed: &Signed) -> Result<bool, SealError> {
    let Some(signed_attrs) = signed.signer.signed_attrs.as_ref() else {
        return Ok(false);
    };
    let key = verifying_key(&signed.certificate)?;
    let to_verify = signed_attrs
        .to_der()
        .map_err(|e| malformed(format!("cannot re-encode the signed attributes: {e}")))?;
    let signature = x509_verify::SignatureRef::new(
        &signed.signer.signature_algorithm,
        signed.signer.signature.as_bytes(),
    );
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

/// Whether the signed `messageDigest` matches `content`.
fn digest_matches(signed: &Signed, content: &[u8]) -> bool {
    use sha2::{Digest as _, Sha256};

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
        .is_some_and(|d| d.as_bytes() == Sha256::digest(content).as_slice())
}

// ─── Whether the archival protection is still live ───────────────────────────

/// How much life is left in a seal's archival timestamp.
///
/// # Why a seal can stop being long-term without anything changing
///
/// An archival timestamp is what keeps a `B-LTA` seal verifiable after its
/// signing certificate expires — which for a retention-locked passport is the
/// whole point, because the document outlives every certificate involved.
///
/// **The archival timestamp expires too.** Its own timestamping authority's
/// certificate has a validity period, and once that passes the token can no
/// longer be validated on its own terms. ETSI's long-term profiles handle this
/// by **re-timestamping** before it happens, a new archive timestamp over the
/// old one. Nothing here does that, and nothing would notice: `evidenced_level`
/// reports `BaselineLta` from the *presence* of the attribute, so a seal whose
/// archival timestamp lapsed years ago reports exactly as it did on the day it
/// was bought.
///
/// # A signal, never a verdict
///
/// Deliberately the same posture the trust anchor's freshness takes, and for the
/// same reason: a seal whose archival timestamp is nearing expiry still verifies,
/// and that window is the only chance to renew without an outage. Folding this
/// into a failure would refuse documents that are fine and destroy the early
/// warning it exists to give.
///
/// No threshold is applied here. [`Self::Current`] carries the date, and how
/// much notice is enough is a policy question belonging to whoever reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArchivalFreshness {
    /// No archival timestamp at all — a seal below `B-LTA`.
    ///
    /// Nothing to renew, which is different from a renewal that has lapsed.
    NotArchived,
    /// The archival timestamp's authority certificate is still valid.
    Current {
        /// When that certificate expires — the date by which re-timestamping
        /// has to have happened.
        expires: DateTime<Utc>,
    },
    /// It has expired. The archival protection has lapsed.
    ///
    /// The seal may still verify today; what is gone is the thing that was
    /// meant to keep it verifying once its signing certificate goes.
    Lapsed {
        /// When the authority's certificate expired. The same value
        /// [`Self::Current`] carries, read from the other side of it.
        expires: DateTime<Utc>,
    },
    /// An archival timestamp is present and could not be read.
    ///
    /// **Not [`Self::Current`].** A token that cannot be checked is not a fresh
    /// one, and reporting it as current is how a staleness signal goes quiet at
    /// the moment it matters.
    Unknown,
}

/// Read how much life is left in a seal's archival timestamp.
///
/// # What is checked, and the one thing that is not
///
/// The token's own signature is verified, so a fabricated archival timestamp
/// does not produce a reassuring date. What is **not** checked is that the token
/// archives *this* seal: the `archive-time-stamp-v3` imprint is computed over the
/// concatenation EN 319 122-1 clause 5.5.3 specifies together with an
/// `ats-hash-index-v3`, neither of which this crate builds or reads — see
/// `local::LocalIdentity::sign_detached_at`, which says the same thing from the
/// writing side.
///
/// So this answers *"is there archival protection here, and has it lapsed?"* and
/// not *"is this seal archived?"*. The distinction matters for a seal from
/// elsewhere and not at all for one this node made.
///
/// The **latest** timestamp decides, by `genTime`. A renewal chain is a sequence
/// of archive timestamps each covering the one before it, and it is the newest
/// that carries the protection forward — reading an older one would report a
/// renewed seal as lapsed.
///
/// # Errors
///
/// [`SealError::Backend`] when the seal itself cannot be read.
pub fn archival_freshness(
    seal_der: &[u8],
    now: DateTime<Utc>,
) -> Result<ArchivalFreshness, SealError> {
    let signed = parse(seal_der)?;
    let Some(attrs) = signed.signer.unsigned_attrs.as_ref() else {
        return Ok(ArchivalFreshness::NotArchived);
    };

    let archival: Vec<_> = attrs
        .iter()
        .filter(|a| {
            a.oid == ID_AA_ETS_ARCHIVE_TIMESTAMP_V3 || a.oid == ID_AA_ETS_ARCHIVE_TIMESTAMP_V2
        })
        .collect();
    if archival.is_empty() {
        return Ok(ArchivalFreshness::NotArchived);
    }

    // The newest readable token wins. An unreadable one among several is not
    // fatal — but if *none* reads, the answer is unknown rather than absent.
    let mut newest: Option<(DateTime<Utc>, DateTime<Utc>)> = None;
    for attr in archival {
        for value in attr.values.as_slice() {
            let Some((made_at, expires)) = archival_token(value) else {
                continue;
            };
            if newest.is_none_or(|(seen, _)| made_at > seen) {
                newest = Some((made_at, expires));
            }
        }
    }

    let Some((_, expires)) = newest else {
        return Ok(ArchivalFreshness::Unknown);
    };
    Ok(if expires > now {
        ArchivalFreshness::Current { expires }
    } else {
        ArchivalFreshness::Lapsed { expires }
    })
}

/// One archive timestamp's `(genTime, authority certificate expiry)`.
///
/// `None` when the token cannot be read or its signature does not hold — a
/// token that failed its check must not contribute a date.
fn archival_token(value: &der::Any) -> Option<(DateTime<Utc>, DateTime<Utc>)> {
    let token_der = value.to_der().ok()?;
    let token = parse(&token_der).ok()?;
    if !signature_holds(&token).unwrap_or(false) {
        return None;
    }
    let content = token.econtent.as_ref()?;
    if !digest_matches(&token, content) {
        return None;
    }
    let info = TstInfo::from_der(content).ok()?;

    let made_at = to_utc(info.gen_time.to_unix_duration().as_secs())?;
    let expires = to_utc(
        token
            .certificate
            .tbs_certificate
            .validity
            .not_after
            .to_unix_duration()
            .as_secs(),
    )?;
    Some((made_at, expires))
}

/// Seconds since the epoch as a UTC instant.
fn to_utc(seconds: u64) -> Option<DateTime<Utc>> {
    DateTime::from_timestamp(i64::try_from(seconds).ok()?, 0)
}

// ─── Who issued it, and where its key lives ──────────────────────────────────

/// `id-pe-qcStatements` — the extension a qualified certificate carries.
///
/// RFC 3739 §3.2.6, as profiled by ETSI EN 319 412-5. Its absence is itself a
/// finding: a certificate with no QCStatements at all is not claiming to be a
/// qualified certificate.
const ID_PE_QC_STATEMENTS: const_oid::ObjectIdentifier =
    const_oid::ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.1.3");

/// `esi4-qcStatement-4` — the key resides in a qualified creation device.
///
/// ETSI EN 319 412-5 §4.2.2. **This is the Annex III(j) indication**: Art. 32(1)(f)
/// (reached for seals through Art. 40) requires that the seal was created by a
/// qualified electronic seal creation device, and Annex III(j) requires the
/// certificate to say so "in a form suitable for automated processing". This OID
/// is that form.
const ID_ETSI_QCS_QC_SSCD: const_oid::ObjectIdentifier =
    const_oid::ObjectIdentifier::new_unwrap("0.4.0.1862.1.4");

/// One `QCStatement`, of which only the identifier is read.
///
/// RFC 3739 §3.2.6. The optional `statementInfo` is decoded so the structure
/// parses, and then ignored — presence of the identifier is the whole signal,
/// and reading further would invite treating a declaration as a verification.
#[derive(der::Sequence)]
struct QcStatement {
    id: const_oid::ObjectIdentifier,
    #[asn1(optional = "true")]
    _info: Option<der::Any>,
}

/// The signer certificate's issuer, subject, and Annex III(j) indication.
///
/// Read out of the seal rather than taken from configuration, deliberately. A
/// node knows which backend it was told to use; it does not thereby know what
/// the returned bytes contain, and a verdict founded on a configuration flag
/// attests the operator's intent rather than the seal. Everything here comes
/// from the certificate the seal carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignerCertificate {
    /// The issuer distinguished name, RFC 4514, for reading.
    pub issuer: String,
    /// The subject distinguished name, RFC 4514, for reading.
    pub subject: String,
    /// DER of the issuer distinguished name, for matching.
    ///
    /// The bytes rather than the string, because this is what gets compared
    /// against a listed CA's *subject* and a string comparison would depend on
    /// how two independent implementations chose to escape a name.
    pub issuer_der: Vec<u8>,
    /// Whether issuer and subject are the same name — a self-signed certificate.
    ///
    /// The structural test for "nobody issued this to us". It is a property of
    /// the certificate, so it cannot be misconfigured into being false.
    pub self_issued: bool,
    /// What the certificate declares about the creation device.
    pub creation_device: CreationDevice,
}

impl SignerCertificate {
    /// The shareable half — everything but the bytes used for matching.
    ///
    /// [`Self::issuer_der`] stays behind: it exists so a listed CA's subject can
    /// be compared exactly, which is this crate's business and nobody else's.
    #[must_use]
    pub fn origin(&self) -> SealOrigin {
        SealOrigin {
            subject: self.subject.clone(),
            issuer: self.issuer.clone(),
            self_issued: self.self_issued,
            creation_device: self.creation_device,
        }
    }
}

/// Read the signer certificate's issuer, subject and device indication.
///
/// Says nothing about whether the seal verifies — that is
/// [`verify_against_embedded_certificate`], and the two are deliberately
/// separate: *who issued this* and *does it check out* are different questions,
/// and a caller that wants a trust verdict needs both answered rather than one
/// standing in for the other.
///
/// # Errors
///
/// [`SealError::Backend`] when the bytes are not a readable CMS seal.
pub fn signer_certificate(seal_der: &[u8]) -> Result<SignerCertificate, SealError> {
    let signed = parse(seal_der)?;
    let tbs = &signed.certificate.tbs_certificate;

    let issuer_der = tbs
        .issuer
        .to_der()
        .map_err(|e| malformed(format!("cannot re-encode the issuer name: {e}")))?;
    let subject_der = tbs
        .subject
        .to_der()
        .map_err(|e| malformed(format!("cannot re-encode the subject name: {e}")))?;

    Ok(SignerCertificate {
        issuer: tbs.issuer.to_string(),
        subject: tbs.subject.to_string(),
        self_issued: issuer_der == subject_der,
        issuer_der,
        creation_device: creation_device(tbs),
    })
}

/// Whether a given certificate authority actually signed the seal's certificate.
///
/// Three outcomes rather than a boolean, because *this CA did not sign it* and
/// *the check could not be run* send a reader in opposite directions. Collapsing
/// them would either brand a lawful seal a forgery or let an unrunnable check
/// read as a clean miss — the same split [`super::trustlist`] draws between a
/// document signed by the wrong key and one altered after signing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IssuerCheck {
    /// The issuer's public key verifies its signature over the seal
    /// certificate's `tbsCertificate`. This CA issued it.
    Verified,
    /// The signature does not verify under this issuer's key.
    ///
    /// Not an error: it is a finding, and the one that catches a certificate
    /// relabelled with a listed CA's name.
    NotSignedByThisIssuer,
    /// The check could not be run at all.
    ///
    /// An unreadable issuer certificate, or a key algorithm this build does not
    /// verify — see the `x509-verify` feature list in `Cargo.toml`, which is
    /// pinned to the algorithms actually measured in the published lists. Never
    /// to be reported as either of the above.
    Unverifiable(String),
}

/// The DER of every issuer name the seal's embedded certificates refer to.
///
/// What a caller needs to decide **which** trust anchors are worth trying. The
/// signer's own issuer is not enough on its own: where a trusted list publishes
/// self-signed roots — Italy's does, for 194 of its 203 entries — the anchor's
/// subject matches the *intermediate's* issuer, one link further up, and a
/// caller filtering on the signer's issuer alone would find no candidate and
/// report an unlisted provider.
///
/// Duplicates are removed; order is not meaningful.
///
/// # Errors
///
/// [`SealError::Backend`] when the seal cannot be read.
pub fn chain_issuer_names(seal_der: &[u8]) -> Result<Vec<Vec<u8>>, SealError> {
    let signed = parse(seal_der)?;
    let mut names: Vec<Vec<u8>> = Vec::new();
    for certificate in &signed.chain {
        if let Ok(der) = certificate.tbs_certificate.issuer.to_der()
            && !names.contains(&der)
        {
            names.push(der);
        }
    }
    Ok(names)
}

/// How far a certificate path may be walked before it is treated as a loop.
///
/// Real chains are two or three links. The cap is not a tuning parameter: the
/// certificates come out of a seal an operator was handed, so a hostile one may
/// carry a chain shaped to make this walk expensive.
const MAX_PATH_LENGTH: usize = 8;

/// Check whether the seal's certificate chains to `anchor_certificate_der`.
///
/// **A path check against one anchor, not a path builder.** The trust anchor is
/// established elsewhere — the Official Journal anchors the list of trusted
/// lists, which anchors each national list, which carries this certificate — so
/// what remains is whether the seal's signer chains up to it.
///
/// Intermediates are taken **only from the seal itself**. A CAdES seal normally
/// travels with its issuing chain, and nothing here fetches a certificate over
/// the network: a path completed by a document an attacker could serve is not a
/// path. This matters more than it sounds, because Member States do not publish
/// the same thing — Italy's list carries self-signed roots, so an intermediate
/// is needed to reach them, while Finland's and France's carry the issuing CAs
/// directly and the walk finishes in one step.
///
/// Every link is verified. Reaching the anchor by name alone would let any
/// embedded certificate claim any issuer, which is the hole this whole function
/// exists to close.
///
/// Signatures are verified with the tolerant comparison rather than the strict
/// one: the strict variant refuses a non-normalised ECDSA signature, which is
/// lawful in X.509 and emitted by real certificate authorities. Using it would
/// reject genuine certificates as forgeries.
///
/// Nothing here checks a validity window or consults revocation.
///
/// # Errors
///
/// [`SealError::Backend`] when the *seal* cannot be read. A problem with the
/// *anchor* is [`IssuerCheck::Unverifiable`], not an error: the seal is fine and
/// one candidate among several could not be checked.
pub fn check_path_to(
    seal_der: &[u8],
    anchor_certificate_der: &[u8],
) -> Result<IssuerCheck, SealError> {
    let signed = parse(seal_der)?;

    let anchor = match Certificate::from_der(anchor_certificate_der) {
        Ok(c) => c,
        Err(e) => {
            return Ok(IssuerCheck::Unverifiable(format!(
                "the anchor certificate does not parse: {e}"
            )));
        }
    };
    let anchor_key = match verifying_key(&anchor) {
        Ok(k) => k,
        Err(e) => {
            return Ok(IssuerCheck::Unverifiable(format!(
                "no verifier for the anchor's key: {e}"
            )));
        }
    };

    let mut current = &signed.certificate;
    let mut seen: Vec<&x509_cert::name::Name> = Vec::new();
    for _ in 0..MAX_PATH_LENGTH {
        // The anchor first, so a chain that also embeds a copy of it cannot
        // lengthen the walk.
        if current.tbs_certificate.issuer == anchor.tbs_certificate.subject {
            return Ok(verified_under(&anchor, &anchor_key, current));
        }

        // Otherwise climb one link, using only what the seal carries. A
        // certificate is never its own issuer here: a self-signed certificate
        // that is not the anchor terminates the walk rather than looping.
        let Some(next) = signed.chain.iter().find(|c| {
            c.tbs_certificate.subject == current.tbs_certificate.issuer
                && c.tbs_certificate.subject != current.tbs_certificate.subject
        }) else {
            return Ok(IssuerCheck::NotSignedByThisIssuer);
        };
        if seen.contains(&&next.tbs_certificate.subject) {
            return Ok(IssuerCheck::Unverifiable(
                "the embedded certificates form a loop".to_owned(),
            ));
        }
        seen.push(&current.tbs_certificate.subject);

        // The intermediate must have signed the certificate below it, or the
        // chain is decoration.
        let key = match verifying_key(next) {
            Ok(k) => k,
            Err(e) => {
                return Ok(IssuerCheck::Unverifiable(format!(
                    "no verifier for an intermediate's key: {e}"
                )));
            }
        };
        match verified_under(next, &key, current) {
            IssuerCheck::Verified => {}
            other => return Ok(other),
        }
        current = next;
    }

    Ok(IssuerCheck::Unverifiable(format!(
        "the certificate path is longer than {MAX_PATH_LENGTH} links"
    )))
}

/// The signature-algorithm family an OID belongs to, where it is one this
/// module can reason about.
///
/// Prefix matching on the arc rather than an enumeration of every OID: RSA's
/// signature algorithms all sit under `1.2.840.113549.1.1`, alongside the key
/// algorithm itself, and ECDSA's under `1.2.840.10045`. A new hash in either
/// family lands in the right place without an edit here, and an OID from
/// neither family is simply unknown, which is the honest answer.
fn algorithm_family(oid: &str) -> Option<&'static str> {
    if oid.starts_with("1.2.840.113549.1.1.") {
        Some("RSA")
    } else if oid.starts_with("1.2.840.10045.") {
        Some("ECDSA")
    } else if oid == "1.3.101.112" || oid == "1.3.101.113" {
        Some("EdDSA")
    } else {
        None
    }
}

/// One link: did `issuer` sign `certificate`?
fn verified_under(
    issuer: &Certificate,
    key: &x509_verify::VerifyingKey,
    certificate: &Certificate,
) -> IssuerCheck {
    // Settle an algorithm mismatch here rather than letting the verifier report
    // it as an unrecognised OID. A certificate authority holding an RSA key
    // cannot have produced an ECDSA signature, so that pairing is a **definite**
    // non-match — and reporting it as "could not be checked" would leave the
    // commonest forgery, a self-signed P-256 certificate relabelled with an
    // RSA-keyed CA's name, looking like a gap in this build's algorithm support.
    let signature_family = algorithm_family(&certificate.signature_algorithm.oid.to_string());
    let key_family = algorithm_family(
        &issuer
            .tbs_certificate
            .subject_public_key_info
            .algorithm
            .oid
            .to_string(),
    );
    if let (Some(signature), Some(k)) = (signature_family, key_family)
        && signature != k
    {
        return IssuerCheck::NotSignedByThisIssuer;
    }

    match key.verify(certificate) {
        Ok(()) => IssuerCheck::Verified,
        // `verify` folds "does not verify" and "cannot verify this algorithm"
        // into one error type, so the signature-level one is named explicitly
        // and everything else stays unverifiable. Guessing the other way round
        // would report a forgery whenever a new algorithm appeared.
        Err(x509_verify::Error::Verification) => IssuerCheck::NotSignedByThisIssuer,
        Err(e) => IssuerCheck::Unverifiable(format!("the check could not be run: {e}")),
    }
}

/// The Annex III(j) indication, read off the QCStatements extension.
///
/// An unparseable extension reports [`CreationDevice::NoQualifiedDevice`] rather
/// than failing: the statement was not found, which is what the variant says,
/// and the failure direction that matters is never reporting a device that was
/// not declared.
fn creation_device(tbs: &x509_cert::TbsCertificate) -> CreationDevice {
    let Some(ext) = tbs
        .extensions
        .as_ref()
        .and_then(|e| e.iter().find(|e| e.extn_id == ID_PE_QC_STATEMENTS))
    else {
        return CreationDevice::NotAQualifiedCertificate;
    };

    let declared = Vec::<QcStatement>::from_der(ext.extn_value.as_bytes())
        .is_ok_and(|s| s.iter().any(|s| s.id == ID_ETSI_QCS_QC_SSCD));

    if declared {
        CreationDevice::DeclaresQualifiedDevice
    } else {
        CreationDevice::NoQualifiedDevice
    }
}

/// What this node can establish about the seal certificate's own standing:
/// its validity window, and what the seal's revocation material says.
///
/// # The second limb of Art. 32(1)(b)
///
/// Reg. (EU) No 910/2014 Art. 32(1)(b), reached for seals by Art. 40, asks two
/// things of the certificate: that a qualified provider issued it, and that it
/// **was valid at the time of signing**. Whether the issuer is qualified is a
/// trusted list question and lives in [`crate::qualification`]. This is the
/// other half, and until now nothing asked it — a certificate that had expired
/// or been revoked when the seal was made still reached the top verdict.
///
/// # Which moment, and what it is worth
///
/// "At the time of signing" is only answerable if the signing time is known, and
/// a seal's own claim about when it was made is worth nothing. So the moment
/// used is the **attested** one — the checked timestamp token, which a seal
/// carries from `B-T` upward — and `now` is the fallback, marked unattested.
///
/// That mark is load-bearing. A verdict reached against an unproven moment is
/// reported with a `NO_POE` sub-indication rather than as a failure, because a
/// certificate that has expired *since* the seal was made says nothing bad about
/// the seal: certificates expire, and sealed passports outlive them by years.
///
/// # Revocation is read from the seal, never fetched
///
/// The CRL distribution point in a certificate is a URL chosen by whoever issued
/// it, and this certificate arrived inside a seal an operator was handed.
/// Fetching it would have a background task make requests to an address the
/// input controls. The long-term profiles remove the need: ETSI EN 319 122-1
/// puts revocation values in `SignedData.crls` from `B-LT` upward precisely so a
/// seal can be checked years later, offline.
///
/// So a `B-LT` or `B-LTA` seal can be answered, and a `B-B` or `B-T` seal
/// reports `NotAvailable` — which is not a defect, only a question this material
/// cannot answer.
///
/// # Errors
///
/// Propagates a seal that will not parse. Everything narrower — no CRL, a CRL
/// from another issuer, one whose signature does not verify — is a value, not an
/// error: they are answers about the seal rather than failures to read it.
pub fn certificate_standing(
    seal_der: &[u8],
    now: DateTime<Utc>,
) -> Result<CertificateStanding, SealError> {
    let signed = parse(seal_der)?;

    let judged_at = match attested_sealing_time(seal_der)? {
        Some(at) => JudgedTime { at, attested: true },
        None => JudgedTime {
            at: now,
            attested: false,
        },
    };

    let validity = &signed.certificate.tbs_certificate.validity;
    let (Some(not_before), Some(not_after)) = (
        instant_of(validity.not_before),
        instant_of(validity.not_after),
    ) else {
        // Not a verdict of "invalid" — a refusal to guess. A window this cannot
        // read is a malformed certificate, and reporting it as expired or as
        // valid would both be inventions.
        return Err(malformed("the certificate's validity window is unreadable"));
    };
    let standing = if judged_at.at < not_before {
        WindowStanding::NotYetValid
    } else if judged_at.at > not_after {
        WindowStanding::Expired
    } else {
        WindowStanding::Inside
    };

    Ok(CertificateStanding {
        validity: ValidityWindow {
            not_before,
            not_after,
            standing,
        },
        judged_at,
        revocation: revocation_from(&signed),
    })
}

/// An ASN.1 `Time` as an instant.
///
/// Both of its encodings carry an absolute moment in UTC, so this is a unit
/// conversion and not a timezone decision. `None` only for a value outside the
/// representable range, which a caller reports rather than papers over: a
/// certificate whose window cannot be read has not been shown to be valid.
fn instant_of(t: x509_cert::time::Time) -> Option<DateTime<Utc>> {
    to_utc(t.to_unix_duration().as_secs())
}

/// What the seal's embedded CRLs say about its signing certificate.
///
/// Every step can only narrow the answer, and each narrowing is reported as what
/// it is. A CRL from another issuer says nothing about this certificate; one
/// whose signature does not verify is not evidence of anything, and treating
/// either as "not revoked" would manufacture an assurance out of material that
/// carries none.
fn revocation_from(signed: &Signed) -> RevocationStanding {
    let issuer = &signed.certificate.tbs_certificate.issuer;
    let serial = &signed.certificate.tbs_certificate.serial_number;

    let mut last_problem: Option<String> = None;
    for crl in &signed.crls {
        if &crl.tbs_cert_list.issuer != issuer {
            // Not a problem, just not about this certificate: a seal may carry
            // the CRLs for every certificate in its chain.
            continue;
        }

        // The CRL must be signed by the same issuer, checked against a
        // certificate the seal carries. Without that, a revocation list is a
        // list of numbers anybody could have written — and an attacker able to
        // add one could *unrevoke* a certificate by shipping an empty CRL.
        let Some(issuer_cert) = signed
            .chain
            .iter()
            .find(|c| &c.tbs_certificate.subject == issuer)
        else {
            last_problem = Some("the CRL's issuer certificate is not in the seal".to_owned());
            continue;
        };
        let key = match verifying_key(issuer_cert) {
            Ok(k) => k,
            Err(e) => {
                last_problem = Some(format!("no verifier for the CRL issuer's key: {e}"));
                continue;
            }
        };
        if let Err(e) = key.verify(crl) {
            last_problem = Some(format!("the CRL's own signature does not verify: {e}"));
            continue;
        }

        if let Some(entry) = crl
            .tbs_cert_list
            .revoked_certificates
            .as_ref()
            .and_then(|r| r.iter().find(|e| &e.serial_number == serial))
        {
            let Some(at) = instant_of(entry.revocation_date) else {
                last_problem = Some("the revocation date is unreadable".to_owned());
                continue;
            };
            return RevocationStanding::Revoked { at };
        }
        let Some(as_of) = instant_of(crl.tbs_cert_list.this_update) else {
            last_problem = Some("the CRL's thisUpdate is unreadable".to_owned());
            continue;
        };
        return RevocationStanding::NotRevoked { as_of };
    }

    match last_problem {
        Some(reason) => RevocationStanding::Unusable { reason },
        None => RevocationStanding::NotAvailable,
    }
}

// ─── The certificate's own standing ──────────────────────────────────────────

/// A CA, a leaf it issued, and whatever CRLs a test wants to embed.
///
/// Real certificates and a real CRL signature, because every assertion below is
/// about whether a signature checks out. A fixture that faked one would be
/// testing the fixture.
#[cfg(test)]
mod standing_tests {
    use super::*;
    use time::OffsetDateTime;

    /// Seconds, as `rcgen`'s date type.
    fn at(offset_days: i64) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(Utc::now().timestamp() + offset_days * 86_400)
            .expect("a representable date")
    }

    struct Issued {
        ca: rcgen::CertifiedIssuer<'static, rcgen::KeyPair>,
        leaf_der: Vec<u8>,
        leaf_serial: rcgen::SerialNumber,
    }

    /// A CA and a leaf whose validity window is `from`..`to`, in days from now.
    fn issue(from: i64, to: i64) -> Issued {
        issue_from("Test Issuing CA", from, to)
    }

    /// The same, under a chosen CA name — so a test can produce either a
    /// genuinely different issuer or a different key wearing the same name.
    fn issue_from(ca_name: &str, from: i64, to: i64) -> Issued {
        fn key() -> rcgen::KeyPair {
            rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("key")
        }
        let mut ca_params =
            rcgen::CertificateParams::new(vec![ca_name.to_owned()]).expect("params");
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, ca_name);
        // A CA that may sign CRLs, or `rcgen` refuses to make one with it.
        ca_params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];
        ca_params.not_before = at(-3650);
        ca_params.not_after = at(3650);
        let ca = rcgen::CertifiedIssuer::self_signed(ca_params, key()).expect("a CA");

        let mut leaf_params =
            rcgen::CertificateParams::new(vec!["Test Sealing Certificate".to_owned()])
                .expect("params");
        leaf_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "Test Sealing Certificate");
        leaf_params.not_before = at(from);
        leaf_params.not_after = at(to);
        let leaf_serial = leaf_params.serial_number.clone().unwrap_or_else(|| {
            let s = rcgen::SerialNumber::from(42u64);
            leaf_params.serial_number = Some(s.clone());
            s
        });
        let leaf = leaf_params
            .signed_by(&key(), &*ca)
            .expect("a leaf signed by the CA");

        Issued {
            ca,
            leaf_der: leaf.der().to_vec(),
            leaf_serial,
        }
    }

    /// A CRL from `issued`'s CA, listing the leaf as revoked `days` from now
    /// when `revoked` is set.
    fn crl(issued: &Issued, revoked: Option<i64>) -> x509_cert::crl::CertificateList {
        let params = rcgen::CertificateRevocationListParams {
            this_update: at(0),
            next_update: at(30),
            crl_number: rcgen::SerialNumber::from(1u64),
            issuing_distribution_point: None,
            key_identifier_method: rcgen::KeyIdMethod::Sha256,
            revoked_certs: revoked
                .map(|days| rcgen::RevokedCertParams {
                    serial_number: issued.leaf_serial.clone(),
                    revocation_time: at(days),
                    reason_code: Some(rcgen::RevocationReason::KeyCompromise),
                    invalidity_date: None,
                })
                .into_iter()
                .collect(),
        };
        let der = params
            .signed_by(&issued.ca)
            .expect("a signed CRL")
            .der()
            .to_vec();
        x509_cert::crl::CertificateList::from_der(&der).expect("the CRL parses")
    }

    /// A seal carrying `certificates` and `crls`, built from a real local seal
    /// so the CMS structure is one this crate actually produces.
    fn seal_with(
        certificates: &[Vec<u8>],
        crls: &[x509_cert::crl::CertificateList],
    ) -> (Vec<u8>, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let id = crate::local::LocalIdentity::load_or_create(dir.path()).expect("identity");
        let der = id.sign_detached(&[0x22; 32]).expect("sign");

        let info = ContentInfo::from_der(&der).expect("CMS");
        let mut sd: SignedData = info.content.decode_as().expect("SignedData");

        let parsed: Vec<Certificate> = certificates
            .iter()
            .map(|d| Certificate::from_der(d).expect("a certificate"))
            .collect();
        let mut certs = der::asn1::SetOfVec::new();
        for c in &parsed {
            certs
                .insert(cms::cert::CertificateChoices::Certificate(c.clone()))
                .expect("certificate");
        }
        sd.certificates = Some(cms::signed_data::CertificateSet(certs));

        // The signer must name the certificate under test, or the parser refuses
        // the seal before any of this is reached.
        let mut signers = sd.signer_infos.0.as_slice().to_vec();
        signers[0].sid = cms::signed_data::SignerIdentifier::IssuerAndSerialNumber(
            cms::cert::IssuerAndSerialNumber {
                issuer: parsed[0].tbs_certificate.issuer.clone(),
                serial_number: parsed[0].tbs_certificate.serial_number.clone(),
            },
        );
        let mut set = der::asn1::SetOfVec::new();
        set.insert(signers.remove(0)).expect("signer");
        sd.signer_infos = cms::signed_data::SignerInfos::from(set);

        if !crls.is_empty() {
            let mut choices = der::asn1::SetOfVec::new();
            for crl in crls {
                choices
                    .insert(cms::revocation::RevocationInfoChoice::Crl(crl.clone()))
                    .expect("crl");
            }
            sd.crls = Some(cms::revocation::RevocationInfoChoices(choices));
        }

        let reencoded = ContentInfo {
            content_type: const_oid::db::rfc5911::ID_SIGNED_DATA,
            content: der::Any::encode_from(&sd).expect("encode"),
        }
        .to_der()
        .expect("re-encode");
        (reencoded, dir)
    }

    /// **A certificate that expired before now is reported expired.**
    ///
    /// The gap #323 named: nothing read `notAfter`, so a seal made with a
    /// long-dead certificate reached the same verdict as one made yesterday.
    #[test]
    fn an_expired_certificate_is_seen_to_be_expired() {
        let issued = issue(-400, -30);
        let (seal, _dir) = seal_with(&[issued.leaf_der.clone(), issued.ca.der().to_vec()], &[]);

        let standing = certificate_standing(&seal, Utc::now()).expect("readable");
        assert_eq!(standing.validity.standing, WindowStanding::Expired);
        assert!(standing.validity.not_after < Utc::now());
        assert!(
            !standing.judged_at.attested,
            "a local seal carries a timestamp from a TSA this node also runs, but nothing \
             here attests to a *provider's* time — the flag is what stops an unproven \
             moment being reported as a failure"
        );
    }

    /// A certificate valid now is inside its window, and the window is reported
    /// so a reader can check the arithmetic rather than trust the verdict.
    #[test]
    fn a_current_certificate_is_inside_its_window() {
        let issued = issue(-30, 400);
        let (seal, _dir) = seal_with(&[issued.leaf_der.clone(), issued.ca.der().to_vec()], &[]);

        let standing = certificate_standing(&seal, Utc::now()).expect("readable");
        assert_eq!(standing.validity.standing, WindowStanding::Inside);
        assert!(standing.validity.not_before < standing.validity.not_after);
    }

    /// **A revoked certificate is found, from the seal's own CRL.**
    ///
    /// No network: the CRL travels inside the seal, which is what ETSI's
    /// long-term profiles put it there for.
    #[test]
    fn a_revoked_certificate_is_found_in_the_seals_own_crl() {
        let issued = issue(-30, 400);
        let revocation = crl(&issued, Some(-1));
        let (seal, _dir) = seal_with(
            &[issued.leaf_der.clone(), issued.ca.der().to_vec()],
            &[revocation],
        );

        let standing = certificate_standing(&seal, Utc::now()).expect("readable");
        match standing.revocation {
            RevocationStanding::Revoked { at } => assert!(at < Utc::now()),
            other => panic!("expected a revocation, got {other:?}"),
        }
    }

    /// A CRL that covers the certificate and does not list it says so, and says
    /// *as of when* — a CRL older than the seal cannot rule out a later
    /// revocation, and the field is there so a reader can see which question was
    /// answered.
    #[test]
    fn a_clean_crl_reports_the_moment_it_speaks_for() {
        let issued = issue(-30, 400);
        let (seal, _dir) = seal_with(
            &[issued.leaf_der.clone(), issued.ca.der().to_vec()],
            &[crl(&issued, None)],
        );

        let standing = certificate_standing(&seal, Utc::now()).expect("readable");
        match standing.revocation {
            RevocationStanding::NotRevoked { as_of } => {
                assert!((Utc::now() - as_of).num_minutes().abs() < 5);
            }
            other => panic!("expected a clean CRL, got {other:?}"),
        }
    }

    /// **A CRL nobody signed for is not evidence.**
    ///
    /// The attack this closes is the interesting direction: an empty CRL
    /// *unrevokes* a certificate. Anyone able to add one to a seal could turn a
    /// revoked certificate into a clean report, so the list's own signature is
    /// checked against a certificate the seal carries before a word of it is
    /// believed.
    #[test]
    fn a_crl_whose_signature_does_not_verify_is_unusable() {
        let issued = issue(-30, 400);
        let mut tampered = crl(&issued, Some(-1));
        // Drop the revocation, leaving the signature over the original content.
        tampered.tbs_cert_list.revoked_certificates = None;
        let (seal, _dir) = seal_with(
            &[issued.leaf_der.clone(), issued.ca.der().to_vec()],
            &[tampered],
        );

        let standing = certificate_standing(&seal, Utc::now()).expect("readable");
        match standing.revocation {
            RevocationStanding::Unusable { reason } => {
                assert!(
                    reason.contains("signature"),
                    "the reason must name what failed: {reason}"
                );
            }
            other => panic!("a tampered CRL must not be believed, got {other:?}"),
        }
    }

    /// A seal carrying no revocation material says so, and that is not a defect:
    /// `B-B` and `B-T` seals are not required to carry any.
    #[test]
    fn a_seal_with_no_crl_reports_that_it_could_not_ask() {
        let issued = issue(-30, 400);
        let (seal, _dir) = seal_with(&[issued.leaf_der.clone(), issued.ca.der().to_vec()], &[]);

        let standing = certificate_standing(&seal, Utc::now()).expect("readable");
        assert_eq!(standing.revocation, RevocationStanding::NotAvailable);
    }

    /// A CRL from a different issuer is silently not about this certificate —
    /// neither an answer nor a problem. A seal legitimately carries the CRLs for
    /// every certificate in its chain.
    #[test]
    fn a_crl_from_another_issuer_is_not_an_answer() {
        let issued = issue(-30, 400);
        let other = issue_from("Some Other CA", -30, 400);
        let (seal, _dir) = seal_with(
            &[issued.leaf_der.clone(), issued.ca.der().to_vec()],
            &[crl(&other, Some(-1))],
        );

        let standing = certificate_standing(&seal, Utc::now()).expect("readable");
        assert_eq!(
            standing.revocation,
            RevocationStanding::NotAvailable,
            "another CA's list says nothing about this certificate, in either direction"
        );
    }

    /// **A CRL wearing the issuer's name, signed by another key, is refused.**
    ///
    /// The same asymmetry #323 was opened about, one level down: a name is not a
    /// signature. Matching a CRL to a certificate by issuer name alone would let
    /// anyone who can put bytes in a seal revoke a certificate they do not
    /// control — or, worse in the other direction, clear a revoked one by
    /// shipping an empty list under the right name.
    ///
    /// The answer is `unusable` rather than `notAvailable` on purpose: something
    /// claiming to be authoritative was there and did not check out, which is
    /// worth looking at. Silence would file it beside "no CRL was included",
    /// which is an ordinary state of a `B-T` seal.
    #[test]
    fn a_crl_naming_the_issuer_but_signed_by_another_key_is_unusable() {
        let issued = issue(-30, 400);
        // Same subject name, freshly generated key.
        let impostor = issue(-30, 400);
        let (seal, _dir) = seal_with(
            &[issued.leaf_der.clone(), issued.ca.der().to_vec()],
            &[crl(&impostor, Some(-1))],
        );

        let standing = certificate_standing(&seal, Utc::now()).expect("readable");
        match standing.revocation {
            RevocationStanding::Unusable { reason } => assert!(
                reason.contains("signature"),
                "the reason must name what failed: {reason}"
            ),
            other => panic!("a CRL under a borrowed name must not be believed, got {other:?}"),
        }
    }
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

    // ─── attested sealing time ───────────────────────────────────────────────

    /// A timestamped seal reports a time a third party attests, not our clock.
    #[test]
    fn a_timestamped_seal_reports_an_attested_time() {
        let dir = tempfile::tempdir().expect("tempdir");
        let id = crate::local::LocalIdentity::load_or_create(dir.path()).expect("identity");
        let der = id
            .sign_detached_at(&[0x11; 32], SealConformanceLevel::BaselineT)
            .expect("sign");

        let attested = attested_sealing_time(&der)
            .expect("readable")
            .expect("a B-T seal carries a timestamp");

        let drift = (chrono::Utc::now() - attested).num_seconds().abs();
        assert!(
            drift < 300,
            "the attested time should be about now: {attested}"
        );
    }

    /// A `B-B` seal carries no timestamp, and reports none rather than a guess.
    ///
    /// The distinction the whole function exists for: no attested time is a
    /// different answer from the node's own clock, and `SealedEnvelope::sealed_at`
    /// is the latter.
    #[test]
    fn a_seal_with_no_timestamp_attests_no_time() {
        let dir = tempfile::tempdir().expect("tempdir");
        let id = crate::local::LocalIdentity::load_or_create(dir.path()).expect("identity");
        let der = id.sign_detached(&[0x11; 32]).expect("sign");

        assert_eq!(attested_sealing_time(&der).expect("readable"), None);
    }

    /// **A genuine token lifted from another seal is refused.**
    ///
    /// The attack the imprint check exists for, and the reason verifying the
    /// token's own signature is not enough on its own. `signature-time-stamp` is
    /// an *unsigned* attribute — the seal's signature does not cover it — so
    /// swapping the whole token costs nothing. The token moved here is perfectly
    /// valid: real authority, sound signature, real `genTime`. It is simply a
    /// timestamp of a *different* signature.
    ///
    /// EN 319 122-1 clause 5.3 says the imprint is over this `SignerInfo`'s
    /// signature value, so checking it is what ties the time to this seal.
    #[test]
    fn a_timestamp_token_from_another_seal_is_refused() {
        use cms::content_info::ContentInfo;
        use cms::signed_data::SignedData;

        let dir = tempfile::tempdir().expect("tempdir");
        let id = crate::local::LocalIdentity::load_or_create(dir.path()).expect("identity");
        let mine = id
            .sign_detached_at(&[0x11; 32], SealConformanceLevel::BaselineT)
            .expect("sign");
        // A second seal over different content, so its timestamp covers a
        // different signature value.
        let theirs = id
            .sign_detached_at(&[0x22; 32], SealConformanceLevel::BaselineT)
            .expect("sign");

        let borrowed = {
            let info = ContentInfo::from_der(&theirs).expect("CMS");
            let sd: SignedData = info.content.decode_as().expect("SignedData");
            sd.signer_infos.0.as_slice()[0]
                .unsigned_attrs
                .as_ref()
                .expect("a B-T seal has unsigned attributes")
                .iter()
                .find(|a| a.oid == ID_AA_SIGNATURE_TIME_STAMP_TOKEN)
                .expect("a signature timestamp")
                .clone()
        };

        let info = ContentInfo::from_der(&mine).expect("CMS");
        let mut sd: SignedData = info.content.decode_as().expect("SignedData");
        let mut signers = sd.signer_infos.0.as_slice().to_vec();
        let mut attrs = der::asn1::SetOfVec::new();
        attrs.insert(borrowed).expect("attribute");
        signers[0].unsigned_attrs = Some(attrs);
        let mut set = der::asn1::SetOfVec::new();
        set.insert(signers.remove(0)).expect("signer");
        sd.signer_infos = cms::signed_data::SignerInfos::from(set);

        let swapped = ContentInfo {
            content_type: const_oid::db::rfc5911::ID_SIGNED_DATA,
            content: der::Any::encode_from(&sd).expect("encode"),
        }
        .to_der()
        .expect("re-encode");

        assert_eq!(
            attested_sealing_time(&swapped).expect("readable"),
            None,
            "a valid token over someone else's signature must not become this seal's time"
        );
    }

    // ─── archival freshness ──────────────────────────────────────────────────

    /// A `B-LTA` seal reports when its archival protection has to be renewed.
    #[test]
    fn an_archived_seal_reports_a_renewal_date() {
        let dir = tempfile::tempdir().expect("tempdir");
        let id = crate::local::LocalIdentity::load_or_create(dir.path()).expect("identity");
        let der = id
            .sign_detached_at(&[0x11; 32], SealConformanceLevel::BaselineLta)
            .expect("sign");

        let ArchivalFreshness::Current { expires: renew_by } =
            archival_freshness(&der, chrono::Utc::now()).expect("readable")
        else {
            panic!("a fresh LTA seal is current");
        };
        assert!(
            renew_by > chrono::Utc::now(),
            "the renewal date must be in the future: {renew_by}"
        );
    }

    /// The same seal, read from far enough in the future, reports the lapse.
    ///
    /// The whole point of the signal. Nothing about the seal changes — only the
    /// clock — which is exactly how this failure arrives in practice: on a date
    /// nobody has in a calendar, years after the passport was locked.
    #[test]
    fn the_same_seal_read_later_reports_that_it_lapsed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let id = crate::local::LocalIdentity::load_or_create(dir.path()).expect("identity");
        let der = id
            .sign_detached_at(&[0x11; 32], SealConformanceLevel::BaselineLta)
            .expect("sign");

        let ArchivalFreshness::Current { expires: renew_by } =
            archival_freshness(&der, chrono::Utc::now()).expect("readable")
        else {
            panic!("current now");
        };
        let after = renew_by + chrono::Duration::seconds(1);

        assert_eq!(
            archival_freshness(&der, after).expect("readable"),
            ArchivalFreshness::Lapsed { expires: renew_by },
            "past its authority's certificate, the archival protection is gone"
        );
    }

    /// A seal with no archival timestamp has nothing to renew, and says so.
    ///
    /// `NotArchived` is not `Lapsed`: a `B-LT` seal was never promised long-term
    /// protection, and reporting it as lapsed would raise an alarm about a
    /// commitment nobody made.
    #[test]
    fn a_seal_below_lta_has_nothing_to_renew() {
        let dir = tempfile::tempdir().expect("tempdir");
        let id = crate::local::LocalIdentity::load_or_create(dir.path()).expect("identity");
        let der = id
            .sign_detached_at(&[0x11; 32], SealConformanceLevel::BaselineLt)
            .expect("sign");

        assert_eq!(
            archival_freshness(&der, chrono::Utc::now()).expect("readable"),
            ArchivalFreshness::NotArchived
        );
    }

    /// The level says `BaselineLta` either way — which is why this exists.
    ///
    /// `evidenced_level` reports the *presence* of the archival material, and is
    /// right to: the material is there. The two answers together are the finding
    /// — a seal that still evidences LTA and whose archival protection has gone.
    #[test]
    fn a_lapsed_seal_still_evidences_lta() {
        let dir = tempfile::tempdir().expect("tempdir");
        let id = crate::local::LocalIdentity::load_or_create(dir.path()).expect("identity");
        let der = id
            .sign_detached_at(&[0x11; 32], SealConformanceLevel::BaselineLta)
            .expect("sign");

        // Past the local authority's certificate, which runs to 4096.
        let far_future = "9999-01-01T00:00:00Z"
            .parse::<chrono::DateTime<chrono::Utc>>()
            .expect("a representable instant");
        assert!(matches!(
            archival_freshness(&der, far_future).expect("readable"),
            ArchivalFreshness::Lapsed { .. }
        ));
        assert_eq!(
            evidenced_level(&der).expect("readable"),
            Some(SealConformanceLevel::BaselineLta),
            "the level is unchanged, which is exactly how this goes unnoticed"
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
