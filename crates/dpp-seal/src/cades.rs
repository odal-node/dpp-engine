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

use cms::cert::CertificateChoices;
use cms::content_info::ContentInfo;
use cms::signed_data::{SignedData, SignerInfo};
use der::{Decode as _, Encode as _};
use dpp_domain::seal::SealConformanceLevel;
use dpp_types::{CreationDevice, SealOrigin};
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

    let key = verifying_key(&signed.certificate)?;

    // Re-encode as SET OF, matching what was signed (RFC 5652 §5.4) rather than
    // the `[0] IMPLICIT` form the attributes take inside `SignerInfo`. Verifying
    // the wrong one fails against every correct seal in existence.
    let to_verify = signed_attrs
        .to_der()
        .map_err(|e| malformed(format!("cannot re-encode the signed attributes: {e}")))?;

    let signature = x509_verify::SignatureRef::new(
        &signed.signer.signature_algorithm,
        signed.signer.signature.as_bytes(),
    );

    let message = x509_verify::MessageOwned::from(to_verify);
    match key.verify(x509_verify::VerifyInfo::new(message, signature)) {
        Ok(()) => Ok(true),
        Err(x509_verify::Error::Verification) => Ok(false),
        // An algorithm this build cannot check is **not** a failed signature.
        // Returning `false` would report a possibly-sound seal as broken, and the
        // binding built on this would call it retargeted.
        Err(e) => Err(malformed(format!(
            "the signature could not be checked: {e}"
        ))),
    }
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
