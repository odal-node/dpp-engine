//! Who issued it, and where its key lives; and the certificate's own standing.

use chrono::{DateTime, Utc};
use der::{Decode as _, Encode as _};
use dpp_types::{
    CertificateStanding, CreationDevice, JudgedTime, RevocationStanding, SealOrigin,
    ValidityWindow, WindowStanding,
};

use super::signature::verifying_key;
use super::signed::Signed;
use super::signed::malformed;
use super::signed::parse;
use super::timestamp::to_utc;
use crate::error::SealError;

/// `id-pe-qcStatements` — the extension a qualified certificate carries.
///
/// RFC 3739 §3.2.6, as profiled by ETSI EN 319 412-5. Its absence is itself a
/// finding: a certificate with no QCStatements at all is not claiming to be a
/// qualified certificate.
pub(super) const ID_PE_QC_STATEMENTS: const_oid::ObjectIdentifier =
    const_oid::ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.1.3");

/// `esi4-qcStatement-4` — the key resides in a qualified creation device.
///
/// ETSI EN 319 412-5 §4.2.2. **This is the Annex III(j) indication**: Art. 32(1)(f)
/// (reached for seals through Art. 40) requires that the seal was created by a
/// qualified electronic seal creation device, and Annex III(j) requires the
/// certificate to say so "in a form suitable for automated processing". This OID
/// is that form.
pub(super) const ID_ETSI_QCS_QC_SSCD: const_oid::ObjectIdentifier =
    const_oid::ObjectIdentifier::new_unwrap("0.4.0.1862.1.4");

/// One `QCStatement`, of which only the identifier is read.
///
/// RFC 3739 §3.2.6. The optional `statementInfo` is decoded so the structure
/// parses, and then ignored — presence of the identifier is the whole signal,
/// and reading further would invite treating a declaration as a verification.
#[derive(der::Sequence)]
pub(super) struct QcStatement {
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

/// The Annex III(j) indication, read off the QCStatements extension.
///
/// An unparseable extension reports [`CreationDevice::NoQualifiedDevice`] rather
/// than failing: the statement was not found, which is what the variant says,
/// and the failure direction that matters is never reporting a device that was
/// not declared.
pub(super) fn creation_device(tbs: &x509_cert::TbsCertificate) -> CreationDevice {
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
/// # 🚨 The moment is an argument, not something read here
///
/// `attested` is the time the **caller** is willing to treat as a proof of
/// existence, and this function deliberately cannot work it out for itself. A
/// token's own checks (see [`attested_sealing_time`]) establish that the time is
/// genuinely what the token says, not that anybody should believe the authority
/// that said it — and a time from an authority nobody lists would settle the very
/// finding it is the evidence for. Whether the authority is a qualified one is a
/// Trusted List question, and this module holds no lists.
///
/// So the caller that does hold them passes the token's time only when the
/// authority qualifies, and `None` otherwise; this function reads the seal the
/// same way either way. Reading the token here would have left a way to ask the
/// question without the gate, and a way nobody is meant to use is one somebody
/// eventually does.
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
    attested: Option<DateTime<Utc>>,
) -> Result<CertificateStanding, SealError> {
    let signed = parse(seal_der)?;

    let judged_at = match attested {
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
pub(super) fn instant_of(t: x509_cert::time::Time) -> Option<DateTime<Utc>> {
    to_utc(t.to_unix_duration().as_secs())
}

/// What the seal's embedded CRLs say about its signing certificate.
///
/// Every step can only narrow the answer, and each narrowing is reported as what
/// it is. A CRL from another issuer says nothing about this certificate; one
/// whose signature does not verify is not evidence of anything, and treating
/// either as "not revoked" would manufacture an assurance out of material that
/// carries none.
pub(super) fn revocation_from(signed: &Signed) -> RevocationStanding {
    let issuer = &signed.certificate.tbs_certificate.issuer;
    let serial = &signed.certificate.tbs_certificate.serial_number;

    let mut last_problem: Option<String> = None;
    // The newest clean answer, kept rather than returned. A seal may carry
    // several CRLs from the same issuer — a long-term seal accumulates them —
    // and returning on the first that verifies would report `notRevoked` from a
    // stale list while a later one carries the revocation. A revocation found
    // anywhere ends the search; nothing else can.
    let mut clean: Option<DateTime<Utc>> = None;
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
        if clean.is_none_or(|seen| as_of > seen) {
            clean = Some(as_of);
        }
    }

    match (clean, last_problem) {
        // A list that answered outranks one that failed: something usable was
        // found, and the failure of another copy does not unsay it.
        (Some(as_of), _) => RevocationStanding::NotRevoked { as_of },
        (None, Some(reason)) => RevocationStanding::Unusable { reason },
        (None, None) => RevocationStanding::NotAvailable,
    }
}

#[cfg(test)]
#[path = "certificate_tests.rs"]
mod tests;
