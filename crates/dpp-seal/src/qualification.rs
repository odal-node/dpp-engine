//! Whether a seal was made under a qualified provider, or signed here.
//!
//! The question this answers is the one an operator, an auditor and a market
//! surveillance authority all ask first, and which nothing in this crate could
//! answer before: **did a qualified trust service provider issue the certificate
//! behind this seal, or did the node sign it itself?** A node running the local
//! development backend produces seals that verify perfectly and mean nothing
//! legally, and until now the two were distinguishable only by knowing which
//! backend was configured.
//!
//! Everything here is read out of the seal. Configuration is not consulted,
//! deliberately: a node knows which backend it was *told* to use, which attests
//! the operator's intent rather than the bytes that came back.
//!
//! # What this reaches, and what it does not
//!
//! Regulation (EU) No 910/2014 Art. 40 applies Art. 32 to seals *mutatis
//! mutandis*, and Art. 32(1) has two legs that an ordinary AdES validation does
//! not reach:
//!
//! - **Art. 32(1)(a)–(b)** — the certificate was a qualified certificate issued
//!   by a QTSP. A Trusted List question (Art. 22), answered here by
//!   [`IssuerStanding`].
//! - **Art. 32(1)(f)** — the seal was created by a qualified electronic seal
//!   creation device, which **Annex III(j)** requires the certificate to declare
//!   in machine-processable form. Answered here by
//!   [`CreationDevice`](dpp_types::CreationDevice).
//!
//! Two legs, so two fields rather than one ladder: they are independent, and a
//! seal can hold either without the other.
//!
//! ## This does not produce `SealChecks::QualifiedValidation`
//!
//! Stated here because the gap is one step and is easy to overlook once the
//! verdict reads `QualifiedAtSealing`.
//!
//! The issuer is matched by **name**: the seal certificate's issuer
//! distinguished name against the subject of a CA certificate the list carries.
//! That identifies which listed CA the seal *claims* to come from. It does not
//! verify that the CA actually issued it — no certificate path is built and no
//! signature of the CA over the seal certificate is checked. Anyone can mint a
//! self-signed certificate bearing a listed CA's name, and it would land in
//! [`IssuerStanding::QualifiedAtSealing`] here.
//!
//! So this is a **trust-status report about a named issuer**, not a validation.
//! It is the right input to a qualified validation and the wrong thing to mistake
//! for one, which is why nothing in this module returns a
//! [`SealChecks`](dpp_domain::seal::SealChecks) at all — a rung would be claimed
//! by whoever wired it up next, and the missing step would go with it.
//!
//! Path verification is the work that closes it, and it needs a signature
//! verifier covering the algorithms real QTSP certificate authorities use — RSA
//! among them, which this crate cannot do today.

use base64::Engine as _;
use chrono::{DateTime, Utc};
use der::{Decode as _, Encode as _};
use dpp_domain::trusted_list::{TrustServiceStatus, TrustServiceType};

use crate::cades::{SignerCertificate, signer_certificate};
use crate::error::SealError;
use crate::trustlist::VerifiedTrustedList;
use dpp_types::CreationDevice;

/// What the Trusted Lists say about the certificate's issuer.
///
/// "At sealing" throughout, never "now". A provider granted qualified status in
/// 2029 was not qualified in 2027, and a present-tense check would certify a seal
/// that never was; a provider withdrawn last week did not retroactively unmake
/// the seals it issued. Art. 32(1)(b) asks about the time of sealing, and trusted
/// lists carry the history to answer it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IssuerStanding {
    /// The certificate is its own issuer — nobody issued it to this node.
    ///
    /// What the local development backend produces, and a structural property of
    /// the certificate rather than a configuration flag, so it cannot be turned
    /// off by an environment variable. A seal here carries **no legal weight
    /// whatsoever**; it attests that a key this node holds signed a digest.
    SelfIssued {
        /// The subject name, which is also the issuer name.
        subject: String,
    },
    /// Some provider issued it, and no list consulted names that issuer as a
    /// qualified CA.
    ///
    /// Note **consulted**: this is a statement about the lists that were passed
    /// in, not about the Union. A caller holding one Member State's list and
    /// getting this answer has learnt that the issuer is not in *that* list.
    NotListed {
        /// The issuer name the certificate carries.
        issuer: String,
    },
    /// The issuer is a listed CA, but was not granted qualified status when the
    /// seal was made.
    NotQualifiedAtSealing {
        /// The issuer name.
        issuer: String,
        /// The provider the list files that CA under.
        provider: Option<String>,
        /// The list's `SchemeTerritory`.
        territory: Option<String>,
        /// The status in force at the sealing time.
        ///
        /// `None` means the list's history does not reach back that far, which
        /// is a **different finding** from a recorded non-granted status: the
        /// list is silent about that moment rather than negative about it, and
        /// another source may still answer. Collapsing the two into a boolean is
        /// how "we do not know" becomes "it was not qualified".
        status: Option<TrustServiceStatus>,
    },
    /// The issuer was a granted qualified CA when the seal was made.
    ///
    /// **This is not a qualified-seal verdict** — see the module documentation.
    /// The issuer was matched by name, so this says the seal claims an issuer
    /// that was genuinely qualified at the time, not that the issuer signed it.
    QualifiedAtSealing {
        /// The issuer name.
        issuer: String,
        /// The provider the list files that CA under.
        provider: Option<String>,
        /// The list's `SchemeTerritory`.
        territory: Option<String>,
        /// Whether the same provider also held **qualified remote seal creation
        /// device management** at the sealing time.
        ///
        /// The Art. 39a service. eIDAS 2 made managing remote qualified seal
        /// creation devices a qualified trust service in its own right, and the
        /// Art. 51(3) transitional that allowed it to be done without qualified
        /// status **expired on 21 May 2026**. A provider holding the certificate
        /// leg and not this one cannot supply the creation-device limb of
        /// Art. 3(27) for a *remote* seal, however good the certificate is.
        ///
        /// False is therefore not merely an absence for a cloud-sealing
        /// arrangement, which is what this node's hosted mode is.
        remote_qscd_management: bool,
    },
}

/// The two legs of Art. 32(1), read off one seal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealQualification {
    /// Art. 32(1)(a)–(b) — who issued the certificate, and their standing.
    pub issuer: IssuerStanding,
    /// Art. 32(1)(f) via Annex III(j) — what the certificate declares about the
    /// device holding its key.
    pub creation_device: CreationDevice,
}

impl SealQualification {
    /// Whether a provider issued this seal's certificate at all.
    ///
    /// The plain local-versus-provider split, separated from every question of
    /// standing. False means the node signed it itself, and no amount of trusted
    /// list will change that; true means there is an issuer worth asking about,
    /// whatever [`Self::issuer`] then says about them.
    #[must_use]
    pub fn is_provider_seal(&self) -> bool {
        !matches!(self.issuer, IssuerStanding::SelfIssued { .. })
    }
}

impl std::fmt::Display for SealQualification {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.issuer {
            IssuerStanding::SelfIssued { subject } => write!(
                f,
                "signed locally by {subject} — self-issued, on no Trusted List, of no legal effect"
            ),
            IssuerStanding::NotListed { issuer } => write!(
                f,
                "issued by {issuer}, which no consulted Trusted List names as a qualified CA"
            ),
            IssuerStanding::NotQualifiedAtSealing {
                issuer,
                territory,
                status,
                ..
            } => {
                write!(f, "issued by {issuer}, listed")?;
                if let Some(t) = territory {
                    write!(f, " in {t}")?;
                }
                match status {
                    Some(s) => write!(f, " but {} when the seal was made", s.as_uri()),
                    None => write!(f, " but with no recorded status when the seal was made"),
                }
            }
            IssuerStanding::QualifiedAtSealing {
                issuer,
                territory,
                remote_qscd_management,
                ..
            } => {
                write!(f, "issued by {issuer}, a qualified CA")?;
                if let Some(t) = territory {
                    write!(f, " in {t}")?;
                }
                write!(f, " when the seal was made")?;
                if !remote_qscd_management {
                    write!(
                        f,
                        "; the provider does not hold Art. 39a remote QSCD management"
                    )?;
                }
                write!(f, " — issuer matched by name, no certificate path verified")
            }
        }
    }
}

/// Report what the Trusted Lists say about a seal's issuer.
///
/// `sealed_at` is when the seal was made, and is what the lists are questioned
/// about — see [`IssuerStanding`]. Pass the envelope's own `sealed_at`, not the
/// present moment.
///
/// `lists` are the national lists to consult, each already verified against a
/// verified list of trusted lists. An empty slice is legitimate and yields
/// [`IssuerStanding::NotListed`] for every provider seal, which is the honest
/// answer to "is this issuer in nothing?".
///
/// This says nothing about whether the seal verifies; that is
/// [`verify_against_embedded_certificate`](crate::cades::verify_against_embedded_certificate),
/// and a trust report needs both.
///
/// # Errors
///
/// [`SealError::Backend`] when the bytes are not a readable CMS seal.
pub fn qualify(
    seal_der: &[u8],
    lists: &[VerifiedTrustedList],
    sealed_at: DateTime<Utc>,
) -> Result<SealQualification, SealError> {
    let certificate = signer_certificate(seal_der)?;
    Ok(SealQualification {
        issuer: standing(&certificate, lists, sealed_at),
        creation_device: certificate.creation_device,
    })
}

/// The issuer's standing, given a certificate already read.
fn standing(
    certificate: &SignerCertificate,
    lists: &[VerifiedTrustedList],
    sealed_at: DateTime<Utc>,
) -> IssuerStanding {
    if certificate.self_issued {
        return IssuerStanding::SelfIssued {
            subject: certificate.subject.clone(),
        };
    }

    let issuer = certificate.issuer.clone();
    let Some(found) = find_issuer(certificate, lists) else {
        return IssuerStanding::NotListed { issuer };
    };

    let status = found.service.history.status_at(sealed_at).cloned();
    if !status.as_ref().is_some_and(TrustServiceStatus::is_granted) {
        return IssuerStanding::NotQualifiedAtSealing {
            issuer,
            provider: found.provider.name.clone(),
            territory: found.territory.clone(),
            status,
        };
    }

    IssuerStanding::QualifiedAtSealing {
        issuer,
        provider: found.provider.name.clone(),
        territory: found.territory.clone(),
        remote_qscd_management: found
            .provider
            .services_of_type(TrustServiceType::REMOTE_QSEAL_CD_MANAGEMENT)
            .any(|s| s.history.was_granted_at(sealed_at)),
    }
}

/// The listed CA service whose certificate carries the seal's issuer name.
struct Found<'a> {
    provider: &'a crate::trustlist::ListedProvider,
    service: &'a crate::trustlist::ListedService,
    territory: Option<String>,
}

/// Find the CA entry naming this certificate's issuer.
///
/// Matched on the DER of the distinguished name, which is exact: a certificate's
/// issuer field is copied from the issuing CA's subject field, so the encodings
/// agree where the relationship is real. Exact matching is stricter than the
/// RFC 5280 name-comparison rules, so a Member State that re-encoded a name would
/// produce a miss — reported as [`IssuerStanding::NotListed`], which understates
/// the issuer's standing rather than overstating it.
///
/// Only [`TrustServiceType::QUALIFIED_CERTIFICATE_CA`] entries are considered.
/// That is the service type Art. 32(1)(a)–(b) turns on, and a provider listed for
/// some other qualified service is not thereby a qualified CA.
///
/// The first match wins. A CA certificate appearing in two Member States' lists
/// would be a defect in the lists rather than an ambiguity to resolve here.
fn find_issuer<'a>(
    certificate: &SignerCertificate,
    lists: &'a [VerifiedTrustedList],
) -> Option<Found<'a>> {
    for list in lists {
        for (provider, services) in
            list.providers_offering(TrustServiceType::QUALIFIED_CERTIFICATE_CA)
        {
            for service in services {
                if service
                    .certificates
                    .iter()
                    .any(|c| subject_der(c).is_some_and(|s| s == certificate.issuer_der))
                {
                    return Some(Found {
                        provider,
                        service,
                        territory: list.territory().map(str::to_owned),
                    });
                }
            }
        }
    }
    None
}

/// DER of a base64 certificate's subject name, or `None` if it will not parse.
///
/// A list entry that cannot be read is skipped rather than fatal. One
/// unparseable certificate among thousands must not stop the others being
/// searched, and the consequence of skipping is a miss — the safe direction.
fn subject_der(base64_certificate: &str) -> Option<Vec<u8>> {
    let der = base64::engine::general_purpose::STANDARD
        .decode(base64_certificate.trim())
        .ok()?;
    x509_cert::Certificate::from_der(&der)
        .ok()?
        .tbs_certificate
        .subject
        .to_der()
        .ok()
}

#[cfg(test)]
#[path = "qualification_tests.rs"]
mod tests;
