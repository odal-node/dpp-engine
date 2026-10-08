//! The seal's issuer, read against the Trusted Lists: [`qualify`].

use chrono::{DateTime, Utc};
use dpp_domain::trusted_list::{TrustServiceStatus, TrustServiceType};

use crate::cades::{IssuerCheck, SignerCertificate, signer_certificate};
use crate::error::SealError;
use crate::trustlist::VerifiedTrustedList;

use super::listed::{decoded, subject_der};
use super::{IssuerStanding, SealQualification, UncheckedTerritory};

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
    unchecked: &[UncheckedTerritory],
    sealed_at: DateTime<Utc>,
) -> Result<SealQualification, SealError> {
    let certificate = signer_certificate(seal_der)?;
    Ok(SealQualification {
        issuer: standing(seal_der, &certificate, lists, unchecked.len(), sealed_at),
        creation_device: certificate.creation_device,
        unchecked: unchecked.to_vec(),
    })
}

/// The issuer's standing, given a certificate already read.
fn standing(
    seal_der: &[u8],
    certificate: &SignerCertificate,
    lists: &[VerifiedTrustedList],
    unchecked: usize,
    sealed_at: DateTime<Utc>,
) -> IssuerStanding {
    if certificate.self_issued {
        return IssuerStanding::SelfIssued {
            subject: certificate.subject.clone(),
        };
    }

    let issuer = certificate.issuer.clone();
    // Candidates are chosen against **every** issuer name the seal's embedded
    // certificates refer to, not only the signer's own. Where a Member State
    // publishes self-signed roots, the anchor's subject matches an
    // intermediate's issuer one link further up, and filtering on the signer's
    // issuer alone would select nothing and report an unlisted provider — with
    // the chain to prove otherwise sitting inside the seal.
    let names = crate::cades::chain_issuer_names(seal_der).unwrap_or_default();
    let candidates = find_issuer_candidates(&names, lists);
    let Some(first) = candidates.first() else {
        // Nothing matched — but *why* nothing matched decides what may be said.
        // A chain that ends at a self-issued root has told its whole story, and
        // "no list names it" is a finding about that story. A chain that simply
        // ran out has not, and the same sentence would be an accusation drawn
        // from a certificate nobody shipped.
        return match crate::cades::chain_terminus(seal_der) {
            Ok(crate::cades::ChainTerminus::Truncated { missing_issuer }) => {
                IssuerStanding::ChainIncomplete {
                    issuer,
                    missing_issuer,
                }
            }
            // A complete chain, or a seal that stopped parsing between here and
            // the read above — which cannot happen, and if it did, the weaker
            // statement is the safe one.
            Ok(crate::cades::ChainTerminus::SelfIssuedRoot { .. }) => IssuerStanding::NotListed {
                issuer,
                consulted: lists.len(),
                unchecked,
            },
            Err(_) => IssuerStanding::ChainIncomplete {
                issuer: issuer.clone(),
                missing_issuer: issuer,
            },
        };
    };
    // Where the path cannot be pinned to one candidate, the name that was
    // matched is reported from the first. They all carry the same subject name
    // — that is what made them candidates — so the provider and territory are
    // the answer to "whose name is on this", which is the question those
    // variants are reporting on.
    let provider = first.provider.name.clone();
    let territory = first.territory.clone();

    let (found, unverifiable) = verify_path(seal_der, &candidates);
    let Some(found) = found else {
        return match unverifiable {
            // Never collapsed into the variant below. "We could not check" and
            // "this CA did not sign it" are opposite findings, and only one of
            // them is an accusation.
            Some(reason) => IssuerStanding::PathUnverifiable {
                issuer,
                provider,
                territory,
                reason,
            },
            None => IssuerStanding::SignatureNotFromListedCa {
                issuer,
                provider,
                territory,
            },
        };
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

/// Which candidate actually signed the certificate, and why none could be checked.
///
/// Returns the first candidate whose key verifies. The second value is the first
/// reason a candidate could not be checked at all, and it is only meaningful
/// when no candidate verified — it is what separates *nobody here signed this*
/// from *we were unable to ask*.
fn verify_path<'a>(
    seal_der: &[u8],
    candidates: &'a [Candidate<'a>],
) -> (Option<&'a Candidate<'a>>, Option<String>) {
    let mut unverifiable = None;
    for candidate in candidates {
        match crate::cades::check_path_to(seal_der, &candidate.certificate_der) {
            Ok(IssuerCheck::Verified) => return (Some(candidate), None),
            Ok(IssuerCheck::NotSignedByThisIssuer) => {}
            Ok(IssuerCheck::Unverifiable(why)) => {
                if unverifiable.is_none() {
                    unverifiable = Some(why);
                }
            }
            // The seal parsed once already to get here, so this is not reachable
            // by a malformed seal. Recorded as unverifiable rather than ignored,
            // because the one thing it must not become is an accusation.
            Err(e) => {
                if unverifiable.is_none() {
                    unverifiable = Some(e.to_string());
                }
            }
        }
    }
    (None, unverifiable)
}

/// A listed CA certificate carrying the seal certificate's issuer name.
struct Candidate<'a> {
    provider: &'a crate::trustlist::ListedProvider,
    service: &'a crate::trustlist::ListedService,
    territory: Option<String>,
    /// The CA certificate's DER, for the signature check.
    certificate_der: Vec<u8>,
}

/// Every listed CA certificate whose subject is an issuer name the seal refers to.
///
/// **All of them, not the first.** A certificate authority rotating its key
/// publishes the old and the new certificate together, under the same subject
/// name, so relying parties do not break at the cutover — the trusted list
/// module already records that Finland names five signing certificates for this
/// reason. Stopping at the first match would verify against whichever the list
/// happened to order first and report a genuine seal as unsigned, intermittently
/// and only for providers mid-rotation.
///
/// Matched on the DER of the distinguished name, which is exact. That is
/// stricter than RFC 5280's comparison rules, so a Member State that re-encoded
/// a name would produce no candidates — reported as
/// [`IssuerStanding::NotListed`], which understates the issuer's standing rather
/// than overstating it.
///
/// Only [`TrustServiceType::QUALIFIED_CERTIFICATE_CA`] entries are considered.
/// That is the service type Art. 32(1)(a)–(b) turns on, and a provider listed
/// for some other qualified service is not thereby a qualified CA.
fn find_issuer_candidates<'a>(
    issuer_names: &[Vec<u8>],
    lists: &'a [VerifiedTrustedList],
) -> Vec<Candidate<'a>> {
    let mut found = Vec::new();
    for list in lists {
        for (provider, services) in
            list.providers_offering(TrustServiceType::QUALIFIED_CERTIFICATE_CA)
        {
            for service in services {
                for c in &service.certificates {
                    let Some(der) = decoded(c) else { continue };
                    if subject_der(&der).is_some_and(|s| issuer_names.contains(&s)) {
                        found.push(Candidate {
                            provider,
                            service,
                            territory: list.territory().map(str::to_owned),
                            certificate_der: der,
                        });
                    }
                }
            }
        }
    }
    found
}

#[cfg(test)]
#[path = "issuer_tests.rs"]
mod tests;
