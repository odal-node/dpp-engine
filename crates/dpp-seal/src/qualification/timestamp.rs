//! Whoever stamped a seal's time, read against the Trusted Lists:
//! [`qualify_timestamp`].

use dpp_domain::trusted_list::{TrustServiceStatus, TrustServiceType};

use crate::cades::IssuerCheck;
use crate::error::SealError;
use crate::trustlist::VerifiedTrustedList;

use super::listed::{decoded, subject_der};
use super::{TimestampStanding, UncheckedTerritory};

/// Report what the Trusted Lists say about whoever stamped a seal's time.
///
/// ✅ Reg. (EU) No 910/2014 Art. 42 and Art. 41(2) — the `TSA/QTST` service type.
/// See [`TimestampStanding`] for what each answer means and why the verdict is
/// gated on it.
///
/// Asked about the **stamp's own** `genTime`, never the present, and never
/// [`SealedEnvelope::sealed_at`](dpp_domain::seal::SealedEnvelope::sealed_at),
/// which is this node's clock: a list's history can only be questioned about a
/// moment the authority itself vouched for.
///
/// A seal with no timestamp that survived its checks answers
/// [`TimestampStanding::NoAttestedTime`] — a finding, not a failure to read.
///
/// # Errors
///
/// [`SealError::Backend`] when the bytes are not a readable CMS seal.
pub fn qualify_timestamp(
    seal_der: &[u8],
    lists: &[VerifiedTrustedList],
    unchecked: &[UncheckedTerritory],
) -> Result<TimestampStanding, SealError> {
    Ok(match crate::cades::signature_timestamp_token(seal_der)? {
        Some(token) => timestamp_standing(&token, lists, unchecked.len()),
        None => TimestampStanding::NoAttestedTime,
    })
}

/// The authority's standing, given a token that already survived its own checks.
///
/// Public to the crate because the token is what a renewal gets back from an
/// authority, and the same question decides whether a fresh stamp is worth
/// keeping.
pub(crate) fn timestamp_standing(
    token: &crate::cades::TimestampToken,
    lists: &[VerifiedTrustedList],
    unchecked: usize,
) -> TimestampStanding {
    let authority = token.subject();
    let claimed_issuer = token.issuer();
    let gen_time = token.gen_time();

    // The certificate itself may be the listed one, so look for it first — and
    // before concluding anything from it being self-signed. A `TSA/QTST` entry's
    // service identity is usually the unit's own certificate, and a unit whose
    // certificate is listed is listed however it was signed.
    let signer_der = match token.signer_der() {
        Ok(d) => d,
        // The token parsed once already to get here, so this is not reachable by
        // a malformed token; it is recorded as unverifiable rather than ignored
        // because the one thing it must not become is an accusation.
        Err(e) => {
            return TimestampStanding::PathUnverifiable {
                authority,
                claimed_issuer,
                provider: None,
                territory: None,
                reason: e.to_string(),
            };
        }
    };
    let names = token.chain_issuer_names();
    let candidates = find_authority_candidates(&signer_der, &names, lists);

    let found = if let Some(direct) = candidates.iter().find(|c| c.direct) {
        // A directly listed certificate needs no path: it *is* the entry.
        direct
    } else {
        // Self-issued is decided **before** any name is matched, and from the
        // certificate alone, so a node with no network still knows — and so a
        // self-signed certificate that merely shares a listed authority's name is
        // reported as what it is rather than as a forgery. A seal's issuer is
        // treated the same way.
        if token.is_self_issued() {
            return TimestampStanding::SelfIssued { subject: authority };
        }

        let Some(first) = candidates.first() else {
            // Nothing listed matches, and *why* decides what may be said, exactly
            // as it does for a seal's issuer: a chain that ends at a self-issued
            // root has told its whole story, one that ran out has not.
            return match token.chain_terminus() {
                crate::cades::ChainTerminus::Truncated { missing_issuer } => {
                    TimestampStanding::ChainIncomplete {
                        authority,
                        missing_issuer,
                    }
                }
                crate::cades::ChainTerminus::SelfIssuedRoot { .. } => {
                    TimestampStanding::NotListed {
                        authority,
                        consulted: lists.len(),
                        unchecked,
                    }
                }
            };
        };
        let provider = first.provider.name.clone();
        let territory = first.territory.clone();

        // Every candidate is tried, and the first reason one could not be
        // checked is kept apart: "we could not ask" and "this CA did not sign it"
        // are opposite findings, and only one of them is an accusation.
        let mut verified = None;
        let mut unverifiable = None;
        for c in &candidates {
            match token.check_path_to(&c.certificate_der) {
                IssuerCheck::Verified => {
                    verified = Some(c);
                    break;
                }
                IssuerCheck::Unverifiable(why) => {
                    unverifiable.get_or_insert(why);
                }
                IssuerCheck::NotSignedByThisIssuer => {}
            }
        }
        match verified {
            Some(c) => c,
            None => {
                return match unverifiable {
                    Some(reason) => TimestampStanding::PathUnverifiable {
                        authority,
                        claimed_issuer,
                        provider,
                        territory,
                        reason,
                    },
                    None => TimestampStanding::SignatureNotFromListedAuthority {
                        authority,
                        claimed_issuer,
                        provider,
                        territory,
                    },
                };
            }
        }
    };

    let status = found.service.history.status_at(gen_time).cloned();
    if !status.as_ref().is_some_and(TrustServiceStatus::is_granted) {
        return TimestampStanding::NotQualifiedAtStamping {
            authority,
            provider: found.provider.name.clone(),
            territory: found.territory.clone(),
            status,
        };
    }
    TimestampStanding::QualifiedAtStamping {
        authority,
        provider: found.provider.name.clone(),
        territory: found.territory.clone(),
    }
}

/// A listed `TSA/QTST` certificate that is, or may have issued, the authority's.
struct AuthorityCandidate<'a> {
    provider: &'a crate::trustlist::ListedProvider,
    service: &'a crate::trustlist::ListedService,
    territory: Option<String>,
    /// The listed certificate's DER, for the signature check.
    certificate_der: Vec<u8>,
    /// Whether it is the authority's **own** certificate — byte-for-byte — so
    /// that no path has to be verified.
    direct: bool,
}

/// Every listed `TSA/QTST` certificate that is the authority's own, or whose
/// subject is an issuer name the token's certificates refer to.
///
/// **All of them, not the first** — a service mid-rotation lists old and new
/// together, and stopping at the first would verify against whichever the list
/// ordered first and report a genuine token as unsigned, intermittently. Matched
/// on DER for the name, which is exact and so stricter than RFC 5280: a Member
/// State that re-encoded a name produces no candidate, reported as unlisted, which
/// understates standing rather than overstating it.
///
/// Only [`TrustServiceType::QUALIFIED_TIMESTAMP_AUTHORITY`] entries. A provider
/// listed for some other qualified service is not thereby a qualified timestamp
/// authority.
fn find_authority_candidates<'a>(
    signer_der: &[u8],
    issuer_names: &[Vec<u8>],
    lists: &'a [VerifiedTrustedList],
) -> Vec<AuthorityCandidate<'a>> {
    let mut found = Vec::new();
    for list in lists {
        for (provider, services) in
            list.providers_offering(TrustServiceType::QUALIFIED_TIMESTAMP_AUTHORITY)
        {
            for service in services {
                for c in &service.certificates {
                    let Some(der) = decoded(c) else { continue };
                    let direct = der == signer_der;
                    if direct || subject_der(&der).is_some_and(|s| issuer_names.contains(&s)) {
                        found.push(AuthorityCandidate {
                            provider,
                            service,
                            territory: list.territory().map(str::to_owned),
                            certificate_der: der,
                            direct,
                        });
                    }
                }
            }
        }
    }
    found
}

#[cfg(test)]
#[path = "timestamp_tests.rs"]
mod tests;
