//! Whose certificates a seal carries, and whether they chain to a trust anchor.

use der::{Decode as _, Encode as _};
use x509_cert::Certificate;

use super::signature::verifying_key;
use super::signed::Signed;
use super::signed::parse;
use crate::error::SealError;

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
    Ok(issuer_names_of(&parse(seal_der)?))
}

pub(super) fn issuer_names_of(signed: &Signed) -> Vec<Vec<u8>> {
    let mut names: Vec<Vec<u8>> = Vec::new();
    for certificate in &signed.chain {
        if let Ok(der) = certificate.tbs_certificate.issuer.to_der()
            && !names.contains(&der)
        {
            names.push(der);
        }
    }
    names
}

/// How far a certificate path may be walked before it is treated as a loop.
///
/// Real chains are two or three links. The cap is not a tuning parameter: the
/// certificates come out of a seal an operator was handed, so a hostile one may
/// carry a chain shaped to make this walk expensive.
pub(super) const MAX_PATH_LENGTH: usize = 8;

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
    Ok(path_to(&parse(seal_der)?, anchor_certificate_der))
}

/// The path walk itself, over any parsed `SignedData` — a seal, or the time-stamp
/// token inside one. See [`check_path_to`] for what it does and does not establish.
pub(super) fn path_to(signed: &Signed, anchor_certificate_der: &[u8]) -> IssuerCheck {
    let anchor = match Certificate::from_der(anchor_certificate_der) {
        Ok(c) => c,
        Err(e) => {
            return IssuerCheck::Unverifiable(format!(
                "the anchor certificate does not parse: {e}"
            ));
        }
    };
    let anchor_key = match verifying_key(&anchor) {
        Ok(k) => k,
        Err(e) => {
            return IssuerCheck::Unverifiable(format!("no verifier for the anchor's key: {e}"));
        }
    };

    let mut current = &signed.certificate;
    let mut seen: Vec<&x509_cert::name::Name> = Vec::new();
    for _ in 0..MAX_PATH_LENGTH {
        // The anchor first, so a chain that also embeds a copy of it cannot
        // lengthen the walk.
        if current.tbs_certificate.issuer == anchor.tbs_certificate.subject {
            return verified_under(&anchor, &anchor_key, current);
        }

        // Otherwise climb one link, using only what the seal carries. A
        // certificate is never its own issuer here: a self-signed certificate
        // that is not the anchor terminates the walk rather than looping.
        //
        // **Every** embedded certificate carrying the issuer name, not the
        // first. A certificate authority rotating its key publishes the old and
        // the new certificate together under one subject name so relying parties
        // do not break at the cutover, and a CAdES seal made during that window
        // legitimately carries both. Taking the first would verify against
        // whichever the signer happened to encode first and, when that is the
        // wrong one, report a genuine seal as `NotSignedByThisIssuer` — the
        // accusation, not the shrug. `qualification::find_issuer_candidates`
        // already takes all of them, for this reason, on the *listed* side of
        // the same question.
        let candidates: Vec<&Certificate> = signed
            .chain
            .iter()
            .filter(|c| {
                c.tbs_certificate.subject == current.tbs_certificate.issuer
                    && c.tbs_certificate.subject != current.tbs_certificate.subject
            })
            .collect();
        if candidates.is_empty() {
            return IssuerCheck::NotSignedByThisIssuer;
        }

        // The first candidate whose key verifies this link, and — kept
        // separately — the first reason a candidate could not be checked at
        // all. The split matters for the same reason it does one level up: "we
        // could not ask" and "none of these signed it" are opposite findings,
        // and only one of them accuses anybody. An unreadable key in one
        // rotation certificate must not convict the CA that holds the other.
        let mut verified_next: Option<&Certificate> = None;
        let mut unverifiable: Option<String> = None;
        for candidate in &candidates {
            let key = match verifying_key(candidate) {
                Ok(k) => k,
                Err(e) => {
                    unverifiable.get_or_insert_with(|| {
                        format!("no verifier for an intermediate's key: {e}")
                    });
                    continue;
                }
            };
            match verified_under(candidate, &key, current) {
                IssuerCheck::Verified => {
                    verified_next = Some(candidate);
                    break;
                }
                IssuerCheck::Unverifiable(why) => {
                    unverifiable.get_or_insert(why);
                }
                IssuerCheck::NotSignedByThisIssuer => {}
            }
        }
        let Some(next) = verified_next else {
            return match unverifiable {
                Some(why) => IssuerCheck::Unverifiable(why),
                None => IssuerCheck::NotSignedByThisIssuer,
            };
        };

        if seen.contains(&&next.tbs_certificate.subject) {
            return IssuerCheck::Unverifiable("the embedded certificates form a loop".to_owned());
        }
        seen.push(&current.tbs_certificate.subject);
        current = next;
    }

    IssuerCheck::Unverifiable(format!(
        "the certificate path is longer than {MAX_PATH_LENGTH} links"
    ))
}

/// The signature-algorithm family an OID belongs to, where it is one this
/// module can reason about.
///
/// Prefix matching on the arc rather than an enumeration of every OID: RSA's
/// signature algorithms all sit under `1.2.840.113549.1.1`, alongside the key
/// algorithm itself, and ECDSA's under `1.2.840.10045`. A new hash in either
/// family lands in the right place without an edit here, and an OID from
/// neither family is simply unknown, which is the honest answer.
pub(super) fn algorithm_family(oid: &str) -> Option<&'static str> {
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
pub(super) fn verified_under(
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

/// Where the certificate chain the seal carries comes to an end.
///
/// Two endings, and telling them apart is what separates a finding from an
/// absence of one. A chain that reaches a self-issued certificate is complete as
/// far as the seal is concerned: everything needed to judge it is present, and a
/// verdict about it is a verdict about the whole path. A chain that simply runs
/// out is not — the link that would have led somewhere was never shipped, and
/// anything concluded from its absence is a guess.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainTerminus {
    /// The walk reached a certificate that issued itself.
    SelfIssuedRoot {
        /// Its subject, which is also its issuer.
        subject: String,
    },
    /// The walk stopped because the seal carries no certificate with the name it
    /// needed next.
    ///
    /// ETSI EN 319 122-1 clause 5.2.1 asks a generator to include the signing
    /// certificate (a *shall*) and, where the signature is meant to be validated
    /// through a Trusted List, the intermediates between it and a listed CA (a
    /// *should*, and only for certificates "not available to verifiers"). So a
    /// seal in this state is not necessarily non-conformant — but it is one this
    /// node cannot follow, and the honest report says which of those it is.
    Truncated {
        /// The issuer name the walk needed and could not find.
        missing_issuer: String,
    },
}

/// Follow the seal's embedded certificates up from its signer, and say how far
/// they go.
///
/// Deliberately makes no judgement about trust: it answers only whether the
/// material to judge the chain is present. The trusted list question is asked
/// elsewhere, and asking it against a chain that ran out is how "we could not
/// look" turns into "we looked and found nothing".
///
/// # Errors
///
/// Propagates a seal that will not parse.
pub fn chain_terminus(seal_der: &[u8]) -> Result<ChainTerminus, SealError> {
    Ok(terminus_of(&parse(seal_der)?))
}

pub(super) fn terminus_of(signed: &Signed) -> ChainTerminus {
    let mut current = &signed.certificate;

    for _ in 0..MAX_PATH_LENGTH {
        if current.tbs_certificate.issuer == current.tbs_certificate.subject {
            return ChainTerminus::SelfIssuedRoot {
                subject: current.tbs_certificate.subject.to_string(),
            };
        }
        // The same climb `check_path_to` makes, and it must stay the same: a
        // walk that found a link the other could not would report a complete
        // chain the verifier then failed to follow.
        let Some(next) = signed.chain.iter().find(|c| {
            c.tbs_certificate.subject == current.tbs_certificate.issuer
                && c.tbs_certificate.subject != current.tbs_certificate.subject
        }) else {
            return ChainTerminus::Truncated {
                missing_issuer: current.tbs_certificate.issuer.to_string(),
            };
        };
        current = next;
    }

    // A loop, or a chain longer than the walk allows. Reported as truncated
    // rather than as a root: what is certain is that this walk did not reach
    // one.
    ChainTerminus::Truncated {
        missing_issuer: current.tbs_certificate.issuer.to_string(),
    }
}

#[cfg(test)]
#[path = "path_tests.rs"]
mod tests;
