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
//! ## The issuer is verified, not merely named
//!
//! Matching starts from the name — the seal certificate's issuer distinguished
//! name against the subject of a CA certificate the list carries — and **does
//! not stop there**. Every listed certificate under that name is then tried as a
//! verifier of the CA's signature over this certificate's `tbsCertificate`, and
//! only a certificate that actually verifies reaches
//! [`IssuerStanding::QualifiedAtSealing`].
//!
//! Every listed certificate, because a certificate authority rotating its key
//! publishes the old and the new together under one subject name. Stopping at
//! the first would report a genuine seal as unsigned, intermittently, and only
//! for providers mid-rotation.
//!
//! Before that check existed, a self-signed certificate relabelled with a listed
//! CA's name reached the top verdict — and **still verified as a seal**, because
//! a CMS signature covers the signed attributes rather than the certificate
//! travelling beside them. What the relabelling breaks is the certificate's own
//! signature, which is exactly what this now checks.
//!
//! ## A chain that runs out is not a finding about the lists
//!
//! Matching considers every issuer name the seal's embedded certificates refer
//! to, so a seal carrying its intermediates reaches a listed root two or more
//! links up. A seal that does **not** carry them is a different state, and
//! [`IssuerStanding::ChainIncomplete`] reports it as one: the walk ran out of
//! links, so a listed CA may sit above the gap and "no list names this issuer"
//! would be an accusation drawn from a certificate nobody shipped.
//!
//! Which state a seal is in is decided by where its chain ends —
//! [`crate::cades::chain_terminus`] — not by whether the lookup happened to
//! fail. Nothing is fetched to fill the gap: the material a verifier is expected
//! to have is what the seal carries and what the lists publish, and an AIA URL
//! inside an untrusted certificate is not something a node should be dialling.
//!
//! ## The certificate's own standing is a different question, asked elsewhere
//!
//! Art. 32(1)(b), reached for seals by Art. 40, has two limbs: the certificate
//! must have been **issued by a qualified trust service provider**, and it must
//! have been **valid at the time of signing**. This module answers the first —
//! it is the trusted list question, and the list is the only thing that can
//! answer it.
//!
//! The second is answerable from the seal alone, so it lives with the rest of
//! the certificate reading in [`crate::cades::certificate_standing`]: the
//! validity window judged against an attested sealing time, and revocation read
//! from the CRLs the seal carries. This module deliberately does not fold that
//! in. A caller wanting the whole of (b) asks both, which keeps each answer
//! traceable to the evidence it came from — a trusted list, or the bytes.
//!
//! ## Still not `SealChecks::QualifiedValidation`
//!
//! Conditions of Art. 32(1) remain unchecked, and none is a matter of degree:
//!
//! - **(f), the creation device.** [`CreationDevice`] reports what Annex III(j)
//!   *declares*, which is the certificate's word for it. Nothing confirms it,
//!   and nothing could from bytes alone.
//! - **(c) and (d)** — that the validation data corresponds to what the relying
//!   party was given, and that the data representing the seal creator is
//!   correctly provided — are about the presentation, not the envelope.
//! - **(h)**, the Art. 26 requirements for an advanced seal.
//!
//! So nothing in this module returns a
//! [`SealChecks`](dpp_domain::seal::SealChecks). A rung would be claimed by
//! whoever wired it up next, and the missing conditions would go with it.

use base64::Engine as _;
use chrono::{DateTime, Utc};
use der::{Decode as _, Encode as _};
use dpp_domain::trusted_list::{TrustServiceStatus, TrustServiceType};

use crate::cades::{IssuerCheck, SignerCertificate, signer_certificate};
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
    ///
    /// # Read the two counts before reading the verdict
    ///
    /// This is the only variant that claims an **absence**, so it is the only
    /// one whose meaning changes with what was available to look at, and the
    /// counts are carried here rather than only on [`SealQualification`] so that
    /// a caller matching on the variant alone cannot miss them.
    ///
    /// - `consulted == 0` — nothing was looked at. The answer is about nothing,
    ///   and it is what a node with no trusted lists loaded reports for every
    ///   provider seal, qualified or not.
    /// - `unchecked > 0` — some territory the list of trusted lists names could
    ///   not be verified, so a provider listed *there* is indistinguishable from
    ///   one listed nowhere. Not a Union-wide claim.
    /// - `consulted > 0 && unchecked == 0` — as complete as the list of trusted
    ///   lists allows. Still not "not qualified in law": a provider can be
    ///   qualified and the list wrong, which is the Member State's problem and
    ///   not something this can see.
    ///
    /// [`SealQualification::unchecked`] carries which territories and why.
    ///
    /// [`Self::ChainIncomplete`] deliberately carries no counts. It already
    /// refuses to make the absence claim — the walk ran out of links, so a
    /// listed CA may sit above the gap whatever was consulted.
    NotListed {
        /// The issuer name the certificate carries.
        issuer: String,
        /// How many territories' verified lists were searched.
        consulted: usize,
        /// How many territories the list of trusted lists names could not be
        /// verified, and so were not searched.
        unchecked: usize,
    },
    /// The seal did not carry enough certificates to reach a root, and no list
    /// names any issuer it does refer to.
    ///
    /// **Weaker than [`Self::NotListed`], deliberately.** There, the chain ends
    /// at a certificate that issued itself: everything the seal has to say about
    /// its own provenance has been said, and no consulted list names it. Here
    /// the walk ran out of links — the certificate that would have led somewhere
    /// was never shipped — so a listed CA may well sit above the gap, and
    /// reporting an unlisted provider would be an accusation drawn from an
    /// absence.
    ///
    /// The distinction is not academic: Member States do not publish the same
    /// thing. Most Italian entries are self-signed roots, so a seal from an
    /// Italian provider is expected to reach its listed CA through an
    /// intermediate — and a provider that omits that intermediate produces
    /// exactly this state. ETSI EN 319 122-1 clause 5.2.1 asks generators to
    /// include those intermediates where the signature is to be validated
    /// through a Trusted List, which is the remedy an operator seeing this
    /// should ask their provider for.
    ChainIncomplete {
        /// The issuer name the seal certificate carries.
        issuer: String,
        /// The name the walk needed next and the seal did not carry. Equal to
        /// `issuer` when the seal carries only its signing certificate.
        missing_issuer: String,
    },
    /// A listed CA carries this name, and **did not sign this certificate**.
    ///
    /// The forgery finding. Every listed certificate under that name was tried —
    /// a CA mid-rotation publishes several — and none of their keys verifies the
    /// signature over this certificate's `tbsCertificate`.
    ///
    /// Distinct from [`Self::NotListed`], which says nobody listed carries the
    /// name at all. Here somebody does, and the seal is claiming to be theirs.
    SignatureNotFromListedCa {
        /// The issuer name the certificate claims.
        issuer: String,
        /// The provider whose name was claimed.
        provider: Option<String>,
        /// The list carrying that name.
        territory: Option<String>,
    },
    /// A listed CA carries this name and the signature could not be checked.
    ///
    /// **Not an accusation, and never to be read as one.** The usual cause is a
    /// key algorithm this build does not verify; a CA certificate that will not
    /// parse is the other. Reporting it as
    /// [`Self::SignatureNotFromListedCa`] would call a possibly-genuine seal a
    /// forgery on the strength of a check that never ran — the same mistake as
    /// reading an unknown trusted-list status as a withdrawn one.
    PathUnverifiable {
        /// The issuer name the certificate claims.
        issuer: String,
        /// The provider whose name was claimed.
        provider: Option<String>,
        /// The list carrying that name.
        territory: Option<String>,
        /// Why no candidate could be checked.
        reason: String,
    },
    /// The issuer is a listed CA, but was not granted qualified status when the
    /// seal was made.
    ///
    /// Reached only once the path verifies: this CA did issue the certificate,
    /// and was not qualified at the time.
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
    /// A granted qualified CA issued this certificate, and was granted when the
    /// seal was made.
    ///
    /// The issuer's signature over this certificate's `tbsCertificate` verifies
    /// under a key the trusted list publishes for it, so the name is not merely
    /// claimed. What is still **not** established here: the certificate's own
    /// validity window at sealing time, and whether it had been revoked — see
    /// the module documentation.
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
    /// The territories the list of trusted lists names that could **not** be
    /// consulted for this verdict, and why.
    ///
    /// Empty means either that every named territory was searched, or that
    /// nothing was — [`IssuerStanding::NotListed`]'s `consulted` count is what
    /// separates those, and it is carried on the variant for that reason.
    ///
    /// # Why the verdict carries this at all
    ///
    /// Because an absence claim is only as wide as what was looked at, and
    /// nothing else can say how wide that was. A verdict of "no list names this
    /// issuer" reads as a statement about the Union; it is one only when this is
    /// empty and something was consulted.
    ///
    /// This is not hypothetical. Germany's trusted list does not verify against
    /// the mandated profile today, and Germany has one of the larger provider
    /// populations — so a node consulting the Union would be missing it, and a
    /// qualified German provider would be reported exactly like an unlisted one.
    /// That is the failure this field exists to make visible rather than
    /// prevent: it cannot be prevented from here.
    pub unchecked: Vec<UncheckedTerritory>,
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
            // The counts are in the sentence because this is the one verdict
            // whose meaning depends on them, and an operator reading a log line
            // has no other way to tell "not in the Union" from "not in the
            // nothing we looked at".
            IssuerStanding::NotListed {
                issuer,
                consulted: 0,
                ..
            } => write!(
                f,
                "issued by {issuer} — no Trusted List was consulted, so nothing is known about \
                 whether that issuer is a qualified CA"
            ),
            IssuerStanding::NotListed {
                issuer,
                consulted,
                unchecked: 0,
            } => write!(
                f,
                "issued by {issuer}, which none of the {consulted} Trusted Lists consulted names \
                 as a qualified CA"
            ),
            IssuerStanding::NotListed {
                issuer,
                consulted,
                unchecked,
            } => write!(
                f,
                "issued by {issuer}, which none of the {consulted} Trusted Lists consulted names \
                 as a qualified CA — but {unchecked} territory(ies) could not be consulted, so a \
                 provider listed in one of those would look exactly like this"
            ),
            IssuerStanding::ChainIncomplete {
                issuer,
                missing_issuer,
            } => write!(
                f,
                "issued by {issuer}; the seal does not carry a certificate for {missing_issuer},                  so no path to a listed CA could be followed — ask the provider to include the                  intermediates (ETSI EN 319 122-1 clause 5.2.1)"
            ),
            IssuerStanding::SignatureNotFromListedCa {
                issuer, territory, ..
            } => {
                write!(f, "claims {issuer}, a CA listed")?;
                if let Some(t) = territory {
                    write!(f, " in {t}")?;
                }
                write!(
                    f,
                    " — but no certificate that list publishes for that name signed this one"
                )
            }
            IssuerStanding::PathUnverifiable {
                issuer,
                territory,
                reason,
                ..
            } => {
                write!(f, "claims {issuer}, a CA listed")?;
                if let Some(t) = territory {
                    write!(f, " in {t}")?;
                }
                write!(f, " — the signature could not be checked: {reason}")
            }
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
                // The certificate's own validity and revocation are no longer
                // unchecked — they are simply not this verdict's subject, and
                // `cades::certificate_standing` reports them separately. Saying
                // "not checked" here would now be false, and saying nothing
                // would let this read as the whole of Art. 32(1)(b).
                write!(
                    f,
                    " — issuer signature verified; the certificate's own validity                      window and revocation are reported separately"
                )
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

/// A territory the list of trusted lists names and this node could not consult.
///
/// Carried rather than dropped because the two states a caller must tell apart —
/// *this issuer is on no list* and *the list it would be on could not be read* —
/// are otherwise identical at the point of the verdict.
///
/// The reason is free text on purpose. What stops a list being consulted is not
/// an enumerable set: a signature that does not verify, a document over a parser
/// ceiling, a fetch that failed, a scheme operator mid-rotation whose entry has
/// not caught up. An operator reading this needs the sentence, and a caller
/// deciding what to do needs only that the territory is absent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UncheckedTerritory {
    /// The `SchemeTerritory` the list of trusted lists names.
    pub territory: String,
    /// Why this node could not consult it, in terms an operator can act on.
    pub reason: String,
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

/// A base64 certificate's DER, or `None` if it will not decode.
///
/// A list entry that cannot be read is skipped rather than fatal. One
/// unparseable certificate among hundreds must not stop the others being
/// searched, and the consequence of skipping is a miss — the safe direction.
fn decoded(base64_certificate: &str) -> Option<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(base64_certificate.trim())
        .ok()
}

/// A certificate's subject name, DER-encoded.
fn subject_der(der: &[u8]) -> Option<Vec<u8>> {
    x509_cert::Certificate::from_der(der)
        .ok()?
        .tbs_certificate
        .subject
        .to_der()
        .ok()
}

#[cfg(test)]
#[path = "qualification_tests.rs"]
mod tests;
