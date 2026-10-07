//! What Art. 32(1) says about a seal, as a shape the HTTP surface can serve.
//!
//! ✅ COMPLIANCE-PIN: Regulation (EU) No 910/2014 Art. 32(1)(a)–(b) and (f),
//! applied to seals by Art. 40.
//!
//! # Why these types are here and the logic that fills them is not
//!
//! Reading a verdict out of a CAdES needs an ASN.1 parser, a signature check and
//! the EU Trusted Lists; `dpp-seal` does all three. But `dpp-vault` serves the
//! answer and reaches the seal crate through exactly one seam — the
//! [`SealInspector`](crate::seal::SealInspector) trait in this crate — so the
//! *shape* of the answer has to live below both.
//!
//! That is the arrangement every other seal verdict already uses:
//! [`SealOrigin`](crate::seal::SealOrigin),
//! [`SealBinding`](crate::seal::SealBinding),
//! [`CertificateStanding`](crate::seal::CertificateStanding) and
//! [`ArchivalFreshness`](crate::seal::ArchivalFreshness) are all declared here
//! and computed there. These moved to join them rather than inventing a second,
//! parallel wire shape that would have to be kept in step by hand.
//!
//! 🚨 **Serialised, and the wire spelling is a published contract.** camelCase
//! throughout, and the variant tags are what a client matches on — see each
//! variant's own note. Nothing here is renameable without breaking a reader.

use serde::{Deserialize, Serialize};

use dpp_domain::trusted_list::TrustServiceStatus;

use crate::seal::CreationDevice;

/// What the Trusted Lists say about the certificate's issuer.
///
/// "At sealing" throughout, never "now". A provider granted qualified status in
/// 2029 was not qualified in 2027, and a present-tense check would certify a seal
/// that never was; a provider withdrawn last week did not retroactively unmake
/// the seals it issued. Art. 32(1)(b) asks about the time of sealing, and trusted
/// lists carry the history to answer it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "standing",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
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
                unchecked: 0,
            } => write!(
                f,
                "issued by {issuer} — no Trusted List was consulted, so nothing is known about \
                 whether that issuer is a qualified CA"
            ),
            // Nothing verified, but territories were named and every one failed.
            // A different operational fact from the arm above and worth its own
            // sentence: that one is a node that never looked, this one is a node
            // that looked and got nowhere — a refresher running and failing,
            // rather than absent.
            IssuerStanding::NotListed {
                issuer,
                consulted: 0,
                unchecked,
            } => write!(
                f,
                "issued by {issuer} — no Trusted List could be consulted: {unchecked} \
                 territory(ies) were named and none could be read, so nothing is known about \
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
                "issued by {issuer}; the seal does not carry a certificate for {missing_issuer}, so no path to a listed CA could be followed — ask the provider to include the intermediates (ETSI EN 319 122-1 clause 5.2.1)"
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
                    " — issuer signature verified; the certificate's own validity window and revocation are reported separately"
                )
            }
        }
    }
}

/// What the Trusted Lists say about the authority that stamped a seal's time.
///
/// ✅ Regulation (EU) No 910/2014 Art. 42 and Art. 41(2): a qualified electronic
/// time stamp is a service of a qualified trust service provider, and the
/// presumption of the accuracy of the date and time it indicates attaches to
/// that. The list entry that says so is the **`TSA/QTST`** service type.
///
/// # Why a seal's timestamp needs this at all
///
/// A timestamp token's own signature holding says the token is genuine. It says
/// nothing about **who signed it**, and the signer is whoever the seal's holder
/// chose: a seal can be handed a token minted under a key made that afternoon,
/// stamping any moment inside that key's own certificate window. Before this, such
/// a token was a perfectly good *proof of existence*, and a proof of existence
/// decides whether a certificate finding is a failure or an open question — so an
/// out-of-window certificate could be turned from unproven into unremarkable by
/// attaching a time nobody had reason to believe.
///
/// So the moment a seal's certificate is judged against is **only treated as
/// attested when the authority is [`Self::QualifiedAtStamping`]**. Every other
/// standing leaves the time visible — `attestedSealedAt` still reports what the
/// token says — and judges the certificate against this node's clock instead,
/// which is reported as unproven rather than as a failure.
///
/// "At stamping" throughout, never "now", for the reason [`IssuerStanding`] gives:
/// the list carries the history, and a service withdrawn last week did not
/// retroactively unmake the stamps it made while granted.
///
/// # Matched two ways, unlike a seal's issuer
///
/// A `TSA/QTST` entry's service digital identity is usually the timestamping
/// unit's **own** certificate, and sometimes the CA above it. A seal's issuer is
/// only ever a CA, so only a path to a listed CA is looked for there. Here a token
/// whose signing certificate *is* the listed one needs no path at all, and one
/// issued by a listed CA needs the path verified, link by link.
///
/// 🚨 **Serialised, and the spelling is a published contract** — the same rule
/// [`IssuerStanding`] carries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "standing",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum TimestampStanding {
    /// The seal carries no timestamp that survived its own checks.
    ///
    /// A `B-B` seal has none, and so does a seal whose token failed its
    /// signature, its imprint or its authority's validity window. In every case
    /// there is no time to ask a list about, and nothing is known about any
    /// authority.
    NoAttestedTime,
    /// The authority's certificate is its own issuer, and no list names it.
    ///
    /// Decided before any list is consulted and from the certificate alone, so a
    /// node with no network still knows its seals' times are worth nothing to
    /// anybody else. What the local development backend produces.
    SelfIssued {
        /// The subject name, which is also the issuer name.
        subject: String,
    },
    /// Some provider issued the authority's certificate, and no list consulted
    /// names that authority or its CA under `TSA/QTST`.
    ///
    /// **Read the two counts before reading the verdict** — the same rule, for
    /// the same reason, as [`IssuerStanding::NotListed`]: this is the one variant
    /// that claims an absence, so what it means depends on what was looked at.
    NotListed {
        /// The authority's subject name.
        authority: String,
        /// How many territories' verified lists were searched.
        consulted: usize,
        /// How many territories the list of trusted lists names could not be
        /// verified, and so were not searched.
        unchecked: usize,
    },
    /// The token did not carry enough certificates to reach a root, and no list
    /// names any issuer it does refer to.
    ///
    /// Weaker than [`Self::NotListed`], deliberately: the walk ran out of links,
    /// so a listed CA may sit above the gap.
    ChainIncomplete {
        /// The authority's subject name.
        authority: String,
        /// The name the walk needed next and the token did not carry.
        missing_issuer: String,
    },
    /// A listed `TSA/QTST` CA carries the name the authority's certificate
    /// claims, and **did not sign it**.
    ///
    /// The forgery finding — a certificate relabelled with a listed CA's name.
    SignatureNotFromListedAuthority {
        /// The authority's subject name.
        authority: String,
        /// The issuer name the certificate claims.
        claimed_issuer: String,
        /// The provider whose name was claimed.
        provider: Option<String>,
        /// The list carrying that name.
        territory: Option<String>,
    },
    /// A listed `TSA/QTST` CA carries the claimed name and the signature could
    /// not be checked.
    ///
    /// **Not an accusation.** The usual cause is a key algorithm this build does
    /// not verify, and reporting it as a forgery would call a possibly-genuine
    /// token one on the strength of a check that never ran.
    PathUnverifiable {
        /// The authority's subject name.
        authority: String,
        /// The issuer name the certificate claims.
        claimed_issuer: String,
        /// The provider whose name was claimed.
        provider: Option<String>,
        /// The list carrying that name.
        territory: Option<String>,
        /// Why no candidate could be checked.
        reason: String,
    },
    /// The authority is a listed `TSA/QTST` service that was not granted when it
    /// stamped.
    NotQualifiedAtStamping {
        /// The authority's subject name.
        authority: String,
        /// The provider the list files that service under.
        provider: Option<String>,
        /// The list's `SchemeTerritory`.
        territory: Option<String>,
        /// The status in force at the stamping time. `None` means the list's
        /// history does not reach back that far — silence about that moment,
        /// which is a different finding from a recorded non-granted status.
        status: Option<TrustServiceStatus>,
    },
    /// The authority is a listed `TSA/QTST` service, granted when it stamped.
    ///
    /// The only standing that makes the seal's attested time count as a proof of
    /// existence.
    QualifiedAtStamping {
        /// The authority's subject name.
        authority: String,
        /// The provider the list files that service under.
        provider: Option<String>,
        /// The list's `SchemeTerritory`.
        territory: Option<String>,
    },
}

impl TimestampStanding {
    /// Whether the seal's attested time may be treated as a proof of existence.
    ///
    /// The gate: `true` only for [`Self::QualifiedAtStamping`]. Every other
    /// standing — including the ones that mean *this node could not tell* —
    /// returns `false`, because the direction an unanswered question fails in
    /// has to be the one that leaves a finding unproven rather than settled.
    #[must_use]
    pub fn counts_as_proof_of_existence(&self) -> bool {
        matches!(self, Self::QualifiedAtStamping { .. })
    }
}

impl std::fmt::Display for TimestampStanding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoAttestedTime => {
                write!(f, "the seal carries no timestamp that survived its checks")
            }
            Self::SelfIssued { subject } => write!(
                f,
                "stamped by {subject} — self-issued, on no Trusted List, so the time is the \
                 signer's own word"
            ),
            Self::NotListed {
                authority,
                consulted: 0,
                unchecked: 0,
            } => write!(
                f,
                "stamped by {authority} — no Trusted List was consulted, so nothing is known \
                 about whether it is a qualified timestamp authority"
            ),
            Self::NotListed {
                authority,
                consulted: 0,
                unchecked,
            } => write!(
                f,
                "stamped by {authority} — no Trusted List could be consulted: {unchecked} \
                 territory(ies) were named and none could be read"
            ),
            Self::NotListed {
                authority,
                consulted,
                unchecked: 0,
            } => write!(
                f,
                "stamped by {authority}, which none of the {consulted} Trusted Lists consulted \
                 names as a qualified timestamp authority"
            ),
            Self::NotListed {
                authority,
                consulted,
                unchecked,
            } => write!(
                f,
                "stamped by {authority}, which none of the {consulted} Trusted Lists consulted \
                 names as a qualified timestamp authority — but {unchecked} territory(ies) could \
                 not be consulted, so one listed in those would look exactly like this"
            ),
            Self::ChainIncomplete {
                authority,
                missing_issuer,
            } => write!(
                f,
                "stamped by {authority}; the token does not carry a certificate for \
                 {missing_issuer}, so no path to a listed authority could be followed"
            ),
            Self::SignatureNotFromListedAuthority {
                authority,
                claimed_issuer,
                territory,
                ..
            } => {
                write!(
                    f,
                    "stamped by {authority}, which claims {claimed_issuer}, listed"
                )?;
                if let Some(t) = territory {
                    write!(f, " in {t}")?;
                }
                write!(
                    f,
                    " — but no certificate that list publishes for that name signed it"
                )
            }
            Self::PathUnverifiable {
                authority,
                claimed_issuer,
                territory,
                reason,
                ..
            } => {
                write!(
                    f,
                    "stamped by {authority}, which claims {claimed_issuer}, listed"
                )?;
                if let Some(t) = territory {
                    write!(f, " in {t}")?;
                }
                write!(f, " — the signature could not be checked: {reason}")
            }
            Self::NotQualifiedAtStamping {
                authority,
                territory,
                status,
                ..
            } => {
                write!(f, "stamped by {authority}, listed")?;
                if let Some(t) = territory {
                    write!(f, " in {t}")?;
                }
                match status {
                    Some(s) => write!(f, " but {} when it stamped", s.as_uri()),
                    None => write!(f, " but with no recorded status when it stamped"),
                }
            }
            Self::QualifiedAtStamping {
                authority,
                territory,
                ..
            } => {
                write!(f, "stamped by {authority}, a qualified timestamp authority")?;
                if let Some(t) = territory {
                    write!(f, " in {t}")?;
                }
                write!(f, " when it stamped")
            }
        }
    }
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UncheckedTerritory {
    /// The `SchemeTerritory` the list of trusted lists names.
    pub territory: String,
    /// Why this node could not consult it, in terms an operator can act on.
    pub reason: String,
}

#[cfg(test)]
mod wire_shape {
    use super::*;

    /// 🚨 The verdict's spelling is a published contract.
    ///
    /// A client matches on `standing` to decide what the rest of the object
    /// means, so every tag here is load-bearing and none is renameable without
    /// breaking a reader. Pinned as literals rather than round-tripped: a
    /// round-trip agrees with whatever serde happens to emit, which is the one
    /// thing a wire test must not do.
    #[test]
    fn every_standing_serialises_to_the_documented_tag() {
        let cases: Vec<(IssuerStanding, &str)> = vec![
            (
                IssuerStanding::SelfIssued {
                    subject: "CN=Self".into(),
                },
                r#"{"standing":"selfIssued","subject":"CN=Self"}"#,
            ),
            (
                IssuerStanding::NotListed {
                    issuer: "CN=A".into(),
                    consulted: 26,
                    unchecked: 1,
                },
                r#"{"standing":"notListed","issuer":"CN=A","consulted":26,"unchecked":1}"#,
            ),
            (
                IssuerStanding::ChainIncomplete {
                    issuer: "CN=A".into(),
                    missing_issuer: "CN=B".into(),
                },
                // 🚨 `missingIssuer`, not `missing_issuer`. An internally-tagged
                // enum's container `rename_all` renames the *variants*; the
                // fields inside them need `rename_all_fields`, and without it
                // this one field shipped snake_case into a camelCase API.
                r#"{"standing":"chainIncomplete","issuer":"CN=A","missingIssuer":"CN=B"}"#,
            ),
            (
                IssuerStanding::QualifiedAtSealing {
                    issuer: "CN=A".into(),
                    provider: Some("P".into()),
                    territory: Some("FI".into()),
                    remote_qscd_management: true,
                },
                r#"{"standing":"qualifiedAtSealing","issuer":"CN=A","provider":"P","territory":"FI","remoteQscdManagement":true}"#,
            ),
        ];

        for (verdict, expected) in cases {
            assert_eq!(
                serde_json::to_string(&verdict).expect("serialise"),
                expected,
                "the wire spelling of {verdict:?} is a contract"
            );
        }
    }

    /// No field in any variant is spelled in snake_case.
    ///
    /// The case above names four variants; this one catches the fifth somebody
    /// adds. It walks the serialised form of every variant and fails on an
    /// underscore in a key — which is what `missing_issuer` looked like, and is
    /// what a new multi-word field will look like if `rename_all_fields` is ever
    /// dropped.
    #[test]
    fn no_variant_ships_a_snake_case_key() {
        use dpp_domain::trusted_list::TrustServiceStatus;

        let every = vec![
            IssuerStanding::SelfIssued {
                subject: String::new(),
            },
            IssuerStanding::NotListed {
                issuer: String::new(),
                consulted: 0,
                unchecked: 0,
            },
            IssuerStanding::ChainIncomplete {
                issuer: String::new(),
                missing_issuer: String::new(),
            },
            IssuerStanding::SignatureNotFromListedCa {
                issuer: String::new(),
                provider: None,
                territory: None,
            },
            IssuerStanding::PathUnverifiable {
                issuer: String::new(),
                provider: None,
                territory: None,
                reason: String::new(),
            },
            IssuerStanding::NotQualifiedAtSealing {
                issuer: String::new(),
                provider: None,
                territory: None,
                status: Some(TrustServiceStatus::Withdrawn),
            },
            IssuerStanding::QualifiedAtSealing {
                issuer: String::new(),
                provider: None,
                territory: None,
                remote_qscd_management: false,
            },
        ];

        for verdict in every {
            let json = serde_json::to_value(&verdict).expect("serialise");
            let object = json
                .as_object()
                .expect("an internally-tagged enum is an object");
            for key in object.keys() {
                assert!(
                    !key.contains('_'),
                    "`{key}` on {verdict:?} is snake_case, and this API is camelCase throughout"
                );
            }
        }
    }
}

#[cfg(test)]
mod timestamp_standing_shape {
    use super::*;
    use dpp_domain::trusted_list::TrustServiceStatus;

    /// 🚨 The spelling is a contract, pinned as literals.
    ///
    /// `claimedIssuer` and `missingIssuer` are the two multi-word keys, and the
    /// ones `rename_all_fields` exists to keep camelCase.
    #[test]
    fn every_timestamp_standing_serialises_to_the_documented_tag() {
        let cases: Vec<(TimestampStanding, &str)> = vec![
            (
                TimestampStanding::NoAttestedTime,
                r#"{"standing":"noAttestedTime"}"#,
            ),
            (
                TimestampStanding::SelfIssued {
                    subject: "CN=Self".into(),
                },
                r#"{"standing":"selfIssued","subject":"CN=Self"}"#,
            ),
            (
                TimestampStanding::NotListed {
                    authority: "CN=A".into(),
                    consulted: 26,
                    unchecked: 1,
                },
                r#"{"standing":"notListed","authority":"CN=A","consulted":26,"unchecked":1}"#,
            ),
            (
                TimestampStanding::ChainIncomplete {
                    authority: "CN=A".into(),
                    missing_issuer: "CN=B".into(),
                },
                r#"{"standing":"chainIncomplete","authority":"CN=A","missingIssuer":"CN=B"}"#,
            ),
            (
                TimestampStanding::SignatureNotFromListedAuthority {
                    authority: "CN=A".into(),
                    claimed_issuer: "CN=B".into(),
                    provider: Some("P".into()),
                    territory: Some("FI".into()),
                },
                r#"{"standing":"signatureNotFromListedAuthority","authority":"CN=A","claimedIssuer":"CN=B","provider":"P","territory":"FI"}"#,
            ),
            (
                TimestampStanding::NotQualifiedAtStamping {
                    authority: "CN=A".into(),
                    provider: None,
                    territory: None,
                    status: Some(TrustServiceStatus::Withdrawn),
                },
                r#"{"standing":"notQualifiedAtStamping","authority":"CN=A","provider":null,"territory":null,"status":"withdrawn"}"#,
            ),
            (
                TimestampStanding::QualifiedAtStamping {
                    authority: "CN=A".into(),
                    provider: Some("P".into()),
                    territory: Some("FI".into()),
                },
                r#"{"standing":"qualifiedAtStamping","authority":"CN=A","provider":"P","territory":"FI"}"#,
            ),
        ];

        for (standing, expected) in cases {
            assert_eq!(
                serde_json::to_string(&standing).expect("serialise"),
                expected,
                "the wire spelling of {standing:?} is a contract"
            );
        }
    }

    /// **Only a qualified authority turns a time into a proof of existence.**
    ///
    /// The gate the verdict hangs on, so every other variant is listed rather than
    /// sampled: a variant added later that quietly returned `true` would reopen
    /// the escalation this exists to close, and the exhaustive list is what makes
    /// the compiler ask.
    #[test]
    fn only_a_qualified_authority_counts_as_a_proof_of_existence() {
        let refused = [
            TimestampStanding::NoAttestedTime,
            TimestampStanding::SelfIssued {
                subject: String::new(),
            },
            TimestampStanding::NotListed {
                authority: String::new(),
                consulted: 0,
                unchecked: 0,
            },
            TimestampStanding::ChainIncomplete {
                authority: String::new(),
                missing_issuer: String::new(),
            },
            TimestampStanding::SignatureNotFromListedAuthority {
                authority: String::new(),
                claimed_issuer: String::new(),
                provider: None,
                territory: None,
            },
            TimestampStanding::PathUnverifiable {
                authority: String::new(),
                claimed_issuer: String::new(),
                provider: None,
                territory: None,
                reason: String::new(),
            },
            TimestampStanding::NotQualifiedAtStamping {
                authority: String::new(),
                provider: None,
                territory: None,
                status: None,
            },
        ];
        for standing in refused {
            assert!(
                !standing.counts_as_proof_of_existence(),
                "{standing:?} must not settle a certificate finding"
            );
        }
        assert!(
            TimestampStanding::QualifiedAtStamping {
                authority: String::new(),
                provider: None,
                territory: None,
            }
            .counts_as_proof_of_existence()
        );
    }
}

#[cfg(test)]
mod status_shape {
    use super::*;
    use dpp_domain::trusted_list::TrustServiceStatus;

    /// 🚨 A trusted-list status is not always a string.
    ///
    /// `TrustServiceStatus` is `#[non_exhaustive]` with an `Other(String)`
    /// catch-all, and it serialises as an **object** — `{"other": "<uri>"}`.
    /// Every status a list carries that is not `granted` or `withdrawn` lands
    /// there: `undersupervision`, `recognisedatnationallevel`, and whatever a
    /// Member State publishes next.
    ///
    /// Core keeps them out of the main enum deliberately, so that
    /// `undersupervision` cannot be read as a lesser kind of qualified. The cost
    /// is that `qualification.issuer.status` has three wire shapes rather than
    /// two, and a schema — or a client — that assumes a string breaks on the
    /// first such entry a real list produces.
    #[test]
    fn a_status_outside_the_granted_withdrawn_pair_is_an_object_on_the_wire() {
        assert_eq!(
            serde_json::to_string(&TrustServiceStatus::Granted).expect("serialise"),
            r#""granted""#
        );
        assert_eq!(
            serde_json::to_string(&TrustServiceStatus::Withdrawn).expect("serialise"),
            r#""withdrawn""#
        );

        let other = TrustServiceStatus::Other(
            "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/undersupervision".to_owned(),
        );
        let json = serde_json::to_value(&other).expect("serialise");
        assert!(
            json.is_object(),
            "an unrecognised status is an object, not a string: {json}"
        );
        assert_eq!(
            json["other"].as_str(),
            Some("http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/undersupervision"),
            "carrying the status URI verbatim"
        );
    }

    /// And it reaches the wire through a real verdict, not only on its own.
    #[test]
    fn the_object_form_survives_inside_an_issuer_standing() {
        let verdict = IssuerStanding::NotQualifiedAtSealing {
            issuer: "CN=A".into(),
            provider: Some("P".into()),
            territory: Some("FI".into()),
            status: Some(TrustServiceStatus::Other("http://example/x".to_owned())),
        };

        let json = serde_json::to_value(&verdict).expect("serialise");
        assert!(
            json["status"].is_object(),
            "the schema for this field has to admit an object: {json}"
        );
    }
}
