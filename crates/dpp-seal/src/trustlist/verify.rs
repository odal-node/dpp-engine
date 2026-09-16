//! Verifying the list of trusted lists against the pinned anchor.

use base64::Engine as _;
use roxmltree::{Document, Node};
use xml_sec::xmldsig::{DefaultKeyResolver, DsigStatus, VerifyContext};

use super::anchor::{EU_LOTL_ANCHOR, LotlAnchor};
use super::model::TrustedListPointer;
use super::parse::parse_lotl;

/// Why a list of trusted lists was not accepted.
///
/// Typed rather than a string, because the operator's response differs
/// completely per case and a log line has to make that obvious. A rejected LOTL
/// is either a stale pin, an attack, or a broken download, and those want three
/// different people.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LotlRejected {
    /// The document could not be read as XML, or is not a trusted list.
    Malformed(String),
    /// It carries no signature, or none this verifier could locate.
    NotSigned,
    /// The signature carries no X.509 certificate to check against.
    NoCertificate,
    /// `ds:KeyInfo` carries more than one certificate, so which one the
    /// signature will be verified with is not decidable here.
    ///
    /// Refused rather than guessed. Checking the anchor against one certificate
    /// while `xml-sec` verifies with another would make the trust decision and
    /// the cryptography about different keys — see [`signing_certificate`].
    AmbiguousSigningCertificate {
        /// How many certificates `ds:KeyInfo` carries.
        found: usize,
    },
    /// The certificate is not one the Official Journal authorises.
    ///
    /// **The interesting case.** Most often it means the pin is stale — the
    /// Commission has published a new notice and the anchor has not been
    /// refreshed. It can also mean the document is not the Commission's at all.
    /// The two are indistinguishable from here, which is why the digest is
    /// carried: an operator can compare it against the notice themselves.
    NotAnchored {
        /// Base64 SHA-256 of the certificate that was offered.
        offered: String,
        /// CELEX of the notice this node is pinned to.
        pinned_notice: &'static str,
    },
    /// The certificate is authorised, and the signature over the document does
    /// not verify with it.
    ///
    /// Not a stale pin. The document has been altered, truncated, or was never
    /// signed by the key it names.
    SignatureInvalid(String),
    /// The signature is not shaped the way CID (EU) 2015/1505 Annex I requires.
    ///
    /// Distinct from [`Self::SignatureInvalid`] on purpose, and the distinction
    /// is the whole reason this variant exists: a signature can verify
    /// perfectly and still cover something other than the document being read,
    /// because the transform chain decides what "the document" means. An
    /// operator seeing this has a conformance problem at the publisher, not a
    /// tampered file — and the two send them to different people.
    NonConformantProfile(String),
}

impl std::fmt::Display for LotlRejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(why) => write!(f, "not a readable trusted list: {why}"),
            Self::NotSigned => f.write_str("the document carries no signature"),
            Self::NoCertificate => f.write_str("the signature carries no certificate"),
            Self::AmbiguousSigningCertificate { found } => write!(
                f,
                "ds:KeyInfo carries {found} certificates, and which one signed the document is \
                 not decidable without resolving the chain — refusing rather than checking the \
                 anchor against a certificate that may not be the one it was verified with"
            ),
            Self::NotAnchored {
                offered,
                pinned_notice,
            } => write!(
                f,
                "signed by {offered}, which Official Journal notice {pinned_notice} does not \
                 authorise — refresh the pinned anchor from the current notice, or treat this \
                 document as untrusted"
            ),
            Self::SignatureInvalid(why) => {
                write!(f, "the signature does not verify: {why}")
            }
            Self::NonConformantProfile(why) => write!(
                f,
                "the signature does not follow the profile CID (EU) 2015/1505 Annex I \
                 mandates: {why}"
            ),
        }
    }
}

impl std::error::Error for LotlRejected {}

/// Whether the pinned anchor is still the notice the LOTL itself names.
///
/// **Not part of the verdict.** A superseded pin keeps verifying until the
/// Commission actually rotates the signing certificates, which is exactly why
/// this is worth reporting: the window between "a newer notice exists" and "the
/// old certificates stop being used" is the only chance to refresh without an
/// outage. Folding it into [`LotlRejected`] would refuse documents that verify
/// perfectly today.
///
/// The failure it exists to pre-empt is unpleasant: a pin nobody refreshes
/// eventually meets a LOTL signed by a certificate the notice no longer names,
/// which fails closed as [`LotlRejected::NotAnchored`] — on a date nobody has in
/// a calendar, looking like an outage rather than a lapsed pin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnchorFreshness {
    /// The LOTL names the notice this build is pinned to.
    Current,
    /// The LOTL names a different notice, so the Commission has republished.
    ///
    /// Carries what the document named so an operator can go and read it,
    /// rather than being told only that their pin is wrong.
    Superseded {
        /// The notice the LOTL names as currently in force.
        lotl_names: String,
    },
    /// The document names no notice at all, so the question cannot be answered.
    ///
    /// Distinct from [`Current`](Self::Current) deliberately. Treating "could
    /// not tell" as "up to date" is how a staleness signal goes quiet at the
    /// moment it is most needed — the same fail-closed direction the rest of
    /// this module takes.
    Unknown,
}

impl std::fmt::Display for AnchorFreshness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Current => f.write_str("the pinned notice is the one in force"),
            Self::Superseded { lotl_names } => write!(
                f,
                "the list of lists names {lotl_names} as the notice in force, which is not the \
                 one this build pins — refresh the anchor from it before the signing \
                 certificates rotate"
            ),
            Self::Unknown => {
                f.write_str("the list of lists names no notice, so the pin cannot be checked")
            }
        }
    }
}

/// The notice a LOTL names as currently in force, compared against `pinned`.
///
/// The document lists its notice **first** in `SchemeInformationURI`, ahead of
/// the pivot chain and the per-language legal notices. That ordering is what
/// makes this cheap; it is also the only thing this reads, so a document that
/// reorders those entries would report `Superseded` rather than silently
/// comparing the wrong one.
pub(super) fn anchor_freshness(xml: &str, pinned: &str) -> AnchorFreshness {
    let Ok(doc) = Document::parse(xml) else {
        return AnchorFreshness::Unknown;
    };
    let named = doc
        .descendants()
        .find(|n| n.is_element() && n.tag_name().name() == "SchemeInformationURI")
        .and_then(|n| {
            n.children()
                .find(|c| c.is_element() && c.tag_name().name() == "URI")
        })
        .and_then(|n| n.text())
        .map(str::trim)
        .filter(|s| !s.is_empty());

    match named {
        None => AnchorFreshness::Unknown,
        Some(uri) if uri == pinned => AnchorFreshness::Current,
        Some(uri) => AnchorFreshness::Superseded {
            lotl_names: uri.to_owned(),
        },
    }
}

/// A list of trusted lists whose signature has been verified against the anchor.
///
/// The type exists so a verified document cannot be passed where an unverified
/// one is expected, or the reverse. [`UnverifiedTrustedList`](super::UnverifiedTrustedList)
/// is what parsing alone produces; this is what survives
/// [`verify_lotl`].
///
/// Constructible only by this module — there is no public constructor, so a
/// value of this type is evidence that the check ran.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedLotl {
    pointers: Vec<TrustedListPointer>,
    signed_by: String,
    anchor_freshness: AnchorFreshness,
}

impl VerifiedLotl {
    /// Every pointer the verified document carries.
    #[must_use]
    pub fn pointers(&self) -> &[TrustedListPointer] {
        &self.pointers
    }

    /// Whether the pin this verified against is still the notice in force.
    ///
    /// Read it. A `Verified` document says the signature and the anchor agree
    /// *today*; this says whether that will still be true after the next
    /// rotation, and it is the only warning there is.
    #[must_use]
    pub fn anchor_freshness(&self) -> &AnchorFreshness {
        &self.anchor_freshness
    }

    /// Base64 SHA-256 of the anchored certificate that signed it.
    ///
    /// For a trust report: it says *which* of the authorised certificates the
    /// Commission is currently signing with, which is the thing that changes
    /// when a rotation is coming.
    #[must_use]
    pub fn signed_by(&self) -> &str {
        &self.signed_by
    }
}

/// Verify the list of trusted lists against the compiled-in anchor.
///
/// # What a success means
///
/// Two things, both necessary and neither sufficient alone:
///
/// 1. the certificate in the document's `ds:KeyInfo` is one the Official Journal
///    authorises to sign the LOTL — see [`LotlAnchor::authorises`]; **and**
/// 2. the XML signature over the canonicalised document verifies with that
///    certificate.
///
/// The anchor is what makes the signature check mean anything. A forgery signed
/// by its author's own key verifies perfectly against that key; only (1) rules
/// it out, and a verifier that did (2) alone would accept anything self-consistent.
///
/// The two are checked in that order for a narrower reason: signature
/// verification canonicalises the whole document, which is real work on input
/// that has not yet been shown to come from anywhere in particular. Establishing
/// the key is authorised first keeps that work behind the trust decision. The
/// verdict would be the same either way — this is defence in depth, not
/// correctness.
///
/// # What it still does not mean
///
/// That the certificate is *currently valid*. This checks identity against a
/// published list, not expiry or revocation — the Official Journal is the
/// authority for which keys may sign, and it is not a CRL. A node should report
/// the certificate's validity window separately; the one signing when this
/// anchor was pinned expires 2027-11-17.
///
/// # Errors
///
/// [`LotlRejected`], typed so the three very different causes — stale pin,
/// tampered document, broken download — are distinguishable at the call site.
pub fn verify_lotl(xml: &str) -> Result<VerifiedLotl, LotlRejected> {
    verify_lotl_with(xml, &EU_LOTL_ANCHOR)
}

/// [`verify_lotl`] against a caller-supplied anchor.
///
/// Exists for this crate's tests, which need to exercise the `NotAnchored` path
/// without a forged Commission signature. Production callers want
/// [`verify_lotl`]: an anchor that arrives as an argument is an anchor something
/// else chose, and the whole point of pinning is that nothing else chooses it.
pub fn verify_lotl_with(xml: &str, anchor: &LotlAnchor) -> Result<VerifiedLotl, LotlRejected> {
    let certificate = signing_certificate(xml)?;
    let der = base64::engine::general_purpose::STANDARD
        .decode(&certificate)
        .map_err(|e| LotlRejected::Malformed(format!("certificate is not base64: {e}")))?;

    // The anchor before the signature: canonicalising a document is real work,
    // and this keeps it behind the trust decision. The verdict is the same
    // either way — see this function's documentation.
    if !anchor.authorises(&der) {
        return Err(LotlRejected::NotAnchored {
            offered: base64::engine::general_purpose::STANDARD
                .encode(<sha2::Sha256 as sha2::Digest>::digest(&der)),
            pinned_notice: anchor.notice_celex(),
        });
    }

    // Before the signature, for the same reason the anchor is: this decides
    // what a signature would even be covering, and handing an arbitrary
    // transform chain to the canonicaliser is the thing the profile exists to
    // prevent. A valid signature must not be able to excuse a chain the law
    // does not permit.
    check_signature_profile(xml).map_err(LotlRejected::NonConformantProfile)?;

    let resolver = DefaultKeyResolver::default();
    let outcome = VerifyContext::new()
        .key_resolver(&resolver)
        .verify(xml)
        .map_err(|e| LotlRejected::SignatureInvalid(e.to_string()))?;

    if !matches!(outcome.status, DsigStatus::Valid) {
        return Err(LotlRejected::SignatureInvalid(format!(
            "{:?}",
            outcome.status
        )));
    }

    let pointers = parse_lotl(xml).map_err(|e| LotlRejected::Malformed(e.to_string()))?;

    // Computed after the verdict, never as part of it — see `AnchorFreshness`.
    // Logged as well as returned because the caller that most needs to act on it
    // is an operator reading logs, not the code holding the `VerifiedLotl`.
    let freshness = anchor_freshness(xml, anchor.notice_uri());
    match &freshness {
        AnchorFreshness::Current => {}
        other => tracing::warn!(
            pinned_notice = anchor.notice_celex(),
            "trusted-list anchor: {other}"
        ),
    }

    Ok(VerifiedLotl {
        pointers,
        signed_by: base64::engine::general_purpose::STANDARD
            .encode(<sha2::Sha256 as sha2::Digest>::digest(&der)),
        anchor_freshness: freshness,
    })
}

/// Why a national trusted list was not accepted.
///
/// Separate from [`LotlRejected`] despite the overlap, because the remedies have
/// nothing in common. A LOTL this node will not accept usually means *our* pin
/// is stale; a national list the LOTL does not vouch for means something is
/// wrong at the Member State's end, or with the document in front of us. One
/// shared enum would have a variant meaning two different things depending on
/// which document produced it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustedListRejected {
    /// The document could not be read as XML, or is not a trusted list.
    Malformed(String),
    /// It carries no signature.
    NotSigned,
    /// The signature carries no X.509 certificate.
    NoCertificate,
    /// `ds:KeyInfo` carries more than one certificate.
    ///
    /// Same refusal and same reason as
    /// [`LotlRejected::AmbiguousSigningCertificate`], and it matters more here:
    /// the certificate is compared against the set the LOTL names, so picking
    /// the wrong one of several could let a certificate the LOTL names vouch
    /// for a signature made by a different key beside it.
    AmbiguousSigningCertificate {
        /// How many certificates `ds:KeyInfo` carries.
        found: usize,
    },
    /// The verified LOTL names no certificates at all for this territory.
    ///
    /// Distinct from being named and not matching: nothing can be verified here,
    /// rather than something failing to. A pointer with no certificates cannot
    /// vouch for anything.
    NoAuthorisedCertificates,
    /// The list is signed by a certificate the LOTL does not name for it.
    ///
    /// Most likely a Member State mid-rotation whose LOTL entry has not caught
    /// up, or a document that is not theirs. Unlike a stale anchor this is not
    /// something the operator can fix — it is a finding to report, not a
    /// configuration to change.
    NotNamedByLotl {
        /// Base64 SHA-256 of the certificate that was offered.
        offered: String,
        /// How many the LOTL names for this list.
        authorised: usize,
    },
    /// The certificate is named, and the signature does not verify with it.
    SignatureInvalid(String),
    /// The signature is not shaped the way CID (EU) 2015/1505 Annex I requires.
    ///
    /// Same distinction as [`LotlRejected::NonConformantProfile`]: a shape
    /// problem at the Member State's publisher, not an altered document.
    NonConformantProfile(String),
}

impl std::fmt::Display for TrustedListRejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(why) => write!(f, "not a readable trusted list: {why}"),
            Self::NotSigned => f.write_str("the document carries no signature"),
            Self::NoCertificate => f.write_str("the signature carries no certificate"),
            Self::AmbiguousSigningCertificate { found } => write!(
                f,
                "ds:KeyInfo carries {found} certificates, so the one compared against the list \
                 of trusted lists need not be the one the signature was verified with — \
                 refusing rather than choosing between them"
            ),
            Self::NoAuthorisedCertificates => {
                f.write_str("the list of trusted lists names no certificate for this list")
            }
            Self::NotNamedByLotl {
                offered,
                authorised,
            } => write!(
                f,
                "signed by {offered}, which is not among the {authorised} certificate(s) the \
                 list of trusted lists names for it — the scheme operator may be mid-rotation, \
                 or this document is not theirs"
            ),
            Self::SignatureInvalid(why) => write!(f, "the signature does not verify: {why}"),
            Self::NonConformantProfile(why) => write!(
                f,
                "the signature does not follow the profile CID (EU) 2015/1505 Annex I \
                 mandates: {why}"
            ),
        }
    }
}

impl std::error::Error for TrustedListRejected {}

/// A national trusted list whose signature has been verified against the
/// certificates a **verified** list of trusted lists names for it.
///
/// No public constructor, for the same reason [`VerifiedLotl`] has none.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedTrustedList {
    content: super::model::UnverifiedTrustedList,
    signed_by: String,
}

impl VerifiedTrustedList {
    /// Assert verification, for tests only.
    ///
    /// The type has no public constructor so that nothing outside this module
    /// can claim a list was verified when it was not, and that stays true: this
    /// is `pub(crate)` and `#[cfg(test)]`, so it does not exist in a built
    /// library.
    ///
    /// It earns its place by making the *positive* path testable. Everything
    /// downstream of a verified list — matching a seal's issuer, walking a
    /// certificate path to it, reading a status at sealing time — could
    /// otherwise only ever be exercised on its failure branches, because no
    /// published list carries a CA whose private key a test can hold. With this,
    /// a test can generate its own certificate authority and check that a
    /// genuinely issued certificate is genuinely recognised.
    #[cfg(test)]
    pub(crate) fn asserted_for_tests(
        content: super::model::UnverifiedTrustedList,
        signed_by: impl Into<String>,
    ) -> Self {
        Self {
            content,
            signed_by: signed_by.into(),
        }
    }

    /// The `SchemeTerritory`, where the list gives one.
    #[must_use]
    pub fn territory(&self) -> Option<&str> {
        self.content.territory.as_deref()
    }

    /// The providers the list carries.
    #[must_use]
    pub fn providers(&self) -> &[super::model::ListedProvider] {
        &self.content.providers
    }

    /// Providers listed for a service type, with those services.
    ///
    /// The lookup the Art. 39a question needs, now over content that has been
    /// verified rather than merely fetched.
    pub fn providers_offering<'a>(
        &'a self,
        service_type: &'a str,
    ) -> impl Iterator<
        Item = (
            &'a super::model::ListedProvider,
            Vec<&'a super::model::ListedService>,
        ),
    > + 'a {
        self.content.providers_offering(service_type)
    }

    /// Base64 SHA-256 of the certificate that signed it.
    #[must_use]
    pub fn signed_by(&self) -> &str {
        &self.signed_by
    }
}

/// Verify a national trusted list against the certificates its pointer names.
///
/// `pointer` must come from a [`VerifiedLotl`]. That is the whole chain: the
/// Official Journal anchors the list of lists, and the list of lists anchors
/// every national list. Taking a pointer from an unverified document would move
/// the trust problem rather than solve it, which is why
/// [`TrustedListPointer::certificates`] says so too.
///
/// # Errors
///
/// [`TrustedListRejected`]. Note the deliberate split between
/// [`TrustedListRejected::NotNamedByLotl`] and
/// [`TrustedListRejected::SignatureInvalid`]: the first is a document signed by
/// the wrong key, the second a document altered after signing, and only the
/// second means someone touched the bytes.
pub fn verify_trusted_list(
    xml: &str,
    pointer: &TrustedListPointer,
) -> Result<VerifiedTrustedList, TrustedListRejected> {
    if pointer.certificates.is_empty() {
        return Err(TrustedListRejected::NoAuthorisedCertificates);
    }

    let certificate = signing_certificate(xml).map_err(|e| match e {
        LotlRejected::Malformed(why) => TrustedListRejected::Malformed(why),
        LotlRejected::NotSigned => TrustedListRejected::NotSigned,
        LotlRejected::AmbiguousSigningCertificate { found } => {
            TrustedListRejected::AmbiguousSigningCertificate { found }
        }
        _ => TrustedListRejected::NoCertificate,
    })?;

    // Compared as the published base64 rather than by digest: the LOTL carries
    // the certificates themselves, so there is nothing to hash against and a
    // digest step would only add a place to disagree about encoding.
    if !pointer.certificates.iter().any(|c| c == &certificate) {
        let der = base64::engine::general_purpose::STANDARD
            .decode(&certificate)
            .unwrap_or_default();
        return Err(TrustedListRejected::NotNamedByLotl {
            offered: base64::engine::general_purpose::STANDARD
                .encode(<sha2::Sha256 as sha2::Digest>::digest(&der)),
            authorised: pointer.certificates.len(),
        });
    }

    // Same ordering and the same reason as the LOTL path: the profile decides
    // what the signature covers, so it is checked before one is computed.
    check_signature_profile(xml).map_err(TrustedListRejected::NonConformantProfile)?;

    let resolver = DefaultKeyResolver::default();
    let outcome = VerifyContext::new()
        .key_resolver(&resolver)
        .verify(xml)
        .map_err(|e| TrustedListRejected::SignatureInvalid(e.to_string()))?;

    if !matches!(outcome.status, DsigStatus::Valid) {
        return Err(TrustedListRejected::SignatureInvalid(format!(
            "{:?}",
            outcome.status
        )));
    }

    let content = super::parse::parse_trusted_list(xml)
        .map_err(|e| TrustedListRejected::Malformed(e.to_string()))?;

    let der = base64::engine::general_purpose::STANDARD
        .decode(&certificate)
        .unwrap_or_default();
    Ok(VerifiedTrustedList {
        content,
        signed_by: base64::engine::general_purpose::STANDARD
            .encode(<sha2::Sha256 as sha2::Digest>::digest(&der)),
    })
}

/// The enveloped-signature transform, the first of the two the profile mandates.
const ENVELOPED_SIGNATURE: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
/// Exclusive canonicalization, the second.
const EXCLUSIVE_C14N: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";

/// Check the signature against the transform profile the law mandates.
///
/// ✅ COMPLIANCE-PIN: CID (EU) 2015/1505 Annex I, Chapter II, the "Signature
/// element (clause B.1), General (clause B.1.0)" section inserted by CID (EU)
/// 2025/2164, Annex, point (3). Applicable since 29 April 2026 (its Art. 2).
///
/// The clause is a **closed profile**: `ds:SignedInfo` shall contain a
/// `ds:Reference` with `URI=""` — referring to the entire document — and that
/// reference shall contain only one `ds:Transforms`, which shall contain two
/// `ds:Transform`, the first enveloped-signature and the second exclusive
/// canonicalization.
///
/// # Why this is asserted rather than left to the verifier
///
/// Transforms decide *what was actually signed*, so a permissive transform chain
/// is the classic signature-wrapping surface: a signature that validates
/// perfectly can cover something other than the document being read. The
/// narrowness of the profile is the point of it.
///
/// `xml-sec` does not constrain this by default, and that was checked rather
/// than assumed. Its `TransformPolicy::allowed_algorithms` is documented as
/// "`None` accepts every implemented algorithm" and defaults to `None`, and the
/// implemented set includes XPath and XPath Filter 2.0 — the two most expressive
/// ways to change what a reference covers. `max_transforms_per_reference`
/// defaults to 64. So this assertion is known-necessary, not known-redundant.
///
/// Tightening `allowed_algorithms` to these two URIs would refuse a
/// non-conformant chain *during* verification rather than beside it, which is
/// stronger. It is deliberately not done here: the acceptance bar for that is
/// the full set of lists from the LOTL's own pointers, not the two fixtures in
/// this repository, because one Member State using a different canonicalization
/// for its XAdES reference would stop verifying.
///
/// # What it deliberately does not constrain
///
/// Only the `URI=""` reference. Both published documents carry a **second**
/// reference, to the XAdES `SignedProperties`, with its own single
/// exclusive-c14n transform. The clause governs the reference over the whole
/// document and says nothing about the others, so constraining them would refuse
/// every real trusted list — including the Commission's own.
fn check_signature_profile(xml: &str) -> Result<(), String> {
    let doc = Document::parse(xml).map_err(|e| format!("not XML: {e}"))?;

    let signed_info = doc
        .descendants()
        .find(|n| n.is_element() && n.tag_name().name() == "SignedInfo")
        .ok_or_else(|| "the signature carries no SignedInfo".to_owned())?;

    // Direct children only. A `Reference` nested deeper is not one `SignedInfo`
    // presents to the verifier, and counting it would let an unrelated element
    // change the verdict.
    let whole_document: Vec<Node> = signed_info
        .children()
        .filter(|n| {
            n.is_element() && n.tag_name().name() == "Reference" && n.attribute("URI") == Some("")
        })
        .collect();

    let reference = match whole_document.as_slice() {
        [one] => *one,
        [] => {
            return Err(
                "no ds:Reference with URI=\"\" — nothing in this signature covers the \
                        whole document"
                    .to_owned(),
            );
        }
        many => {
            return Err(format!(
                "{} ds:Reference elements carry URI=\"\" — two document-wide references leave it \
                 ambiguous which one was checked",
                many.len()
            ));
        }
    };

    let transform_sets: Vec<Node> = reference
        .children()
        .filter(|n| n.is_element() && n.tag_name().name() == "Transforms")
        .collect();
    if transform_sets.len() != 1 {
        return Err(format!(
            "the URI=\"\" reference carries {} ds:Transforms elements, and the profile allows \
             exactly one",
            transform_sets.len()
        ));
    }

    let algorithms: Vec<&str> = transform_sets[0]
        .children()
        .filter(|n| n.is_element() && n.tag_name().name() == "Transform")
        .map(|n| n.attribute("Algorithm").unwrap_or_default())
        .collect();

    match algorithms.as_slice() {
        [ENVELOPED_SIGNATURE, EXCLUSIVE_C14N] => Ok(()),
        [first, second] => Err(format!(
            "the URI=\"\" reference transforms are [{first}, {second}], and the profile requires \
             [{ENVELOPED_SIGNATURE}, {EXCLUSIVE_C14N}] in that order"
        )),
        other => Err(format!(
            "the URI=\"\" reference carries {} ds:Transform elements, and the profile requires \
             exactly two",
            other.len()
        )),
    }
}

/// The base64 certificate from the document's signature.
///
/// Read with the same local-name matching the rest of this module uses: the
/// signature is in the `ds:` namespace by convention rather than by requirement,
/// and a publisher is free to bind a different prefix.
///
/// # Why this reads `ds:KeyInfo`, and why it insists on exactly one
///
/// Everything above depends on this returning **the certificate the signature
/// will actually be verified with**. Nothing else in this module establishes
/// that: the anchor decision is taken here, and the signature is computed by
/// `xml-sec` afterwards, from a certificate it selects for itself. If the two
/// pick differently, the trust decision is about one certificate and the
/// cryptography about another, and a caller cannot tell — [`VerifyResult`]
/// exposes no certificate, so there is nothing to compare afterwards.
///
/// They do select differently. `xml-sec` resolves the signing certificate from
/// `ds:KeyInfo` by *chain analysis* — `select_x509_signing_certificate` takes
/// the entry that is neither self-signed nor the issuer of any other entry, and
/// only falls back to document order when that finds nothing. Document order is
/// what a reader like this one sees. For a `ds:KeyInfo` carrying a chain rather
/// than a single certificate — leaf last, which XMLDSig permits — the two
/// disagree, and the disagreement is silent in the permissive direction.
///
/// Both constraints below make them provably agree:
///
/// - **scoped to `ds:KeyInfo`**, because that is the only place `xml-sec`
///   resolves keys from. A `ds:Object` carrying XAdES `CertificateValues` holds
///   certificates too, and a search over the whole `ds:Signature` could return
///   one of those;
/// - **exactly one**, because with one certificate every selection rule — chain
///   analysis, a lookup identifier, document order — resolves to the same bytes.
///
/// This is *our* requirement, not a clause of the profile
/// [`check_signature_profile`] pins; CID (EU) 2015/1505 says nothing about how
/// many certificates `ds:KeyInfo` may carry. It is fail-closed, and it costs
/// nothing today: the Commission's own list and every national list checked
/// carry exactly one. A publisher that starts shipping a full chain is refused
/// with [`LotlRejected::AmbiguousSigningCertificate`] rather than trusted on a
/// certificate nobody verified with — and the fix then is to resolve the leaf
/// the way `xml-sec` does, not to take the first.
fn signing_certificate(xml: &str) -> Result<String, LotlRejected> {
    let doc = Document::parse(xml).map_err(|e| LotlRejected::Malformed(format!("not XML: {e}")))?;

    let signature = doc
        .descendants()
        .find(|n| n.is_element() && n.tag_name().name() == "Signature")
        .ok_or(LotlRejected::NotSigned)?;

    let key_info = signature
        .descendants()
        .find(|n| n.is_element() && n.tag_name().name() == "KeyInfo")
        .ok_or(LotlRejected::NoCertificate)?;

    let certificates: Vec<String> = key_info
        .descendants()
        .filter(|n| n.is_element() && n.tag_name().name() == "X509Certificate")
        .filter_map(|n| n.text())
        .map(|t| t.split_whitespace().collect::<String>())
        .filter(|s| !s.is_empty())
        .collect();

    match certificates.as_slice() {
        [one] => Ok(one.clone()),
        [] => Err(LotlRejected::NoCertificate),
        many => Err(LotlRejected::AmbiguousSigningCertificate { found: many.len() }),
    }
}
