//! Verifying the list of trusted lists against the pinned anchor.

use base64::Engine as _;
use roxmltree::Document;
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
}

impl std::fmt::Display for LotlRejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(why) => write!(f, "not a readable trusted list: {why}"),
            Self::NotSigned => f.write_str("the document carries no signature"),
            Self::NoCertificate => f.write_str("the signature carries no certificate"),
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
        }
    }
}

impl std::error::Error for LotlRejected {}

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
}

impl VerifiedLotl {
    /// Every pointer the verified document carries.
    #[must_use]
    pub fn pointers(&self) -> &[TrustedListPointer] {
        &self.pointers
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

    Ok(VerifiedLotl {
        pointers,
        signed_by: base64::engine::general_purpose::STANDARD
            .encode(<sha2::Sha256 as sha2::Digest>::digest(&der)),
    })
}

/// The base64 certificate from the document's signature.
///
/// Read with the same local-name matching the rest of this module uses: the
/// signature is in the `ds:` namespace by convention rather than by requirement,
/// and a publisher is free to bind a different prefix.
fn signing_certificate(xml: &str) -> Result<String, LotlRejected> {
    let doc = Document::parse(xml).map_err(|e| LotlRejected::Malformed(format!("not XML: {e}")))?;

    let signature = doc
        .descendants()
        .find(|n| n.is_element() && n.tag_name().name() == "Signature")
        .ok_or(LotlRejected::NotSigned)?;

    signature
        .descendants()
        .find(|n| n.is_element() && n.tag_name().name() == "X509Certificate")
        .and_then(|n| n.text())
        .map(|t| t.split_whitespace().collect::<String>())
        .filter(|s| !s.is_empty())
        .ok_or(LotlRejected::NoCertificate)
}
