//! The pinned root of trust for the EU list of trusted lists.

use base64::Engine as _;
use sha2::{Digest as _, Sha256};

/// The certificates authorised to sign the EU list of trusted lists, as
/// **SHA-256 digests**, together with the Official Journal notice they were
/// taken from.
///
/// # Why digests and not certificates
///
/// The Commission publishes the LOTL-signing certificates in the Annex of an
/// Official Journal C-series notice, in PEM, **each with its SHA-256 and SHA-1
/// digest**. Publishing the digests is the hint: the certificate itself arrives
/// inside the LOTL's `ds:KeyInfo`, so a relying party does not need to carry it —
/// only to *recognise* it.
///
/// That makes the entire pinned trust root six base64 strings. It fits on a
/// screen, it diffs legibly in review, and it cannot be mistaken for a
/// certificate store that something might try to build a path through.
///
/// # Why this is compiled in and not configuration
///
/// This is the one value in the system that must not be settable by deployment.
/// An operator — or anything that can write the operator's configuration — that
/// can repoint the anchor can make *any* trusted list verify, and with it any
/// claim of qualified status that rests on one. Configuration is for choices
/// about a deployment; this is the thing the deployment is trusted *against*.
///
/// It is the same reasoning [`crate::config::SEAL_PROVIDER`] applies — a
/// node that cannot name its trust provider must not quietly become one that has
/// none — carried to its root. Changing the anchor is a reviewed commit and a
/// release, and that is the feature, not the friction.
#[derive(Debug, Clone, Copy)]
pub struct LotlAnchor {
    /// Base64 SHA-256 digests of the authorised certificates, exactly as the
    /// notice prints them.
    digests: &'static [&'static str],
    /// Where the LOTL is published, as the same notice states it.
    ///
    /// Pinned alongside the digests because the Commission may change it too,
    /// and a correct certificate presented from an unexpected location is not
    /// something to accept quietly.
    location: &'static str,
    /// CELEX of the notice these came from.
    ///
    /// Carried so provenance lives in the source rather than in someone's
    /// memory of where the numbers were copied from.
    notice_celex: &'static str,
    /// The notice's ELI, for a reader who wants to check the Annex.
    notice_uri: &'static str,
    /// When this pin was taken from that notice.
    pinned_on: &'static str,
}

/// The anchor in force, from Official Journal notice CELEX `52026XC01944`.
///
/// *"Compilation of Member States' trusted lists as notified under Commission
/// Implementing Decision (EU) 2015/1505 as amended by Commission Implementing
/// Decision (EU) 2025/2164"*.
///
/// # Verified when pinned
///
/// All six digests were checked against the live LOTL on 2026-09-11: the
/// document's EU self-pointer declares six certificates, and every one hashes to
/// a digest below. The certificate then signing the LOTL hashed to the second.
///
/// # Refreshing this
///
/// The Commission republishes the notice when the certificates or the location
/// change. There is no push, and a stale pin **fails closed** — nothing verifies,
/// which will present as an outage rather than as a warning.
///
/// The early signal is in the LOTL itself: the first entry of its
/// `SchemeInformationURI` is the notice currently in force, so a node can notice
/// that [`LotlAnchor::notice_uri`] no longer matches and say so *before* the
/// certificates change under it.
///
/// To refresh: open the notice, take the SHA-256 **base64** digests from the
/// Annex — never the SHA-1 ones, which are published for legacy tooling — and
/// replace the list below along with the CELEX, the URI and the date.
pub const EU_LOTL_ANCHOR: LotlAnchor = LotlAnchor {
    digests: &[
        "wGQcT31WxDGxySR0Lbf86cHu99f9ISETonaEhrOrzcU=",
        "4KYg+7Z0c2K7kzrEQWnWdqVTREcWz18xYF8SoiuDlrE=",
        "334pNgw0srjW1fQDJcHU0SyZIs7NM7dAdnSnSys8oeU=",
        "tj1BZ0TnCYv57CyqWWqTvCRo43+ChLpl7MBhcRvLqhg=",
        "I2ED8DqAMa6PR/kFm/jeOFZM2/6+3eSll9UPiYCqZTs=",
        "0gZP3XD2mC3MUWuG2dXFauqTlBfGJLLkeMCyneVPhHQ=",
    ],
    location: "https://ec.europa.eu/tools/lotl/eu-lotl.xml",
    notice_celex: "52026XC01944",
    notice_uri: "https://eur-lex.europa.eu/eli/C/2026/1944/oj",
    pinned_on: "2026-09-11",
};

impl LotlAnchor {
    /// Whether the Official Journal authorises this certificate to sign the LOTL.
    ///
    /// `certificate_der` is the DER the document carried — base64-decoded, not
    /// the base64 text.
    ///
    /// # 🚩 Necessary, and nowhere near sufficient
    ///
    /// A `true` here means *"the Official Journal names this certificate"*. It
    /// does **not** mean the document is authentic, and the two are easy to
    /// conflate at a call site.
    ///
    /// Anyone can copy the genuine LOTL's `ds:KeyInfo` certificate into a forged
    /// document; the forgery would satisfy this check and be a forgery still.
    /// What separates them is the **signature**, verified with this certificate
    /// over the canonicalised document — and that is a different function.
    ///
    /// So this is a precondition to run *before* verifying a signature, to
    /// establish that the key about to be trusted is one the Union published. It
    /// is never the verdict.
    #[must_use]
    pub fn authorises(&self, certificate_der: &[u8]) -> bool {
        let digest =
            base64::engine::general_purpose::STANDARD.encode(Sha256::digest(certificate_der));
        self.digests.contains(&digest.as_str())
    }

    /// Whether this is the location the notice publishes the LOTL at.
    ///
    /// Compared rather than assumed because the Commission may move it, and the
    /// move is announced in the same notice as a certificate change. A LOTL
    /// fetched from somewhere else may be perfectly genuine and still not be the
    /// one this anchor describes.
    #[must_use]
    pub fn is_pinned_location(&self, url: &str) -> bool {
        self.location == url
    }

    /// Where the notice says the LOTL is published.
    #[must_use]
    pub const fn location(&self) -> &'static str {
        self.location
    }

    /// CELEX of the Official Journal notice this pin came from.
    #[must_use]
    pub const fn notice_celex(&self) -> &'static str {
        self.notice_celex
    }

    /// ELI of that notice.
    ///
    /// Compare against the **first** entry of a fetched LOTL's
    /// `SchemeInformationURI`: that entry is the notice currently in force, so a
    /// mismatch means this pin has been superseded and should be refreshed
    /// before the certificates rotate underneath it.
    #[must_use]
    pub const fn notice_uri(&self) -> &'static str {
        self.notice_uri
    }

    /// The date this pin was taken from the notice.
    #[must_use]
    pub const fn pinned_on(&self) -> &'static str {
        self.pinned_on
    }

    /// How many certificates the notice authorises.
    #[must_use]
    pub const fn authorised_count(&self) -> usize {
        self.digests.len()
    }

    /// The raw pinned digests, for this crate's own tests.
    ///
    /// Deliberately not public. A caller with the digest list can only
    /// reimplement [`Self::authorises`], and a second implementation of the
    /// trust decision is the last thing this type should make easy.
    #[cfg(test)]
    pub(crate) const fn digests_for_test(&self) -> &'static [&'static str] {
        self.digests
    }
}
