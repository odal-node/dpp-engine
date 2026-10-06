//! Where a fresh timestamp comes from.
//!
//! Renewing a seal's archive timestamp needs exactly one thing from outside: an
//! RFC 3161 token over an imprint this node computed. That is a different thing
//! from sealing — no key is involved and nothing is signed here — so it is a
//! different seam from [`dpp_domain::ports::seal::SealPort`], and deliberately not
//! a method on it. A `SealPort` is *a backend that seals*; a timestamp authority
//! is reached the same way whichever backend sealed the passport, and a seal
//! bought from one provider can be renewed by an authority that has nothing to do
//! with it.
//!
//! The seam lives here rather than in `dpp-domain` for the reason the inspector
//! does: it is a property of the stored bytes plus an authority, not of a sealing
//! backend, and putting it in the published core crate would mean waiting on a
//! release for something no other consumer needs.
//!
//! Two implementations, and the second is the point:
//!
//! - [`crate::local::LocalTimestampSource`] — the development authority, so the
//!   whole renewal path can be exercised without one. Not qualified, and says so
//!   in its certificate.
//! - [`crate::rfc3161::Rfc3161Source`] — any authority that speaks RFC 3161 over
//!   HTTP, configured by address. Provider-independent on purpose: a qualified
//!   timestamp is a service of a qualified trust service provider (Reg. (EU)
//!   No 910/2014 Art. 42), and which one an operator buys it from is theirs to
//!   decide.
//!
//! There is no placeholder source. A node with no authority configured renews
//! nothing, and reports that rather than pretending to stamp.

use async_trait::async_trait;

use crate::error::SealError;

/// Something that will stamp an imprint.
#[async_trait]
pub trait TimestampSource: Send + Sync {
    /// An RFC 3161 time-stamp token over `imprint`, exactly as the authority made
    /// it.
    ///
    /// `imprint` is the SHA-256 of whatever is being stamped; the caller decides
    /// what that is, because this is called for a renewal whose imprint covers a
    /// whole signature structure (EN 319 122-1 clause 5.5.3) and not for a
    /// document.
    ///
    /// The result is a DER `ContentInfo` — a CMS `SignedData` whose content is a
    /// `TSTInfo`. **It is not trusted on receipt.** Whether it really stamps this
    /// imprint, whether it verifies, and whether its authority is one anybody
    /// lists are all checked by the caller, because a source that vouched for its
    /// own output would be a source nobody could audit.
    ///
    /// # Errors
    ///
    /// [`SealError::Transport`] when the authority could not be reached, and
    /// [`SealError::Backend`] when it answered and refused or returned something
    /// that is not a token for this imprint.
    async fn stamp(&self, imprint: &[u8; 32]) -> Result<Vec<u8>, SealError>;

    /// A short name for logs and metrics. Never a secret, never an address.
    fn name(&self) -> &'static str;
}
