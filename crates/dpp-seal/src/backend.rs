//! `SealBackend` — the one thing every sealing backend has to be able to do.
//!
//! [`crate::adapter::QtspSealAdapter`] holds one of these and does nothing but
//! forward the port's calls to it. The seam exists so that adding, swapping or
//! dropping a backend touches that backend's module and the selector, and
//! nothing else — in particular, not the `SealPort` implementation, which has
//! no business knowing which one it holds.
//!
//! Two things separate this from `SealPort` itself, and they are the reason it
//! is a distinct trait rather than a rename:
//!
//! - **The error type.** A backend returns [`SealError`], which still carries
//!   the classification made where the failure happened. The adapter collapses
//!   it into `DppError` once, at the port boundary, so no backend has to.
//! - **`verify` refuses by default.** Claiming a seal valid on a check that was
//!   never performed is the failure this crate is most exposed to, so silence is
//!   the default and a backend that can genuinely verify has to say so.

use async_trait::async_trait;
use dpp_domain::ports::seal::{SealCapabilities, SealRequest, SealVerification, SealedEnvelope};

use crate::error::SealError;

/// What [`SealBackend::verify`] says instead of guessing.
const VERIFY_UNSUPPORTED: &str = "seal verification is not implemented for this backend: a qualified seal is only meaningfully \
     validated by a party independent of whoever produced it, and this adapter will not report a \
     seal valid on a check it did not perform";

/// One way of producing a seal: a hosted trust service, a local key, a placeholder.
#[async_trait]
pub trait SealBackend: Send + Sync {
    /// Produce a seal over the request's payload digest.
    async fn seal(&self, req: SealRequest) -> Result<SealedEnvelope, SealError>;

    /// Which formats and modes this backend can actually produce.
    ///
    /// It must answer for what it does, not for what the port allows: a
    /// capability nothing here can deliver is a promise the trust report will
    /// carry outward.
    fn capabilities(&self) -> SealCapabilities;

    /// Verify a seal — by default, refuse to.
    ///
    /// The default is refusal because the interesting case cannot be answered
    /// here: a *qualified* seal is worth what the independence of its validator
    /// is worth, so a verdict this node issues on a seal this node bought
    /// attests nothing a relying party should accept. Rust AdES tooling exists
    /// and will improve; that was never what made the answer unavailable.
    ///
    /// A backend that can genuinely check its own output — one whose seals make
    /// no trust claim beyond the key, so that a cryptographic check *is* the
    /// whole truth about them — should override this and say so.
    async fn verify(&self, env: &SealedEnvelope) -> Result<SealVerification, SealError> {
        let _ = env;
        Err(SealError::Unsupported(VERIFY_UNSUPPORTED))
    }
}
