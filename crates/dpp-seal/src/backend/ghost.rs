//! The placeholder backend: synthetic envelopes, no legal validity.
//!
//! `GhostSeal` is the port's own placeholder, so there is nothing to implement
//! here beyond making it a [`SealBackend`] like any other. That it satisfies the
//! same trait as a live provider is the point — a node with no provider takes
//! the identical path, and the difference shows up as `placeholder: true` on the
//! envelope and a `Ghost` trust tier at boot, which a production profile refuses
//! to start on.

use async_trait::async_trait;
use dpp_domain::{
    ports::seal::SealPort,
    seal::{SealCapabilities, SealRequest, SealVerification, SealedEnvelope},
};
use tracing::warn;

pub use dpp_domain::ports::seal::GhostSeal;

use crate::backend::SealBackend;
use crate::error::SealError;

#[async_trait]
impl SealBackend for GhostSeal {
    async fn seal(&self, req: SealRequest) -> Result<SealedEnvelope, SealError> {
        warn!(
            "no seal provider configured — sealing with GhostSeal (placeholder, no legal validity)"
        );
        SealPort::seal(self, req).await.map_err(backend_err)
    }

    fn capabilities(&self) -> SealCapabilities {
        // The placeholder genuinely produces (synthetic) seals — report what
        // `GhostSeal` actually does rather than claiming nothing.
        SealPort::capabilities(self)
    }

    /// Overrides the refusing default: `GhostSeal` verifies, and its answer is
    /// honest — `valid: false`, `placeholder: true`. Refusing here would hide
    /// the one thing a caller most needs to learn from a ghost.
    async fn verify(&self, env: &SealedEnvelope) -> Result<SealVerification, SealError> {
        SealPort::verify(self, env).await.map_err(backend_err)
    }
}

/// `GhostSeal` speaks the port's coarse error; nothing here can re-classify it.
fn backend_err(e: dpp_domain::error::DppError) -> SealError {
    SealError::Backend(e.to_string())
}
