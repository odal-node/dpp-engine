//! `QtspSealAdapter` — the `SealPort` implementation.
//!
//! It holds one [`SealBackend`] and does nothing else: forward the port's three
//! calls, and collapse [`SealError`] into `DppError` at the boundary. Which
//! backend it holds is decided by [`crate::config`] and constructed by that
//! backend's own module, so nothing in this file names one — adding or removing
//! a backend leaves it untouched.

use async_trait::async_trait;
use dpp_domain::{
    error::DppError,
    ports::seal::SealPort,
    seal::{SealCapabilities, SealRequest, SealVerification, SealedEnvelope},
};

use crate::backend::SealBackend;
use crate::error::SealError;

/// eIDAS seal adapter over whichever backend the node was configured with.
pub struct QtspSealAdapter {
    backend: Box<dyn SealBackend>,
}

impl QtspSealAdapter {
    /// Wrap a backend as the node's `SealPort`.
    pub fn new(backend: impl SealBackend + 'static) -> Self {
        Self {
            backend: Box::new(backend),
        }
    }
}

#[async_trait]
impl SealPort for QtspSealAdapter {
    /// Refuses anything the backend does not advertise, before dispatching.
    ///
    /// `SealCapabilities::can_produce` is the domain's own definition of "can
    /// this backend serve this request", and checking it here is what makes a
    /// backend's advertised capabilities binding rather than decorative. Without
    /// it a node asking for `B-LT` from a backend enabled only for `B-T` gets
    /// back whatever the provider chose to produce, recorded as though it were
    /// what was asked for — and the gap surfaces years later, when the seal
    /// stops verifying and the evidence dossier still claims the higher level.
    ///
    /// Refusing costs a retry (the drain backs off, and an exhausted row is
    /// reported as published-but-unsealed). That is the cheaper failure: an
    /// unsealed passport is visible now, where a seal that quietly under-delivers
    /// is discovered only once it matters.
    ///
    /// One check here rather than one per backend, for the reason the domain
    /// gives for defining it once: a backend rolling its own would be free to
    /// disagree with the capabilities it publishes.
    async fn seal(&self, req: SealRequest) -> Result<SealedEnvelope, DppError> {
        let caps = self.backend.capabilities();
        if !caps.can_produce(&req) {
            return Err(SealError::Config(format!(
                "backend cannot produce the requested seal — asked for format {:?}, mode {:?}, \
                 level {:?}, envelope {:?}; backend advertises formats {:?}, modes {:?}, \
                 levels {:?}, envelopes {:?}. Set SEAL_CONFORMANCE_LEVEL to a level this \
                 backend supports, or have the provider enable the one you want.",
                req.sig_format,
                req.mode,
                req.conformance_level,
                req.envelope,
                caps.supported_formats,
                caps.supported_modes,
                caps.supported_levels,
                caps.supported_envelopes,
            ))
            .into());
        }
        self.backend.seal(req).await.map_err(DppError::from)
    }

    async fn verify(&self, env: &SealedEnvelope) -> Result<SealVerification, DppError> {
        self.backend.verify(env).await.map_err(DppError::from)
    }

    fn capabilities(&self) -> SealCapabilities {
        self.backend.capabilities()
    }
}

#[cfg(test)]
#[path = "adapter_tests.rs"]
mod tests;
