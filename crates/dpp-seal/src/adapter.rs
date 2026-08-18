//! `QtspSealAdapter` — the `SealPort` implementation.
//!
//! It holds one [`SealBackend`] and does nothing else: forward the port's three
//! calls, and collapse [`SealError`] into `DppError` at the boundary. Which
//! backend it holds is decided by [`crate::config`] and constructed by that
//! backend's own module, so nothing in this file names one — adding or removing
//! a backend leaves it untouched.

use async_trait::async_trait;
use dpp_domain::{
    domain::error::DppError,
    ports::seal::{SealCapabilities, SealPort, SealRequest, SealVerification, SealedEnvelope},
};

use crate::backend::SealBackend;

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
    async fn seal(&self, req: SealRequest) -> Result<SealedEnvelope, DppError> {
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
mod tests {
    use super::*;
    use crate::ghost::GhostSeal;

    #[test]
    fn unconfigured_reports_ghost_capabilities() {
        let caps = QtspSealAdapter::new(GhostSeal).capabilities();
        assert!(!caps.supported_formats.is_empty());
    }

    /// A backend that implements only what the trait requires must not verify.
    ///
    /// The default is what stops a new backend from silently inheriting a
    /// "valid" answer it never computed — so it is checked through the adapter,
    /// where the refusal has to survive the conversion to `DppError` to reach a
    /// caller at all.
    #[tokio::test]
    async fn a_backend_that_says_nothing_about_verify_refuses() {
        struct Minimal;

        #[async_trait]
        impl SealBackend for Minimal {
            async fn seal(&self, _req: SealRequest) -> Result<SealedEnvelope, crate::SealError> {
                unreachable!("this test never seals")
            }
            fn capabilities(&self) -> SealCapabilities {
                SealCapabilities {
                    supported_formats: Vec::new(),
                    supported_modes: Vec::new(),
                }
            }
        }

        let env = SealedEnvelope {
            format: dpp_domain::ports::seal::SealFormat::Cades,
            seal_value: "p7s".into(),
            signing_cert_ref: None,
            sealed_at: chrono::Utc::now(),
            placeholder: false,
        };
        let err = QtspSealAdapter::new(Minimal)
            .verify(&env)
            .await
            .expect_err("the default must refuse rather than answer");
        assert!(err.to_string().contains("not implemented"), "{err}");
    }
}
