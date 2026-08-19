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
mod tests {
    use super::*;
    use crate::ghost::GhostSeal;
    use dpp_domain::ports::seal::{
        SealConformanceLevel, SealCredentialRef, SealEnvelope, SealFormat, SealMode,
    };

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
                    supported_levels: Vec::new(),
                    supported_envelopes: Vec::new(),
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

    /// A request the backend does not advertise is refused *before* dispatch.
    ///
    /// The backend's `seal` is `unreachable!()`, so this only passes if the
    /// capability check runs first. That ordering is the whole point: every
    /// drained row is billable, and a call that was going to produce the wrong
    /// level should not be paid for to find that out.
    #[tokio::test]
    async fn a_seal_the_backend_cannot_produce_is_refused_before_dispatch() {
        struct OnlyBaselineB;

        #[async_trait]
        impl SealBackend for OnlyBaselineB {
            async fn seal(&self, _req: SealRequest) -> Result<SealedEnvelope, crate::SealError> {
                unreachable!("the capability check must refuse before reaching the backend")
            }
            fn capabilities(&self) -> SealCapabilities {
                SealCapabilities {
                    supported_formats: vec![SealFormat::Cades],
                    supported_modes: vec![SealMode::OperatorSeal],
                    supported_levels: vec![SealConformanceLevel::BaselineB],
                    supported_envelopes: vec![SealEnvelope::Detached],
                }
            }
        }

        let req = SealRequest {
            payload_hash: "00".repeat(32),
            mode: SealMode::OperatorSeal,
            key_ref: SealCredentialRef {
                qtsp_id: "test".into(),
                credential_id: "test".into(),
            },
            sig_format: SealFormat::Cades,
            // One level above what the backend advertises — the mismatch that
            // used to travel to the provider unremarked.
            conformance_level: SealConformanceLevel::BaselineLt,
            envelope: SealEnvelope::Detached,
        };

        let err = QtspSealAdapter::new(OnlyBaselineB)
            .seal(req)
            .await
            .expect_err("a level the backend does not advertise must be refused");
        let msg = err.to_string();
        assert!(
            msg.contains("BaselineLt") && msg.contains("BaselineB"),
            "the error must name both what was asked for and what is available: {msg}"
        );
        assert!(
            msg.contains("SEAL_CONFORMANCE_LEVEL"),
            "and must name the knob that resolves it: {msg}"
        );
    }

    /// The matching case: a request the backend does advertise still goes
    /// through. Without this, the check above could pass by refusing everything.
    #[tokio::test]
    async fn a_seal_the_backend_advertises_reaches_it() {
        struct Accepting;

        #[async_trait]
        impl SealBackend for Accepting {
            async fn seal(&self, _req: SealRequest) -> Result<SealedEnvelope, crate::SealError> {
                Ok(SealedEnvelope {
                    format: SealFormat::Cades,
                    seal_value: "p7s".into(),
                    signing_cert_ref: None,
                    sealed_at: chrono::Utc::now(),
                    placeholder: false,
                })
            }
            fn capabilities(&self) -> SealCapabilities {
                SealCapabilities {
                    supported_formats: vec![SealFormat::Cades],
                    supported_modes: vec![SealMode::OperatorSeal],
                    supported_levels: vec![SealConformanceLevel::BaselineLt],
                    supported_envelopes: vec![SealEnvelope::Detached],
                }
            }
        }

        let req = SealRequest {
            payload_hash: "00".repeat(32),
            mode: SealMode::OperatorSeal,
            key_ref: SealCredentialRef {
                qtsp_id: "test".into(),
                credential_id: "test".into(),
            },
            sig_format: SealFormat::Cades,
            conformance_level: SealConformanceLevel::BaselineLt,
            envelope: SealEnvelope::Detached,
        };

        QtspSealAdapter::new(Accepting)
            .seal(req)
            .await
            .expect("a request within the backend's capabilities must be served");
    }
}
