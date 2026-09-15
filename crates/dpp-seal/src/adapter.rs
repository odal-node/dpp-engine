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
mod tests {
    use super::*;
    use crate::ghost::GhostSeal;
    use dpp_domain::seal::{
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
            format: dpp_domain::seal::SealFormat::Cades,
            seal_value: "p7s".into(),
            signing_cert_ref: None,
            // Not recorded: this fixture asserts nothing about the level.
            conformance_level: None,
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
                    // Not recorded: this fixture asserts nothing about the level.
                    conformance_level: None,
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

    /// The whole `SealPort` contract, run against a real backend.
    ///
    /// `dpp-domain` defines the rules and ships the kit that checks them;
    /// nothing asserted that this crate — its only real implementor — obeyed
    /// them, and a contract with one implementor that ignores it reads as a
    /// guarantee while being none. The kit covers refusing what is not
    /// advertised, returning the format that was asked for rather than
    /// substituting one, and verdict coherence: no pass founded on nothing
    /// checked, and no placeholder counted as a qualified pass.
    ///
    /// Run against the local development sealer deliberately. The kit calls
    /// `seal` once per advertised pair, which against a live QTSP would spend
    /// real money — and this backend produces genuine CAdES bytes, so the rules
    /// are exercised rather than simulated.
    #[tokio::test]
    async fn the_adapter_satisfies_the_seal_port_conformance_kit() {
        let dir = tempfile::tempdir().expect("tempdir");
        let backend = crate::local::LocalIdentity::load_or_create(dir.path()).expect("identity");
        let adapter = QtspSealAdapter::new(backend);

        let report = dpp_domain::ports::seal::conformance::check_seal_port(&adapter).await;

        assert!(
            report.is_conformant(),
            "QtspSealAdapter must satisfy the SealPort contract:\n{report}"
        );
        assert!(
            report.combinations_checked > 0,
            "a kit run that exercised no combination proves nothing"
        );
        // This backend now advertises every baseline level, including ones that
        // outlive the signing certificate, so the kit no longer notes that its
        // seals expire with it. That note was about *levels*, and the levels
        // genuinely changed.
        //
        // What did **not** change is the only thing that ever mattered about
        // these seals, so it is pinned here instead. A structurally complete
        // `B-LTA` envelope signed by a key this node generated for itself is
        // still worth nothing: the verdict is founded on
        // `SealChecks::SignatureOnly` and is not a qualified pass. An `LTA` that
        // ever started reading as a qualified one would be this change's failure
        // mode, and this is where it would be caught.
        let sealed = adapter
            .seal(SealRequest {
                payload_hash: "ab".repeat(32),
                mode: SealMode::OperatorSeal,
                key_ref: SealCredentialRef {
                    qtsp_id: "local".into(),
                    credential_id: "node".into(),
                },
                sig_format: SealFormat::Cades,
                conformance_level: SealConformanceLevel::BaselineLta,
                envelope: SealEnvelope::Detached,
            })
            .await
            .expect("the local backend seals at LTA");

        let verdict = adapter.verify(&sealed).await.expect("verifiable");
        assert_eq!(verdict.checks, dpp_domain::seal::SealChecks::SignatureOnly);
        assert!(
            !verdict.is_qualified_pass(),
            "a locally signed LTA envelope is structurally complete and legally nothing"
        );
        assert_eq!(
            dpp_seal_level(&sealed),
            Some(SealConformanceLevel::BaselineLta),
            "and the bytes must actually carry the LTA material, or the level is a claim"
        );
    }

    /// The level the seal's own bytes evidence.
    fn dpp_seal_level(env: &SealedEnvelope) -> Option<SealConformanceLevel> {
        use base64::Engine as _;
        let der = base64::engine::general_purpose::STANDARD
            .decode(&env.seal_value)
            .expect("base64");
        crate::cades::evidenced_level(&der).expect("readable")
    }
}
