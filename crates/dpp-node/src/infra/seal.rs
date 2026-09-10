//! Selects the eIDAS qualified-seal backend from the environment.
//!
//! The composition root for sealing, in the same place every other adapter's
//! lives — `s3_archive`, `snapshot_store` and `credential_issuers` all resolve
//! themselves here rather than in `main`, so the binary asks for a port and does
//! not learn how any of them are built.
//!
//! # Configuration
//!
//! | Variable                  | Values                   | Meaning                          |
//! |---------------------------|--------------------------|----------------------------------|
//! | `SEAL_PROVIDER`           | unset / `qtsp` / `local` | Which backend to build           |
//! | `SEAL_CONFORMANCE_LEVEL`  | `B` / `T` / `LT` / `LTA` | Baseline level to request (`LT`) |
//!
//! Each backend then reads its own variables — see `dpp_seal::eideasy::config`
//! and `dpp_seal::local::config`. A partial or unrecognised configuration is an
//! error rather than a silent ghost: dropping to no sealing because one variable
//! was misspelled is exactly the downgrade the trust report exists to prevent,
//! so it fails the boot.
//!
//! There is deliberately **no** variable for the seal *mode*. It states whose
//! attestation the seal is, which is a fact about the backend rather than a
//! preference, so it is read off the backend's advertised capabilities — see
//! [`SealWiring::mode`]. A node that would enqueue seal rows its backend cannot
//! produce refuses to boot instead; see [`ensure_drainable`].

use std::sync::Arc;

use anyhow::{Context, Result};
use dpp_domain::{
    ports::seal::SealPort,
    seal::{
        SealCapabilities, SealConformanceLevel, SealCredentialRef, SealEnvelope, SealFormat,
        SealMode, SealRequest,
    },
};
use dpp_types::trust::TrustMode;

/// A selected seal backend, and the three facts about it the node needs.
///
/// A struct rather than the 4-tuple this replaces: `(port, ref, mode, bool)` is
/// two fields past the point where positional returns stay readable at the call
/// site, and the last two are both "about trust" without being interchangeable.
pub struct SealWiring {
    /// The port the drain seals through.
    pub port: Arc<dyn SealPort>,
    /// Which credential the backend signs with.
    ///
    /// Travels from here rather than being named in the drain: this is the only
    /// place that knows which backend was selected, and each backend supplies
    /// its own name through the constant the selector already matches on — so
    /// the two can never disagree.
    pub credential: SealCredentialRef,
    /// **Legal** standing — decides whether a profile will boot.
    pub trust: TrustMode,
    /// **Mechanical** — whether the backend emits an envelope worth draining.
    ///
    /// Deliberately not the same question as [`Self::trust`], and not derivable
    /// from it. A locally signed seal answers yes here while answering `Ghost`
    /// there. Collapsing the two either strands the local backend unexercised or
    /// lets a self-signed certificate satisfy a production boot.
    pub drains: bool,
    /// The baseline level every seal request asks for.
    ///
    /// Travels from here for the same reason as [`Self::credential`]: the drain
    /// is provider-agnostic, and the level a deployment can actually obtain is a
    /// property of its provider arrangement, not of the drain loop.
    ///
    /// Defaults to `B-LT` — the first level that stays verifiable after the
    /// signing certificate expires, and therefore the first that suits a
    /// passport, whose retention lock is permanent.
    ///
    /// **Enforced, not just declared.** `QtspSealAdapter` checks the request
    /// against the backend's advertised `SealCapabilities` before dispatching, so
    /// a backend not enabled for this level refuses rather than returning
    /// whatever it happened to produce. That refusal is deliberate and it bites:
    /// the local development sealer advertises `BaselineB` only, so a node
    /// running `SEAL_PROVIDER=local` at this default will not seal until
    /// `SEAL_CONFORMANCE_LEVEL=B` is set. A self-signed dev seal that cannot
    /// outlive its own certificate is exactly what should not silently satisfy a
    /// request for one that can.
    pub conformance_level: SealConformanceLevel,
    /// **Whose** attestation the seal is — read off what the backend advertises,
    /// never chosen here.
    ///
    /// `SealMode` is not a preference. `ProviderSeal` says a qualified provider
    /// holds the key and attests on the operator's behalf; `OperatorSeal` says
    /// the operator's own certificate signed it. Asking a backend for the mode
    /// it does not implement names an attestation nobody made, which is why the
    /// adapter refuses rather than substituting — core's `SealPort` states the
    /// rule: "the mode decides *whose* attestation the seal is."
    ///
    /// This travelled as a literal `ProviderSeal` in the drain loop, which only
    /// the QTSP backend advertises. Every request built for the local
    /// development sealer was therefore refused, retried eight times and
    /// exhausted: `SEAL_PROVIDER=local` could not produce a seal under any
    /// configuration. Deriving it from the backend is the only form that can be
    /// true for both.
    pub mode: SealMode,
}

/// The mode to request from a backend, read off what it advertises.
///
/// Preference order matters only for a backend advertising both, and the only
/// one that does is the ghost — whose `drains` is false, so nothing it returns
/// is ever requested. `ProviderSeal` wins there because it is the stronger
/// claim, and a backend advertising it is asserting it can back it.
fn mode_for(caps: &SealCapabilities) -> Result<SealMode> {
    [SealMode::ProviderSeal, SealMode::OperatorSeal]
        .into_iter()
        .find(|m| caps.supported_modes.contains(m))
        .ok_or_else(|| {
            anyhow::anyhow!(
                "the configured seal backend advertises no seal mode this node can request \
                 (it advertises {:?})",
                caps.supported_modes
            )
        })
}

/// Refuse to boot a node that would enqueue seal rows it can never drain.
///
/// Publish enqueues a row whenever `drains` is true; the drain then builds one
/// fixed request shape per row. If the backend cannot produce that shape, every
/// row fails identically, backs off through eight attempts and exhausts —
/// leaving published passports permanently unsealed while
/// `GET /vault/api/v1/seal` reports `sealingConfigured: true` throughout. The
/// only operator-visible signal today is `exhausted` climbing hours later.
///
/// Every input to that decision exists at boot, so the mismatch is knowable
/// before a single passport is published. Checking it here converts hours of
/// silence into a refusal naming the axis and the remedy.
///
/// Deliberately gated on `drains`: a node with sealing off enqueues nothing and
/// has nothing to be wrong about.
fn ensure_drainable(w: &SealWiring) -> Result<()> {
    if !w.drains {
        return Ok(());
    }
    let caps = w.port.capabilities();
    let probe = SealRequest {
        // Any well-formed digest: `can_produce` inspects the shape, not the
        // payload.
        payload_hash: "00".repeat(32),
        mode: w.mode.clone(),
        key_ref: w.credential.clone(),
        sig_format: SealFormat::Cades,
        conformance_level: w.conformance_level,
        envelope: SealEnvelope::Detached,
    };
    if caps.can_produce(&probe) {
        return Ok(());
    }
    // Name the axis that actually fails. The adapter's runtime error listed all
    // four and told the reader to change `SEAL_CONFORMANCE_LEVEL`, which is
    // wrong guidance whenever the level is not the mismatching one — it cost a
    // restart chasing the wrong variable.
    let mut wrong: Vec<String> = Vec::new();
    if !caps.supported_modes.contains(&probe.mode) {
        wrong.push(format!(
            "mode {:?} (backend advertises {:?}) — not settable; it is a property of the backend",
            probe.mode, caps.supported_modes
        ));
    }
    if !caps.supported_levels.contains(&probe.conformance_level) {
        wrong.push(format!(
            "level {:?} (backend advertises {:?}) — set SEAL_CONFORMANCE_LEVEL to one of those",
            probe.conformance_level, caps.supported_levels
        ));
    }
    if !caps.supported_formats.contains(&probe.sig_format) {
        wrong.push(format!(
            "format {:?} (backend advertises {:?})",
            probe.sig_format, caps.supported_formats
        ));
    }
    if !caps.supported_envelopes.contains(&probe.envelope) {
        wrong.push(format!(
            "envelope {:?} (backend advertises {:?})",
            probe.envelope, caps.supported_envelopes
        ));
    }
    anyhow::bail!(
        "the configured seal backend cannot produce the seal this node would request, so every \
         published passport would enqueue a row that can never drain. Mismatched: {}",
        wrong.join("; ")
    )
}

/// Read `SEAL_CONFORMANCE_LEVEL`, defaulting to `B-LT`.
///
/// An unrecognised value fails the boot rather than falling back to the default,
/// which would let a deployment that asked for `B-LTA` and misspelled it seal at
/// a lower level than it believes it is sealing at.
fn conformance_level_from_env() -> Result<SealConformanceLevel> {
    let Ok(raw) = std::env::var("SEAL_CONFORMANCE_LEVEL") else {
        return Ok(SealConformanceLevel::BaselineLt);
    };
    match raw.trim().to_ascii_uppercase().as_str() {
        "B" | "B-B" | "BASELINE_B" => Ok(SealConformanceLevel::BaselineB),
        "T" | "B-T" | "BASELINE_T" => Ok(SealConformanceLevel::BaselineT),
        "LT" | "B-LT" | "BASELINE_LT" => Ok(SealConformanceLevel::BaselineLt),
        "LTA" | "B-LTA" | "BASELINE_LTA" => Ok(SealConformanceLevel::BaselineLta),
        other => anyhow::bail!(
            "SEAL_CONFORMANCE_LEVEL '{other}' is not a baseline level \
             (expected one of B, T, LT, LTA)"
        ),
    }
}

/// Build the seal backend named by `SEAL_PROVIDER`.
///
/// # Errors
/// Propagates a backend's own configuration error, and an unrecognised
/// `SEAL_PROVIDER` value. Both fail the boot rather than degrading to a ghost.
pub fn from_env() -> Result<SealWiring> {
    let wiring = wiring_from_env()?;
    ensure_drainable(&wiring)?;
    Ok(wiring)
}

fn wiring_from_env() -> Result<SealWiring> {
    let conformance_level = conformance_level_from_env()?;
    match dpp_seal::SealProvider::from_env().context("seal provider")? {
        dpp_seal::SealProvider::Qtsp => {
            let cfg =
                dpp_seal::eideasy::EideasyConfig::from_env().context("QTSP seal configuration")?;
            // Sandbox is a real seal from a real API, but over the provider's
            // test certificate — a distinct claim from both Ghost and Live.
            let trust = match cfg.environment {
                dpp_seal::eideasy::EideasyEnvironment::Sandbox => TrustMode::Sandbox,
                dpp_seal::eideasy::EideasyEnvironment::Production => TrustMode::Live,
            };
            let credential = SealCredentialRef {
                qtsp_id: dpp_seal::eideasy::config::PROVIDER.to_owned(),
                credential_id: cfg.client_id.clone(),
            };
            tracing::info!(
                base_url = %cfg.base_url,
                mode = trust.as_str(),
                "eIDAS seal: QTSP adapter active"
            );
            let backend = dpp_seal::eideasy::EideasyClient::new(cfg)
                .context("Failed to build the QTSP seal adapter")?;
            let port: Arc<dyn SealPort> = Arc::new(dpp_seal::QtspSealAdapter::new(backend));
            let mode = mode_for(&port.capabilities())?;
            Ok(SealWiring {
                port,
                credential,
                trust,
                drains: true,
                conformance_level,
                mode,
            })
        }
        dpp_seal::SealProvider::Local => {
            let cfg =
                dpp_seal::local::LocalConfig::from_env().context("local seal configuration")?;
            let backend = dpp_seal::local::LocalIdentity::load_or_create(&cfg.key_path)
                .context("Failed to build the local seal adapter")?;
            tracing::warn!(
                key_path = %cfg.key_path.display(),
                "eIDAS seal: LOCAL development backend — a real CMS signature under a \
                 self-signed certificate, on no EU Trusted List and of no legal weight"
            );
            let port: Arc<dyn SealPort> = Arc::new(dpp_seal::QtspSealAdapter::new(backend));
            let mode = mode_for(&port.capabilities())?;
            Ok(SealWiring {
                port,
                credential: SealCredentialRef {
                    qtsp_id: dpp_seal::local::config::PROVIDER.to_owned(),
                    // No credential to reference: the key is this node's own.
                    credential_id: String::new(),
                },
                // Ghost as a trust tier, because no authority stands behind a
                // self-signed certificate — so a sandbox or production profile
                // refuses to boot on it. But the envelope is real, so it drains.
                trust: TrustMode::Ghost,
                drains: true,
                conformance_level,
                mode,
            })
        }
        dpp_seal::SealProvider::None => {
            tracing::info!("eIDAS seal: ghost (no provider) — set SEAL_PROVIDER to enable sealing");
            let port: Arc<dyn SealPort> =
                Arc::new(dpp_seal::QtspSealAdapter::new(dpp_seal::ghost::GhostSeal));
            let mode = mode_for(&port.capabilities())?;
            Ok(SealWiring {
                port,
                // Never used: `drains` is false, so no drain is spawned and
                // nothing builds a request from this.
                credential: SealCredentialRef {
                    qtsp_id: String::new(),
                    credential_id: String::new(),
                },
                trust: TrustMode::Ghost,
                drains: false,
                conformance_level,
                mode,
            })
        }
    }
}

#[cfg(test)]
mod seal_mode_and_drainability {
    use super::*;
    use async_trait::async_trait;
    use dpp_domain::{
        DppError,
        seal::{SealVerification, SealedEnvelope},
    };

    fn caps(modes: Vec<SealMode>, levels: Vec<SealConformanceLevel>) -> SealCapabilities {
        SealCapabilities {
            supported_formats: vec![SealFormat::Cades],
            supported_modes: modes,
            supported_levels: levels,
            supported_envelopes: vec![SealEnvelope::Detached],
        }
    }

    struct Backend(SealCapabilities);

    #[async_trait]
    impl SealPort for Backend {
        async fn seal(&self, _r: SealRequest) -> Result<SealedEnvelope, DppError> {
            unreachable!("capabilities are all these tests read")
        }
        async fn verify(&self, _e: &SealedEnvelope) -> Result<SealVerification, DppError> {
            unreachable!("capabilities are all these tests read")
        }
        fn capabilities(&self) -> SealCapabilities {
            self.0.clone()
        }
    }

    fn wiring(c: SealCapabilities, level: SealConformanceLevel, drains: bool) -> SealWiring {
        let mode = mode_for(&c).expect("a mode");
        SealWiring {
            port: Arc::new(Backend(c)),
            credential: SealCredentialRef {
                qtsp_id: "test".into(),
                credential_id: String::new(),
            },
            trust: TrustMode::Ghost,
            drains,
            conformance_level: level,
            mode,
        }
    }

    /// THE regression. The local development sealer signs under the operator's
    /// own certificate and advertises `OperatorSeal` only. The drain used to
    /// name `ProviderSeal` unconditionally, so every request built for it was
    /// refused, retried eight times and exhausted — `SEAL_PROVIDER=local` could
    /// not produce one seal under any configuration.
    #[test]
    fn a_backend_that_signs_under_its_own_certificate_is_asked_for_an_operator_seal() {
        let m = mode_for(&caps(
            vec![SealMode::OperatorSeal],
            vec![SealConformanceLevel::BaselineB],
        ))
        .expect("a mode");
        assert_eq!(m, SealMode::OperatorSeal);
    }

    /// And the QTSP backend must still be asked for the provider's attestation —
    /// the fix must not swing the other way.
    #[test]
    fn a_provider_held_backend_is_asked_for_a_provider_seal() {
        let m = mode_for(&caps(
            vec![SealMode::ProviderSeal],
            vec![SealConformanceLevel::BaselineLt],
        ))
        .expect("a mode");
        assert_eq!(m, SealMode::ProviderSeal);
    }

    #[test]
    fn a_backend_advertising_no_mode_is_refused_rather_than_defaulted() {
        assert!(mode_for(&caps(vec![], vec![SealConformanceLevel::BaselineB])).is_err());
    }

    /// The local backend's real shape: operator seal, `BaselineB` only. With the
    /// mode derived, this is drainable — which is the whole point.
    #[test]
    fn the_local_backends_shape_is_drainable_at_baseline_b() {
        let w = wiring(
            caps(
                vec![SealMode::OperatorSeal],
                vec![SealConformanceLevel::BaselineB],
            ),
            SealConformanceLevel::BaselineB,
            true,
        );
        assert!(ensure_drainable(&w).is_ok());
    }

    /// The level default (`B-LT`) against that same backend must fail the boot
    /// rather than enqueueing rows that exhaust hours later, and must name the
    /// variable that fixes it.
    #[test]
    fn a_level_the_backend_cannot_reach_fails_the_boot_and_names_the_remedy() {
        let w = wiring(
            caps(
                vec![SealMode::OperatorSeal],
                vec![SealConformanceLevel::BaselineB],
            ),
            SealConformanceLevel::BaselineLt,
            true,
        );
        let err = ensure_drainable(&w).expect_err("must refuse").to_string();
        assert!(err.contains("SEAL_CONFORMANCE_LEVEL"), "{err}");
        assert!(err.contains("BaselineLt"), "{err}");
    }

    /// A node with sealing off enqueues nothing, so it has nothing to be wrong
    /// about — the check must not strand it on a backend it never calls.
    #[test]
    fn a_node_that_does_not_seal_is_not_checked() {
        let w = wiring(
            caps(
                vec![SealMode::OperatorSeal],
                vec![SealConformanceLevel::BaselineB],
            ),
            SealConformanceLevel::BaselineLta,
            false,
        );
        assert!(ensure_drainable(&w).is_ok());
    }
}
