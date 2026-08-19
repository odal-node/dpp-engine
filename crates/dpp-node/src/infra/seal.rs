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

use std::sync::Arc;

use anyhow::{Context, Result};
use dpp_domain::ports::seal::{SealConformanceLevel, SealCredentialRef, SealPort};
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
            Ok(SealWiring {
                port: Arc::new(dpp_seal::QtspSealAdapter::new(backend)),
                credential,
                trust,
                drains: true,
                conformance_level,
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
            Ok(SealWiring {
                port: Arc::new(dpp_seal::QtspSealAdapter::new(backend)),
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
            })
        }
        dpp_seal::SealProvider::None => {
            tracing::info!("eIDAS seal: ghost (no provider) — set SEAL_PROVIDER to enable sealing");
            Ok(SealWiring {
                port: Arc::new(dpp_seal::QtspSealAdapter::new(dpp_seal::ghost::GhostSeal)),
                // Never used: `drains` is false, so no drain is spawned and
                // nothing builds a request from this.
                credential: SealCredentialRef {
                    qtsp_id: String::new(),
                    credential_id: String::new(),
                },
                trust: TrustMode::Ghost,
                drains: false,
                conformance_level,
            })
        }
    }
}
