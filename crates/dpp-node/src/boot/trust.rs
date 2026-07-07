//! Ghost-honesty invariant: collect each trust port's resolved tier, log it,
//! export gauges, and — in a production profile — refuse to boot on
//! placeholder trust. List-driven so a new port inherits the invariant for
//! free (see `dpp_types::trust`'s module doc for the one failure mode of that:
//! a port that's never added to the list is invisible to the guard).

use std::sync::Arc;

use dpp_common::event_codes;
use dpp_types::trust::{NodeProfile, NodeTrustReport, TrustMode, TrustPort};

/// Build the node's trust report from each port's resolved tier and enforce
/// the deployment profile. The seal port is not yet wired, so it always
/// resolves to Ghost for now: a production node cannot boot until a real
/// QTSP seal exists, which is the honest posture.
pub fn build_and_enforce(
    registry_trust: TrustMode,
    archive_trust: TrustMode,
) -> anyhow::Result<Arc<NodeTrustReport>> {
    let trust = Arc::new(NodeTrustReport::new(
        NodeProfile::from_env(),
        vec![
            TrustPort {
                port: "seal",
                mode: TrustMode::Ghost,
                required: true,
            },
            TrustPort {
                port: "registry_sync",
                mode: registry_trust,
                required: true,
            },
            TrustPort {
                port: "archive",
                mode: archive_trust,
                required: false,
            },
        ],
    ));
    for p in &trust.ports {
        tracing::info!(
            port = p.port,
            mode = p.mode.as_str(),
            required = p.required,
            "trust mode"
        );
        metrics::gauge!("trust_mode", "port" => p.port).set(p.mode.gauge_value());
    }
    if let Err(msg) = trust.enforce_profile() {
        tracing::error!(
            code = event_codes::TRUST_GHOST_BOOT_REFUSED,
            %msg,
            "production profile refuses placeholder trust"
        );
        anyhow::bail!(msg);
    }
    Ok(trust)
}
