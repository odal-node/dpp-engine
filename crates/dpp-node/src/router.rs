//! Top-level Axum router for the `dpp-node` single binary.

use std::sync::Arc;

use axum::{Router, extract::DefaultBodyLimit, middleware, response::Json, routing::get};
use tower_http::{
    catch_panic::CatchPanicLayer,
    request_id::{PropagateRequestIdLayer, SetRequestIdLayer},
    trace::TraceLayer,
};

use crate::infra::ruleset::ActiveRuleset;
use dpp_types::trust::NodeTrustReport;

/// Node-global request body cap (8 MiB). Generous enough for the largest
/// legitimate body (the integrator's 5 MiB bulk import, which keeps its own
/// tighter per-route limit) while bounding raw-body abuse on every other route.
const NODE_BODY_LIMIT: usize = 8 * 1024 * 1024;

use dpp_common::{
    metrics::http_metrics_middleware,
    request_id::{UuidRequestId, inject_request_id},
};
use dpp_identity_service::state::AppState as IdentityState;
use dpp_integrator::state::AppState as IntegratorState;
use dpp_vault::state::AppState as VaultState;

/// Assemble the top-level node router by nesting each service's router.
///
/// Route prefixes:
/// - `/vault`      — DPP write engine (create, update, publish, archive)
/// - `/identity`   — did:web identity management and signing
/// - `/integrator` — CSV/Excel inbound adapter
///
/// The bridge crate is library-only (no HTTP surface); it provides
/// cross-service helpers consumed by the vault and integrator handlers.
pub fn build(
    vault_state: VaultState,
    identity_state: IdentityState,
    integrator_state: IntegratorState,
    trust: Arc<NodeTrustReport>,
    active_ruleset: Arc<ActiveRuleset>,
) -> Router {
    let vault_router = dpp_vault::router::build(vault_state);
    // Public-only identity routes (did:web document + health). The internal
    // signing/rotation endpoints are deliberately NOT mounted on the node — the
    // vault signs in-process, so there is no network-reachable signing surface.
    let identity_router = dpp_identity_service::router::build_public(identity_state);
    let integrator_router = dpp_integrator::router::build(integrator_state);

    Router::new()
        .route(
            "/health",
            get(move || {
                let trust = trust.clone();
                let ruleset = active_ruleset.clone();
                async move { node_health(&trust, &ruleset) }
            }),
        )
        .nest("/vault", vault_router)
        .nest("/identity", identity_router)
        .nest("/integrator", integrator_router)
        .layer(DefaultBodyLimit::max(NODE_BODY_LIMIT))
        .layer(TraceLayer::new_for_http())
        .layer(middleware::from_fn(http_metrics_middleware))
        .layer(middleware::from_fn(inject_request_id))
        .layer(PropagateRequestIdLayer::x_request_id())
        .layer(SetRequestIdLayer::x_request_id(UuidRequestId))
        // Turn any handler panic into a clean 500 instead of a dropped
        // connection. The node fuses vault + identity + integrator in one
        // process, so a panic-to-500 net is worth the outermost layer.
        .layer(CatchPanicLayer::new())
}

/// Node health with the ghost-honesty trust report and the active
/// Compliance Current ruleset version, so no surface can present a
/// placeholder as real and the ruleset a passport was validated against is
/// observable ("provably more current than a fork").
pub fn node_health(
    trust: &NodeTrustReport,
    active_ruleset: &ActiveRuleset,
) -> Json<serde_json::Value> {
    let mut body = serde_json::json!({
        "status": "ok",
        "ruleset": { "version": active_ruleset.version() },
    });
    if let serde_json::Value::Object(map) = &mut body
        && let serde_json::Value::Object(t) = trust.health_json()
    {
        map.extend(t);
    }
    Json(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use dpp_types::trust::{NodeProfile, NodeTrustReport, TrustMode, TrustPort};

    #[test]
    fn node_health_surfaces_trust_modes() {
        let report = NodeTrustReport::new(
            NodeProfile::Development,
            vec![
                TrustPort {
                    port: "seal",
                    mode: TrustMode::Ghost,
                    required: true,
                },
                TrustPort {
                    port: "registry_sync",
                    mode: TrustMode::Sandbox,
                    required: true,
                },
            ],
        );
        let ruleset = ActiveRuleset::baseline();
        let Json(body) = node_health(&report, &ruleset);
        assert_eq!(body["status"], "ok");
        assert_eq!(body["profile"], "development");
        assert_eq!(body["trust_mode"]["seal"], "ghost");
        assert_eq!(body["trust_mode"]["registry_sync"], "sandbox");
        assert_eq!(body["ruleset"]["version"], "baseline");
    }
}
