//! Top-level Axum router for the `dpp-node` single binary.

use axum::{Router, extract::DefaultBodyLimit, middleware, response::Json, routing::get};
use tower_http::{
    catch_panic::CatchPanicLayer,
    request_id::{PropagateRequestIdLayer, SetRequestIdLayer},
    trace::TraceLayer,
};

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
) -> Router {
    let vault_router = dpp_vault::router::build(vault_state);
    // Public-only identity routes (did:web document + health). The internal
    // signing/rotation endpoints are deliberately NOT mounted on the node — the
    // vault signs in-process, so there is no network-reachable signing surface.
    let identity_router = dpp_identity_service::router::build_public(identity_state);
    let integrator_router = dpp_integrator::router::build(integrator_state);

    Router::new()
        .route("/health", get(|| async { node_health() }))
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

/// Node liveness. Unauthenticated, so it answers only whether the process is
/// up.
///
/// It used to also return the deployment profile, every trust port's mode, and
/// the active ruleset version. The ghost-honesty signal those carry is worth
/// keeping — no surface may present a placeholder as real — but this endpoint
/// normally sits behind a public reverse proxy so an external monitor can probe
/// it, which made all of it readable by anyone who knew the host name. Which
/// trust ports are degraded and in what way is a targeting signal, and a stale
/// ruleset version says which validation rules a node is running.
///
/// So the honesty moved rather than went away: the profile, trust modes and
/// ruleset version are on the authenticated `/vault/api/v1/node/state`. This
/// sits alongside `/metrics`, which is off the public router for the same
/// reason.
pub fn node_health() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "ok" }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The public probe answers liveness and nothing else.
    ///
    /// This used to assert the opposite — that `/health` surfaced the profile,
    /// every trust port's mode and the ruleset version. Those fields moved to
    /// the authenticated `/vault/api/v1/node/state`; the assertions below are
    /// the regression guard that they do not drift back onto an endpoint
    /// anyone can reach.
    #[test]
    fn public_health_reports_liveness_only() {
        let Json(body) = node_health();

        assert_eq!(body["status"], "ok");
        for leaked in ["profile", "trust_mode", "ruleset"] {
            assert!(
                body.get(leaked).is_none(),
                "`{leaked}` must not be readable without authentication"
            );
        }
        assert_eq!(
            body.as_object().map(serde_json::Map::len),
            Some(1),
            "only `status` belongs on the unauthenticated probe"
        );
    }
}
