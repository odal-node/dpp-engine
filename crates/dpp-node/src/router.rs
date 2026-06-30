//! Top-level Axum router for the `dpp-node` single binary.

use axum::{Router, extract::DefaultBodyLimit, middleware, routing::get};
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
        .route("/health", get(health))
        .nest("/vault", vault_router)
        .nest("/identity", identity_router)
        .nest("/integrator", integrator_router)
        .layer(DefaultBodyLimit::max(NODE_BODY_LIMIT))
        .layer(TraceLayer::new_for_http())
        .layer(middleware::from_fn(http_metrics_middleware))
        .layer(middleware::from_fn(inject_request_id))
        .layer(PropagateRequestIdLayer::x_request_id())
        .layer(SetRequestIdLayer::x_request_id(UuidRequestId))
        // N-6: turn any handler panic into a clean 500 instead of a dropped
        // connection. The node fuses vault + identity + integrator in one
        // process, so a panic-to-500 net is worth the outermost layer.
        .layer(CatchPanicLayer::new())
}

async fn health() -> &'static str {
    "ok"
}
