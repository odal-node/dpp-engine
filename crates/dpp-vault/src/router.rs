//! Axum router for the vault service — wires routes, middleware, and CORS.

use axum::{
    Router,
    http::{HeaderValue, Method, header},
    middleware,
    routing::{delete, get, post},
};
use tower_http::{
    cors::CorsLayer,
    request_id::{PropagateRequestIdLayer, SetRequestIdLayer},
    trace::TraceLayer,
};

use dpp_common::{
    metrics::http_metrics_middleware,
    request_id::{UuidRequestId, inject_request_id},
};

use crate::{
    handlers::{
        api_keys::{api_keys_create_handler, api_keys_delete_handler, api_keys_list_handler},
        archive::archive_handler,
        create::create_handler,
        health::{health_handler, ready_handler},
        history::history_handler,
        info::info_handler,
        list::list_handler,
        node_state::node_state_handler,
        operator::{operator_get_handler, operator_patch_handler},
        public_read::public_read_handler,
        public_read_by_gtin::public_read_by_gtin_handler,
        publish::publish_handler,
        read::read_handler,
        registry_identity::{
            facilities_create_handler, facilities_delete_handler, facilities_list_handler,
            facilities_set_default_handler, operator_ids_create_handler,
            operator_ids_delete_handler, operator_ids_list_handler,
            operator_ids_set_primary_handler,
        },
        suspend::suspend_handler,
        update::update_handler,
    },
    middleware::auth::auth_middleware,
    state::AppState,
};

/// Build the Axum router with all vault routes, auth middleware, CORS, and telemetry layers.
///
/// Public routes (`/health`, `/ready`, `/api/v1/info`, `/public/dpp/*`) are
/// unauthenticated. All `/api/v1/*` routes are wrapped in [`auth_middleware`].
pub fn build(state: AppState) -> Router {
    let authenticated = Router::new()
        // ── DPP CRUD ──────────────────────────────────────────────────
        .route("/dpp", post(create_handler))
        .route("/dpps", get(list_handler))
        .route("/dpp/{dppId}", get(read_handler).put(update_handler))
        .route("/dpp/{dppId}/publish", post(publish_handler))
        .route("/dpp/{dppId}/suspend", post(suspend_handler))
        .route("/dpp/{dppId}/archive", post(archive_handler))
        .route("/dpp/{dppId}/history", get(history_handler))
        // ── Node setup state ──────────────────────────────────────────
        .route("/node/state", get(node_state_handler))
        // ── Operator config ───────────────────────────────────────────
        .route(
            "/operator",
            get(operator_get_handler).patch(operator_patch_handler),
        )
        // ── API keys ──────────────────────────────────────────────────
        .route(
            "/api-keys",
            get(api_keys_list_handler).post(api_keys_create_handler),
        )
        .route("/api-keys/{id}", delete(api_keys_delete_handler))
        // ── Facilities (Annex III) ────────────────────────────────────
        .route(
            "/facilities",
            get(facilities_list_handler).post(facilities_create_handler),
        )
        .route("/facilities/{id}", delete(facilities_delete_handler))
        .route(
            "/facilities/{id}/default",
            post(facilities_set_default_handler),
        )
        // ── Operator identifiers (Art. 13) ────────────────────────────
        .route(
            "/operator-identifiers",
            get(operator_ids_list_handler).post(operator_ids_create_handler),
        )
        .route(
            "/operator-identifiers/{id}",
            delete(operator_ids_delete_handler),
        )
        .route(
            "/operator-identifiers/{id}/primary",
            post(operator_ids_set_primary_handler),
        )
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ));

    let cors_layer = build_cors(&state.cors_allowed_origins);

    Router::new()
        .route("/health", get(health_handler))
        .route("/ready", get(ready_handler))
        .route("/api/v1/info", get(info_handler))
        .route("/public/dpp/{dppId}", get(public_read_handler))
        .route(
            "/public/dpp/by-gtin/{gtin}",
            get(public_read_by_gtin_handler),
        )
        .nest("/api/v1", authenticated)
        .layer(cors_layer)
        .layer(TraceLayer::new_for_http())
        .layer(middleware::from_fn(http_metrics_middleware))
        .layer(middleware::from_fn(inject_request_id))
        .layer(PropagateRequestIdLayer::x_request_id())
        .layer(SetRequestIdLayer::x_request_id(UuidRequestId))
        .with_state(state)
}

/// Build a `CorsLayer` from a list of allowed origins.
/// Returns a very permissive layer when the list is empty (CORS disabled).
fn build_cors(allowed_origins: &[String]) -> CorsLayer {
    if allowed_origins.is_empty() {
        // No origins configured — let the browser see a missing header, which
        // effectively blocks all cross-origin requests. Still need a layer so
        // OPTIONS pre-flights get a response rather than a 404.
        return CorsLayer::new();
    }

    let origins: Vec<HeaderValue> = allowed_origins
        .iter()
        .filter_map(|o| o.parse().ok())
        .collect();

    CorsLayer::new()
        .allow_origin(origins)
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE])
        .allow_credentials(true)
        .max_age(std::time::Duration::from_secs(86400))
}

#[cfg(test)]
mod tests {
    use super::build_cors;

    #[test]
    fn empty_origins_returns_minimal_layer() {
        // Should not panic; produces a layer that blocks cross-origin requests.
        let _layer = build_cors(&[]);
    }

    #[test]
    fn configured_origins_produce_layer() {
        let origins = vec![
            "https://app.odal-node.io".to_string(),
            "http://localhost:3000".to_string(),
        ];
        let _layer = build_cors(&origins);
    }

    #[test]
    fn unparseable_origin_is_silently_filtered() {
        // filter_map skips invalid header values; must not panic.
        let origins = vec!["not a valid origin !!!".to_string()];
        let _layer = build_cors(&origins);
    }
}
