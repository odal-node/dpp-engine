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
        eol::eol_handler,
        evidence::{
            generate_evidence_handler, get_evidence_handler, list_evidence_handler,
            verify_document_handler, verify_evidence_handler,
        },
        find_by_identity::find_by_identity_handler,
        health::{health_handler, ready_handler},
        history::history_handler,
        info::info_handler,
        lint::lint_handler,
        list::list_handler,
        node_state::node_state_handler,
        operator::{operator_get_handler, operator_patch_handler},
        plugins::install_plugin_handler,
        public_read::public_read_handler,
        public_read_by_gtin::public_read_by_gtin_handler,
        publish::publish_handler,
        read::read_handler,
        registry_identity::{
            facilities_audit_handler, facilities_create_handler, facilities_delete_handler,
            facilities_list_handler, facilities_set_default_handler, operator_ids_audit_handler,
            operator_ids_create_handler, operator_ids_delete_handler, operator_ids_list_handler,
            operator_ids_set_primary_handler,
        },
        registry_status::{passport_registry_handler, registry_rollup_handler},
        ruleset::reload_ruleset_handler,
        scan_ingest::{scan_ingest_handler, scan_ingest_mtls},
        seal::{seal_handler, seal_summary_handler},
        stats::{operator_stats_handler, passport_stats_handler},
        suspend::suspend_handler,
        transfer::{
            transfer_accept_handler, transfer_cancel_handler, transfer_initiate_handler,
            transfer_reject_handler,
        },
        update::update_handler,
        validate::validate_handler,
        verify_tree::verify_tree_handler,
        webhooks::{
            webhooks_create_handler, webhooks_delete_handler, webhooks_list_handler,
            webhooks_test_handler,
        },
        whoami::whoami_handler,
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
        // Dry-run of the line above. It shares a prefix with `/dpp/{dppId}`;
        // axum gives a literal segment precedence over a parameter regardless
        // of registration order, so `validate` is never read as a passport id.
        // Asserted in `handlers::validate::tests`, because that precedence is
        // a routing-library property and not something to take on trust.
        .route("/dpp/validate", post(validate_handler))
        .route("/dpps", get(list_handler))
        .route("/dpp/by-identity", get(find_by_identity_handler))
        .route("/dpp/{dppId}", get(read_handler).put(update_handler))
        .route("/dpp/{dppId}/publish", post(publish_handler))
        .route("/dpp/{dppId}/lint", post(lint_handler))
        .route("/dpp/{dppId}/suspend", post(suspend_handler))
        .route("/dpp/{dppId}/archive", post(archive_handler))
        .route("/dpp/{dppId}/eol", post(eol_handler))
        .route(
            "/dpp/{dppId}/transfer/initiate",
            post(transfer_initiate_handler),
        )
        .route(
            "/dpp/{dppId}/transfer/accept",
            post(transfer_accept_handler),
        )
        // The two ways out of a pending handover. Without them a transfer the
        // counterparty never acted on blocks every later transfer on the
        // passport permanently — the chain refuses a new one while any record
        // is still pending, and nothing else can move a record out of that
        // state.
        .route(
            "/dpp/{dppId}/transfer/reject",
            post(transfer_reject_handler),
        )
        .route(
            "/dpp/{dppId}/transfer/cancel",
            post(transfer_cancel_handler),
        )
        .route("/dpp/{dppId}/history", get(history_handler))
        .route("/dpp/{dppId}/verify-tree", get(verify_tree_handler))
        // The qualified seal has its own route because it is stripped from
        // every audience view — it covers the full-payload signature, so it
        // verifies against no redaction.
        .route("/dpp/{dppId}/seal", get(seal_handler))
        // The operator-wide counterpart: the per-passport route cannot answer
        // "is anything unsealed" without already knowing which passport to ask.
        .route("/seal", get(seal_summary_handler))
        // ── Scan telemetry (aggregate, privacy-safe) ──────────────────
        .route("/dpp/{dppId}/stats", get(passport_stats_handler))
        .route("/stats", get(operator_stats_handler))
        .route("/dpp/{dppId}/registry", get(passport_registry_handler))
        .route("/registry", get(registry_rollup_handler))
        .route(
            "/dpp/{dppId}/evidence",
            get(list_evidence_handler).post(generate_evidence_handler),
        )
        .route("/evidence/verify", post(verify_document_handler))
        .route("/evidence/{id}", get(get_evidence_handler))
        .route("/evidence/{id}/verify", post(verify_evidence_handler))
        // ── Node setup state ──────────────────────────────────────────
        .route("/node/state", get(node_state_handler))
        // ── Caller identity ───────────────────────────────────────────
        // Any scope: it reports only what the caller already presented, and a
        // read-only key needs it precisely to learn that it is read-only.
        .route("/whoami", get(whoami_handler))
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
        // ── Plugins (signed product group-plugin hot-install) ────────────────
        .route("/plugins", post(install_plugin_handler))
        // ── Compliance Current (signed ruleset channel hot-reload) ──────────
        .route("/ruleset/reload", post(reload_ruleset_handler))
        // ── Webhooks (signed outbound delivery) ───────────────────────
        .route(
            "/webhooks",
            get(webhooks_list_handler).post(webhooks_create_handler),
        )
        .route("/webhooks/{id}", delete(webhooks_delete_handler))
        .route("/webhooks/{id}/test", post(webhooks_test_handler))
        // ── Facilities (Annex III) ────────────────────────────────────
        .route(
            "/facilities",
            get(facilities_list_handler).post(facilities_create_handler),
        )
        .route("/facilities/{id}", delete(facilities_delete_handler))
        .route("/facilities/{id}/audit", get(facilities_audit_handler))
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
            "/operator-identifiers/{id}/audit",
            get(operator_ids_audit_handler),
        )
        .route(
            "/operator-identifiers/{id}/primary",
            post(operator_ids_set_primary_handler),
        )
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ));

    // Internal service-to-service tree: not public, not Bearer-authenticated.
    // The resolver (which holds no operator API key) flushes scan telemetry here,
    // gated by client-certificate mTLS (`CN=odal-resolver`).
    let internal = Router::new()
        .route("/scan-batch", post(scan_ingest_handler))
        .route_layer(middleware::from_fn(scan_ingest_mtls));

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
        // Audience-scoped read. Deliberately outside `/public` (a public URL
        // whose body varies by caller breaks caching and the meaning of
        // `publicJwsSignature`) and outside `/api/v1` (API keys are the
        // operator's own machine access; a repairer holds a credential and no
        // key, and requiring one would gate lawful access behind a commercial
        // relationship).
        .route(
            "/credential/dpp/{dppId}",
            get(crate::handlers::audience_read::audience_read_handler),
        )
        .nest("/api/v1", authenticated)
        .nest("/internal", internal)
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
        // `X-DPP-Credential` is allow-listed because the readers this route
        // exists for — a repairer's portal, an authority's browser tool — are
        // cross-origin browser clients. Without it their preflight is refused
        // and the credential never reaches the node at all.
        .allow_headers([
            header::AUTHORIZATION,
            header::CONTENT_TYPE,
            crate::middleware::credential::credential_header_name(),
        ])
        .allow_credentials(true)
        .max_age(std::time::Duration::from_secs(86400))
}

#[cfg(test)]
mod tests {
    use super::build_cors;

    /// A browser client cannot send a header the preflight does not allow, so
    /// omitting `X-DPP-Credential` here would make the credential route
    /// unusable from exactly the readers it exists for — and it would fail
    /// silently, as a request that never arrives rather than one that is
    /// refused. Driven as a real preflight rather than by inspecting the layer,
    /// because what matters is the response header a browser actually sees.
    #[tokio::test]
    async fn preflight_allows_the_credential_header() {
        use axum::{Router, body::Body, http::Request, routing::get};
        use tower::ServiceExt as _;

        let app = Router::new()
            .route("/credential/dpp/{id}", get(|| async { "ok" }))
            .layer(super::build_cors(&["https://portal.example".to_owned()]));

        let resp = app
            .oneshot(
                Request::builder()
                    .method("OPTIONS")
                    .uri("/credential/dpp/x")
                    .header("origin", "https://portal.example")
                    .header("access-control-request-method", "GET")
                    .header("access-control-request-headers", "x-dpp-credential")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("preflight");

        let allowed = resp
            .headers()
            .get("access-control-allow-headers")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_ascii_lowercase();

        assert!(
            allowed.contains("x-dpp-credential"),
            "preflight did not allow the credential header; got {allowed:?}"
        );
    }

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
