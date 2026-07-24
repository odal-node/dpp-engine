//! Router for the public DPP resolver.

use axum::{
    Router,
    extract::{Path, Request, State},
    http::HeaderValue,
    middleware,
    response::IntoResponse,
    routing::get,
};
use tower_http::{
    request_id::{PropagateRequestIdLayer, SetRequestIdLayer},
    trace::TraceLayer,
};

use dpp_common::{
    metrics::http_metrics_middleware,
    request_id::{UuidRequestId, inject_request_id},
};

use crate::{
    handlers::{
        health::{health_handler, ready_handler},
        resolve_by_gtin::{
            resolve_by_gtin_batch_handler, resolve_by_gtin_batch_serial_handler,
            resolve_by_gtin_handler, resolve_by_gtin_serial_handler,
        },
        resolve_html::resolve_html_handler,
        resolve_json::resolve_json_handler,
        resolve_qr::resolve_qr_handler,
    },
    state::AppState,
};

/// Build the Axum router with all resolver routes and middleware layers.
///
/// Mounts health probes, content-negotiated DPP resolution, QR PNG generation,
/// and the GS1 Digital Link (`/01/{gtin}`) route. Attaches tracing, Prometheus
/// metrics, and `x-request-id` propagation.
pub fn build(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health_handler))
        .route("/ready", get(ready_handler))
        .route("/dpp/{dppId}", get(content_negotiation_handler))
        .route("/dpp/{dppId}/qr", get(resolve_qr_handler))
        // Every AI combination this node's carrier can print must resolve; all
        // of them key on the GTIN. See `handlers::resolve_by_gtin`.
        .route("/01/{gtin}", get(resolve_by_gtin_handler))
        .route(
            "/01/{gtin}/21/{serial}",
            get(resolve_by_gtin_serial_handler),
        )
        .route("/01/{gtin}/10/{batch}", get(resolve_by_gtin_batch_handler))
        .route(
            "/01/{gtin}/10/{batch}/21/{serial}",
            get(resolve_by_gtin_batch_serial_handler),
        )
        .layer(TraceLayer::new_for_http())
        .layer(middleware::from_fn(http_metrics_middleware))
        .layer(middleware::from_fn(inject_request_id))
        .layer(PropagateRequestIdLayer::x_request_id())
        .layer(SetRequestIdLayer::x_request_id(UuidRequestId))
        .with_state(state)
}

/// Route to HTML or JSON-LD based on the `Accept` header (RFC 9110 §12.4).
async fn content_negotiation_handler(
    state: State<AppState>,
    path: Path<String>,
    request: Request,
) -> axum::response::Response {
    let accept = request
        .headers()
        .get(axum::http::header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let headers = request.headers().clone();

    let res_req = dpp_digital_link::ResolutionRequest::from_accept_header(accept);
    let wants_html = matches!(
        res_req.media_type,
        Some(dpp_digital_link::DppMediaType::Html)
    );

    // Keep a handle for telemetry before `state`/`path` are moved into the handler.
    let scan_counter = state.scan_counter.clone();
    let dpp_id = path.0.clone();

    let mut response = if wants_html {
        resolve_html_handler(state, path).await.into_response()
    } else {
        resolve_json_handler(state, headers, path)
            .await
            .into_response()
    };

    // Count a scan only on a genuine terminal-view success (200) — the html/json
    // handlers return their own non-2xx status for not-found/gone/unverifiable,
    // so this never counts a miss, and it counts one physical scan once. The GS1
    // `/01/{gtin}` redirect deliberately does not reach here and is not counted.
    if let Some(counter) = scan_counter
        && response.status().is_success()
    {
        let variant = if wants_html {
            dpp_common::scan::ScanVariant::Html
        } else {
            dpp_common::scan::ScanVariant::Json
        };
        counter.record_scan(&dpp_id, variant);
    }

    response
        .headers_mut()
        .insert(axum::http::header::VARY, HeaderValue::from_static("Accept"));

    response
}
