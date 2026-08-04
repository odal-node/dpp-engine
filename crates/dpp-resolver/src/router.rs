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
        resolve_aas::{AAS_MEDIA_TYPE, resolve_aas_handler},
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

/// Route to HTML, JSON-LD, or an AAS Environment based on the `Accept`
/// header (RFC 9110 §12.4). Anything this route cannot produce gets `406`.
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
    let allows_json = accept_allows_json(accept);
    // `text/*` selects html only when nothing JSON-shaped is also acceptable,
    // so a client offering both keeps receiving what it received before.
    let wants_html = matches!(
        res_req.media_type,
        Some(dpp_digital_link::DppMediaType::Html)
    ) || (accept_names_text_wildcard(accept) && !allows_json);
    let wants_aas = accept_names_aas(accept);

    // Anything we cannot produce gets 406 rather than a body the caller did not
    // ask for. Deliberately narrow: an absent, empty, `*/*`, or unparseable
    // `Accept` still reaches the JSON-LD default, because RFC 9110 §12.5.1 says
    // a missing header means the client accepts anything — and because every
    // existing consumer relies on that path.
    if !wants_html && !wants_aas && !allows_json {
        return not_acceptable(accept);
    }

    // Keep a handle for telemetry before `state`/`path` are moved into the handler.
    let scan_counter = state.scan_counter.clone();
    let dpp_id = path.0.clone();

    let mut response = if wants_aas {
        resolve_aas_handler(state, path).await.into_response()
    } else if wants_html {
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
        // An AAS read counts as `Json`: it is a machine read of the passport,
        // which is what that variant records. Splitting it out would need a
        // migration — the `variant` column is CHECK-constrained to
        // ('html','json') — and is only worth doing if AAS volume ever needs
        // to be told apart from JSON-LD volume.
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

/// The media ranges in an `Accept` header the client is actually willing to
/// take, lowercased, with `q=0` entries dropped.
///
/// RFC 9110 §12.5.1: `q=0` means "not acceptable". Listing a type and then
/// rejecting it is the standard way to say *anything but this*, and reading the
/// name while ignoring the weight inverts the client's request — `Accept:
/// application/aas+json;q=0, application/ld+json` was served AAS, which is the
/// one representation it asked not to receive.
///
/// Weights are used only to exclude. Ranking the survivors is `DppMediaType`'s
/// job for the html/json split, and this route's third type is chosen by name.
fn acceptable_ranges(accept: &str) -> Vec<String> {
    accept
        .split(',')
        .filter_map(|entry| {
            let mut parts = entry.trim().split(';');
            let media = parts.next()?.trim();
            if media.is_empty() {
                return None;
            }
            let refused = parts.any(|param| {
                param
                    .trim()
                    .strip_prefix("q=")
                    .and_then(|q| q.trim().parse::<f32>().ok())
                    .is_some_and(|q| q <= 0.0)
            });
            (!refused).then(|| media.to_ascii_lowercase())
        })
        .collect()
}

/// Whether the `Accept` header explicitly asks for the AAS media type.
///
/// Matched by name rather than through `DppMediaType`, which models the GS1
/// link-type vocabulary and folds anything unrecognised into `Custom`.
fn accept_names_aas(accept: &str) -> bool {
    acceptable_ranges(accept)
        .iter()
        .any(|media| media == AAS_MEDIA_TYPE)
}

/// Whether the JSON-LD default is a legitimate answer to this `Accept`.
///
/// True for an absent or empty header, for any wildcard, and for the JSON
/// family. The permissive cases are load-bearing: `*/*` is what curl and most
/// HTTP clients send by default, and treating it as unacceptable would 406
/// every existing consumer of this route.
fn accept_allows_json(accept: &str) -> bool {
    if accept.trim().is_empty() {
        return true;
    }
    acceptable_ranges(accept).iter().any(|media| {
        media == "*/*"
            || media == "application/*"
            || media == "application/json"
            || media == "application/ld+json"
    })
}

/// Whether the `Accept` header carries the `text/*` subtype wildcard.
///
/// Deliberately does **not** cover `text/html`: which of html and json wins
/// when both are named is `DppMediaType`'s decision, and taking it over here
/// would change what an existing `Accept: text/html, application/json` client
/// receives. This only covers the range that `DppMediaType` folds into
/// `Custom` and that therefore used to earn a `406` — while its sibling
/// `application/*` was honoured. That asymmetry was an oversight, not a policy.
fn accept_names_text_wildcard(accept: &str) -> bool {
    acceptable_ranges(accept)
        .iter()
        .any(|media| media == "text/*")
}

/// `406` naming what this route can actually produce, so a client can correct
/// itself without reading documentation.
fn not_acceptable(accept: &str) -> axum::response::Response {
    let problem = dpp_common::http_problem::Problem::new(
        axum::http::StatusCode::NOT_ACCEPTABLE,
        "Not Acceptable",
    )
    .with_detail(format!(
        "No representation matches '{accept}'. This resource is available as \
         text/html, application/ld+json, or {AAS_MEDIA_TYPE}."
    ));
    let mut response = (
        axum::http::StatusCode::NOT_ACCEPTABLE,
        [(axum::http::header::CONTENT_TYPE, "application/problem+json")],
        serde_json::to_string(&problem).unwrap_or_default(),
    )
        .into_response();
    response
        .headers_mut()
        .insert(axum::http::header::VARY, HeaderValue::from_static("Accept"));
    response
}
