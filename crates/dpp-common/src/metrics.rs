//! Axum middleware for HTTP request metrics (counter + histogram).
//!
//! # Naming convention (workspace-wide, not just this middleware)
//!
//! Metric names are permanent API surface the moment something scrapes them —
//! a fleet-wide dashboard or alert rule parses them forever. The convention
//! observed across the engine: counters end in `_total` (`http_requests_total`,
//! `signing_failures_total`, `plugin_fuel_exhausted_total`), histograms end in
//! their unit (`http_request_duration_seconds`), gauges carry no suffix
//! (`trust_mode`). Follow it for any new metric.
//!
//! One existing near-miss worth knowing about rather than silently renaming:
//! `registry_outbox_rejected` (a gauge, `dpp-node::main`) and
//! `registry_outbox_rejected_total` (a counter, `dpp-node::infra::registry_drain`)
//! are two different metrics with a name that differs only by the `_total`
//! convention — easy to misread as the same series. Renaming either is a
//! breaking change for anyone already scraping it, so this is flagged, not
//! fixed, here.

use std::time::Instant;

use axum::{extract::Request, middleware::Next, response::Response};

/// Tower middleware that records `http_requests_total` (counter) and
/// `http_request_duration_seconds` (histogram) for every request.
///
/// Dimensions: `route`, `method`, `status`. The `route` is the matched path
/// template (e.g. `/vault/dpp/:dppId`), not the resolved URL, so high-cardinality
/// IDs do not explode the label space.
///
/// Add to each service router via `axum::middleware::from_fn(http_metrics_middleware)`.
/// Metrics are no-ops unless a `metrics` recorder (e.g. Prometheus) has been
/// installed at process startup.
pub async fn http_metrics_middleware(request: Request, next: Next) -> Response {
    let method = request.method().as_str().to_owned();
    let route = request
        .extensions()
        .get::<axum::extract::MatchedPath>()
        .map(|m| m.as_str().to_owned())
        .unwrap_or_else(|| "unknown".to_owned());
    let start = Instant::now();

    let response = next.run(request).await;

    let status = response.status().as_u16().to_string();
    let duration = start.elapsed().as_secs_f64();

    metrics::counter!(
        "http_requests_total",
        "route"  => route.clone(),
        "method" => method.clone(),
        "status" => status
    )
    .increment(1);

    metrics::histogram!(
        "http_request_duration_seconds",
        "route"  => route,
        "method" => method
    )
    .record(duration);

    response
}
