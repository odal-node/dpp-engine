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

use std::sync::atomic::{AtomicU64, Ordering};
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

/// Signing failures since this process started. The Prometheus recorder cannot be
/// read back, so the node-health route reads these instead.
static SIGNING_FAILURES: AtomicU64 = AtomicU64::new(0);
/// Ruleset bundles refused on load since this process started, as above.
static RULESET_LOAD_FAILURES: AtomicU64 = AtomicU64::new(0);

/// Count one publish refused because a passport could not be signed.
///
/// Every increment goes through here, not `metrics::counter!` directly, so the
/// count `/metrics` exports and the one the node-health route reports cannot drift.
pub fn record_signing_failure() {
    SIGNING_FAILURES.fetch_add(1, Ordering::Relaxed);
    metrics::counter!("signing_failures_total").increment(1);
}

/// Count one ruleset bundle refused on load. See [`record_signing_failure`].
pub fn record_ruleset_load_failure() {
    RULESET_LOAD_FAILURES.fetch_add(1, Ordering::Relaxed);
    metrics::counter!("ruleset_load_failures_total").increment(1);
}

/// Signing failures since process start. A restart resets it.
#[must_use]
pub fn signing_failures() -> u64 {
    SIGNING_FAILURES.load(Ordering::Relaxed)
}

/// Ruleset bundles refused since process start. A restart resets it.
#[must_use]
pub fn ruleset_load_failures() -> u64 {
    RULESET_LOAD_FAILURES.load(Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A refused signature shows up on the readable count, not only on the
    /// exported counter the route cannot read.
    #[test]
    fn a_recorded_signing_failure_is_counted_where_the_route_reads_it() {
        let before = signing_failures();
        record_signing_failure();
        assert_eq!(signing_failures(), before + 1);
    }

    #[test]
    fn a_recorded_ruleset_failure_is_counted_where_the_route_reads_it() {
        let before = ruleset_load_failures();
        record_ruleset_load_failure();
        assert_eq!(ruleset_load_failures(), before + 1);
    }
}
