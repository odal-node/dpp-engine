//! Axum middleware for HTTP request metrics (counter + histogram).

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
