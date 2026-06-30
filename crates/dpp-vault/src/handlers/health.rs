//! Health and readiness probes for the vault service.

use std::time::Instant;

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Json, Response},
};
use dpp_common::http_problem::Problem;
use serde_json::{Value, json};

use crate::state::AppState;

/// Liveness probe. Returns `200 OK` with service name and version.
pub async fn health_handler() -> (StatusCode, Json<Value>) {
    (
        StatusCode::OK,
        Json(json!({
            "status": "ok",
            "service": env!("CARGO_PKG_NAME"),
            "version": env!("CARGO_PKG_VERSION")
        })),
    )
}

/// Readiness probe — pings the database to verify the connection is alive.
///
/// Records `db_ping_duration_seconds` (histogram) and `db_ping_total{result}`
/// (counter) on every invocation so the scrape target carries a continuous
/// DB latency signal.
pub async fn ready_handler(State(state): State<AppState>) -> Response {
    let start = Instant::now();
    let result = state.db_ping.ping().await;
    let elapsed = start.elapsed().as_secs_f64();

    let outcome = if result.is_ok() { "ok" } else { "error" };
    metrics::histogram!("db_ping_duration_seconds").record(elapsed);
    metrics::counter!("db_ping_total", "result" => outcome).increment(1);

    match result {
        Ok(_) => (
            StatusCode::OK,
            Json(json!({ "status": "ready", "db": "ok" })),
        )
            .into_response(),
        Err(e) => Problem::new(StatusCode::SERVICE_UNAVAILABLE, "Service Unavailable")
            .with_detail(e.to_string())
            .into_response(),
    }
}
