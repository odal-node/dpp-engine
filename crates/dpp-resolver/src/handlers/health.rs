//! Health and readiness handlers — liveness and readiness probes for the resolver.

use axum::{http::StatusCode, response::Json};
use serde_json::{Value, json};

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

/// Readiness probe. Returns `200 OK` when the resolver is ready to serve traffic.
pub async fn ready_handler() -> (StatusCode, Json<Value>) {
    (StatusCode::OK, Json(json!({ "status": "ready" })))
}
