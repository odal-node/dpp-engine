//! Health and readiness probes for the identity service.

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

/// Readiness probe. Always returns `200 ready` — the identity service has no
/// external dependency to check (the key store is loaded at startup).
pub async fn ready_handler() -> (StatusCode, Json<Value>) {
    (StatusCode::OK, Json(json!({ "status": "ready" })))
}
