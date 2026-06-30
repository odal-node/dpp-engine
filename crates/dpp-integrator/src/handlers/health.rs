//! Health probe for the integrator service.

use axum::{Json, http::StatusCode};
use serde_json::json;

/// Liveness probe. Returns `200 OK` with service name and version.
pub async fn health_handler() -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::OK,
        Json(json!({
            "status": "ok",
            "service": "dpp-integrator",
            "version": env!("CARGO_PKG_VERSION")
        })),
    )
}
