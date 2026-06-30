use axum::{Json, http::StatusCode, response::IntoResponse};
use serde_json::json;

/// `GET /api/v1/info` — vault metadata for dashboard feature detection.
pub async fn info_handler() -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(json!({
            "version": env!("CARGO_PKG_VERSION"),
            "authMethods": ["api_key", "local"],
            "features": ["passthrough_compliance"]
        })),
    )
}
