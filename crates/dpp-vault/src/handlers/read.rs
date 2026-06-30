//! `GET /api/v1/dpp/{dppId}` — authenticated read of any passport by id.

use axum::{
    Json,
    extract::{Extension, Path, State},
    http::StatusCode,
    response::IntoResponse,
};

use crate::{middleware::auth::AuthContext, state::AppState};

use super::error::{api_error, internal_error, parse_passport_id};

/// `GET /api/v1/dpp/{dppId}` — fetch a passport in any status (authenticated).
pub async fn read_handler(
    State(state): State<AppState>,
    Extension(_auth): Extension<AuthContext>,
    Path(dpp_id): Path<String>,
) -> impl IntoResponse {
    let passport_id = match parse_passport_id(&dpp_id) {
        Ok(id) => id,
        Err(e) => return e,
    };

    match state.service.find_by_id(passport_id).await {
        Ok(p) => (StatusCode::OK, Json(p)).into_response(),
        Err(dpp_domain::DppError::NotFound(_)) => {
            api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "DPP not found.")
        }
        Err(e) => internal_error(e),
    }
}
