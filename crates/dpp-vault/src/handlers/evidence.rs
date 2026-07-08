//! `GET /api/v1/dpp/{dppId}/evidence` — self-contained, signed evidence
//! dossier for fully offline verification (N02).

use axum::{
    Json,
    extract::{Extension, Path, State},
    http::StatusCode,
    response::IntoResponse,
};

use crate::{middleware::auth::AuthContext, state::AppState};

use super::error::{api_error, internal_error, parse_passport_id};

/// `GET /api/v1/dpp/{dppId}/evidence` — assemble and return the evidence
/// dossier. Authenticated tier only (it contains full-view data); a public
/// redacted variant can follow later.
pub async fn evidence_handler(
    State(state): State<AppState>,
    Extension(_auth): Extension<AuthContext>,
    Path(dpp_id): Path<String>,
) -> impl IntoResponse {
    let passport_id = match parse_passport_id(&dpp_id) {
        Ok(id) => id,
        Err(e) => return e,
    };

    match state.service.export_evidence(passport_id).await {
        Ok(dossier) => (StatusCode::OK, Json(dossier)).into_response(),
        Err(dpp_domain::DppError::NotFound(_)) => {
            api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "DPP not found.")
        }
        Err(dpp_domain::DppError::Validation(msg)) => {
            api_error(StatusCode::CONFLICT, "CONFLICT", &msg.to_string())
        }
        Err(e) => internal_error(e),
    }
}
