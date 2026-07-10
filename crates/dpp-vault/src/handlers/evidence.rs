//! Evidence dossier endpoints: generate, list, fetch, and verify.

use axum::{
    Json,
    body::Bytes,
    extract::{Extension, Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use uuid::Uuid;

use crate::{domain::verify::verify_dossier_json, middleware::auth::AuthContext, state::AppState};

use super::error::{api_error, internal_error, parse_passport_id};

#[allow(clippy::result_large_err)]
fn parse_dossier_id(s: &str) -> Result<Uuid, axum::response::Response> {
    Uuid::parse_str(s)
        .map_err(|_| api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", "Invalid dossier id"))
}

/// `POST /api/v1/dpp/{dppId}/evidence` — generate and store a new evidence
/// dossier for a passport.
pub async fn generate_evidence_handler(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(dpp_id): Path<String>,
) -> impl IntoResponse {
    let passport_id = match parse_passport_id(&dpp_id) {
        Ok(id) => id,
        Err(e) => return e,
    };

    match state.service.generate_evidence(passport_id, &auth).await {
        Ok(record) => (StatusCode::CREATED, Json(record)).into_response(),
        Err(dpp_domain::DppError::NotFound(_)) => {
            api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "DPP not found.")
        }
        Err(dpp_domain::DppError::Validation(msg)) => {
            api_error(StatusCode::CONFLICT, "CONFLICT", &msg.to_string())
        }
        Err(e) => internal_error(e),
    }
}

/// `GET /api/v1/dpp/{dppId}/evidence` — list stored dossier summaries for a
/// passport, newest first.
pub async fn list_evidence_handler(
    State(state): State<AppState>,
    Extension(_auth): Extension<AuthContext>,
    Path(dpp_id): Path<String>,
) -> impl IntoResponse {
    let passport_id = match parse_passport_id(&dpp_id) {
        Ok(id) => id,
        Err(e) => return e,
    };

    match state.service.list_evidence(passport_id).await {
        Ok(summaries) => (StatusCode::OK, Json(summaries)).into_response(),
        Err(dpp_domain::DppError::NotFound(_)) => {
            api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "DPP not found.")
        }
        Err(e) => internal_error(e),
    }
}

/// `GET /api/v1/evidence/{id}` — fetch one stored dossier's document.
pub async fn get_evidence_handler(
    State(state): State<AppState>,
    Extension(_auth): Extension<AuthContext>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let dossier_id = match parse_dossier_id(&id) {
        Ok(id) => id,
        Err(e) => return e,
    };

    match state.service.get_evidence(dossier_id).await {
        Ok(record) => (StatusCode::OK, Json(record.dossier)).into_response(),
        Err(dpp_domain::DppError::NotFound(_)) => {
            api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "Dossier not found.")
        }
        Err(e) => internal_error(e),
    }
}

/// `POST /api/v1/evidence/{id}/verify` — verify a stored dossier.
pub async fn verify_evidence_handler(
    State(state): State<AppState>,
    Extension(_auth): Extension<AuthContext>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let dossier_id = match parse_dossier_id(&id) {
        Ok(id) => id,
        Err(e) => return e,
    };

    match state.service.verify_evidence(dossier_id).await {
        Ok(report) => (StatusCode::OK, Json(report)).into_response(),
        Err(dpp_domain::DppError::NotFound(_)) => {
            api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "Dossier not found.")
        }
        Err(e) => internal_error(e),
    }
}

/// `POST /api/v1/evidence/verify` — verify an uploaded dossier document.
pub async fn verify_document_handler(
    State(_state): State<AppState>,
    Extension(_auth): Extension<AuthContext>,
    body: Bytes,
) -> impl IntoResponse {
    match verify_dossier_json(&body) {
        Ok(report) => (StatusCode::OK, Json(report)).into_response(),
        Err(e) => api_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "INVALID_DOSSIER",
            &e.to_string(),
        ),
    }
}
