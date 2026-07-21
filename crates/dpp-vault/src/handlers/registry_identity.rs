//! Facility (ESPR Annex III) and operator-identifier (ESPR Art. 13) management
//! endpoints. Admin-scoped: these are operator-config mutations.

use axum::{
    Json,
    extract::{Extension, Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use uuid::Uuid;

use dpp_domain::domain::error::DppError;
use dpp_types::STANDALONE_OPERATOR_ID;
use dpp_types::registry_identity::{CreateFacilityRequest, CreateOperatorIdentifierRequest};

use crate::{middleware::auth::AuthContext, state::AppState};

use super::error::{api_error, internal_error, require_admin};

// ── Facilities ───────────────────────────────────────────────────────────────

/// `GET /api/v1/facilities` — list the operator's facilities.
pub async fn facilities_list_handler(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
) -> impl IntoResponse {
    if let Some(resp) = require_admin(&auth, "Registry-identity management") {
        return resp;
    }
    match state.registry_identity_service.list_facilities().await {
        Ok(items) => (StatusCode::OK, Json(items)).into_response(),
        Err(e) => internal_error(e),
    }
}

/// `POST /api/v1/facilities` — add a facility (validated GLN/country).
pub async fn facilities_create_handler(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Json(body): Json<CreateFacilityRequest>,
) -> impl IntoResponse {
    if let Some(resp) = require_admin(&auth, "Registry-identity management") {
        return resp;
    }
    match state
        .registry_identity_service
        .add_facility(body, &auth.user_id)
        .await
    {
        Ok(f) => (StatusCode::CREATED, Json(f)).into_response(),
        Err(DppError::Validation(msg)) => api_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "VALIDATION_ERROR",
            &msg.to_string(),
        ),
        Err(e) => internal_error(e),
    }
}

/// `POST /api/v1/facilities/{id}/default` — make this facility the default.
pub async fn facilities_set_default_handler(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if let Some(resp) = require_admin(&auth, "Registry-identity management") {
        return resp;
    }
    let parsed = match Uuid::parse_str(&id) {
        Ok(u) => u,
        Err(_) => {
            return api_error(
                StatusCode::BAD_REQUEST,
                "BAD_REQUEST",
                "Invalid facility id",
            );
        }
    };
    match state
        .registry_identity_service
        .set_default_facility(parsed, &auth.user_id)
        .await
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(DppError::NotFound(_)) => {
            api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "Facility not found")
        }
        Err(e) => internal_error(e),
    }
}

/// `DELETE /api/v1/facilities/{id}` — retire a facility (soft-delete; the row is
/// kept as Annex III provenance for passports that stamped its identifier).
pub async fn facilities_delete_handler(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if let Some(resp) = require_admin(&auth, "Registry-identity management") {
        return resp;
    }
    let parsed = match Uuid::parse_str(&id) {
        Ok(u) => u,
        Err(_) => {
            return api_error(
                StatusCode::BAD_REQUEST,
                "BAD_REQUEST",
                "Invalid facility id",
            );
        }
    };
    match state
        .registry_identity_service
        .retire_facility(parsed, &auth.user_id)
        .await
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(DppError::NotFound(_)) => {
            api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "Facility not found")
        }
        Err(DppError::Validation(msg)) => api_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "VALIDATION_ERROR",
            &msg.to_string(),
        ),
        Err(e) => internal_error(e),
    }
}

/// `GET /api/v1/facilities/{id}/audit` — append-only mutation history for a facility.
pub async fn facilities_audit_handler(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if let Some(resp) = require_admin(&auth, "Registry-identity management") {
        return resp;
    }
    let parsed = match Uuid::parse_str(&id) {
        Ok(u) => u,
        Err(_) => {
            return api_error(
                StatusCode::BAD_REQUEST,
                "BAD_REQUEST",
                "Invalid facility id",
            );
        }
    };
    match state.registry_identity_service.facility_audit(parsed).await {
        Ok(items) => (StatusCode::OK, Json(items)).into_response(),
        Err(e) => internal_error(e),
    }
}

// ── Operator identifiers ─────────────────────────────────────────────────────

/// `GET /api/v1/operator-identifiers` — list the operator's identifiers.
pub async fn operator_ids_list_handler(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
) -> impl IntoResponse {
    if let Some(resp) = require_admin(&auth, "Registry-identity management") {
        return resp;
    }
    match state
        .registry_identity_service
        .list_operator_identifiers()
        .await
    {
        Ok(items) => (StatusCode::OK, Json(items)).into_response(),
        Err(e) => internal_error(e),
    }
}

/// `POST /api/v1/operator-identifiers` — add an identifier (validated LEI/VAT/…).
pub async fn operator_ids_create_handler(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Json(body): Json<CreateOperatorIdentifierRequest>,
) -> impl IntoResponse {
    if let Some(resp) = require_admin(&auth, "Registry-identity management") {
        return resp;
    }
    // The identifier itself carries no per-entry country (an Art. 13 economic-
    // operator identifier belongs to the operator, not a location) — reuse the
    // operator's own registered country for the `dpp-registry` validation.
    let operator_country = match state.operator_service.get(STANDALONE_OPERATOR_ID).await {
        Ok(cfg) => cfg.country,
        Err(e) => return internal_error(e),
    };
    match state
        .registry_identity_service
        .add_operator_identifier(body, &operator_country, &auth.user_id)
        .await
    {
        Ok(o) => (StatusCode::CREATED, Json(o)).into_response(),
        Err(DppError::Validation(msg)) => api_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "VALIDATION_ERROR",
            &msg.to_string(),
        ),
        Err(e) => internal_error(e),
    }
}

/// `POST /api/v1/operator-identifiers/{id}/primary` — make this the primary id.
pub async fn operator_ids_set_primary_handler(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if let Some(resp) = require_admin(&auth, "Registry-identity management") {
        return resp;
    }
    let parsed = match Uuid::parse_str(&id) {
        Ok(u) => u,
        Err(_) => {
            return api_error(
                StatusCode::BAD_REQUEST,
                "BAD_REQUEST",
                "Invalid operator-identifier id",
            );
        }
    };
    match state
        .registry_identity_service
        .set_primary_operator_identifier(parsed, &auth.user_id)
        .await
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(DppError::NotFound(_)) => api_error(
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            "Operator identifier not found",
        ),
        Err(e) => internal_error(e),
    }
}

/// `DELETE /api/v1/operator-identifiers/{id}` — retire an identifier (soft-delete;
/// the row is kept as Art. 13 provenance for passports that stamped its value).
pub async fn operator_ids_delete_handler(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if let Some(resp) = require_admin(&auth, "Registry-identity management") {
        return resp;
    }
    let parsed = match Uuid::parse_str(&id) {
        Ok(u) => u,
        Err(_) => {
            return api_error(
                StatusCode::BAD_REQUEST,
                "BAD_REQUEST",
                "Invalid operator-identifier id",
            );
        }
    };
    match state
        .registry_identity_service
        .retire_operator_identifier(parsed, &auth.user_id)
        .await
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(DppError::NotFound(_)) => api_error(
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            "Operator identifier not found",
        ),
        Err(DppError::Validation(msg)) => api_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "VALIDATION_ERROR",
            &msg.to_string(),
        ),
        Err(e) => internal_error(e),
    }
}

/// `GET /api/v1/operator-identifiers/{id}/audit` — append-only mutation history.
pub async fn operator_ids_audit_handler(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if let Some(resp) = require_admin(&auth, "Registry-identity management") {
        return resp;
    }
    let parsed = match Uuid::parse_str(&id) {
        Ok(u) => u,
        Err(_) => {
            return api_error(
                StatusCode::BAD_REQUEST,
                "BAD_REQUEST",
                "Invalid operator-identifier id",
            );
        }
    };
    match state
        .registry_identity_service
        .operator_identifier_audit(parsed)
        .await
    {
        Ok(items) => (StatusCode::OK, Json(items)).into_response(),
        Err(e) => internal_error(e),
    }
}
