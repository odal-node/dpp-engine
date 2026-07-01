//! `POST /api/v1/dpp/{dppId}/publish` — sign and publish a draft passport.

use axum::{
    Json,
    extract::{Extension, Path, State},
    http::StatusCode,
    response::IntoResponse,
};

use crate::{middleware::auth::AuthContext, state::AppState};

use super::error::{api_error, internal_error, parse_passport_id};

/// `POST /api/v1/dpp/{dppId}/publish` — Ed25519-sign and publish a draft passport.
///
/// Validates sector data, calls the identity service to sign, then atomically
/// writes the JWS, QR URL, and `Published` status. Returns `409` if the passport
/// is not in a publishable state.
pub async fn publish_handler(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(dpp_id): Path<String>,
) -> impl IntoResponse {
    let passport_id = match parse_passport_id(&dpp_id) {
        Ok(id) => id,
        Err(e) => return e,
    };

    // Gate: the responsible economic operator's identity must be complete before
    // any passport can be published (EU DPP requirement). Enforced here rather
    // than at bootstrap so key-minting and legal onboarding stay decoupled.
    match state
        .operator_service
        .get(dpp_types::STANDALONE_OPERATOR_ID)
        .await
    {
        Ok(op) if !op.is_complete() => {
            let missing = op.missing_fields().join(", ");
            return api_error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "OPERATOR_INCOMPLETE",
                &format!(
                    "Operator identity is incomplete — set the following before \
                     publishing: {missing}. Use `odal operator set` (or PATCH /api/v1/operator)."
                ),
            );
        }
        Ok(_) => {}
        Err(e) => return internal_error(e),
    }

    match state.service.publish(passport_id, &auth).await {
        Ok(p) => (StatusCode::OK, Json(p)).into_response(),
        Err(dpp_domain::DppError::NotFound(_)) => {
            api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "DPP not found.")
        }
        Err(dpp_domain::DppError::InvalidTransition { .. }) => api_error(
            StatusCode::CONFLICT,
            "CONFLICT",
            "DPP cannot be published from its current state.",
        ),
        // Publish-time gates (Annex III completeness, binding compliance
        // violations, sector-data validation) surface as client errors, not 500s.
        Err(dpp_domain::DppError::Validation(msg)) => api_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "VALIDATION_ERROR",
            &msg.to_string(),
        ),
        Err(e) => internal_error(e),
    }
}
