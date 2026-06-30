use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};

use dpp_domain::domain::status::PassportStatus;

use crate::public_view::public_view;
use crate::state::AppState;

use super::error::{api_error, internal_error, parse_passport_id};

/// Public, unauthenticated read of a **published** passport.
///
/// Used by the resolver service to serve the public passport page. Returns 404
/// for any passport that is not in `Published` / `active` state. The payload is
/// **redacted to the Public access tier** (crypto Gap 6 / vault V1 / node N2) —
/// professional/confidential fields are never served on this unauthenticated route.
pub async fn public_read_handler(
    State(state): State<AppState>,
    Path(dpp_id): Path<String>,
) -> impl IntoResponse {
    let passport_id = match parse_passport_id(&dpp_id) {
        Ok(id) => id,
        Err(e) => return e,
    };

    // We look up by ID only (no operator filter) and check status afterwards.
    match state.service.find_by_id_any_status(passport_id).await {
        Ok(Some(p)) if p.status == PassportStatus::Published => {
            let full = match serde_json::to_value(&p) {
                Ok(v) => v,
                Err(e) => {
                    return internal_error(dpp_domain::DppError::Serialisation(e.to_string()));
                }
            };
            let view = public_view(&full, p.sector.catalog_key());
            (StatusCode::OK, Json(view)).into_response()
        }
        Ok(Some(p)) if p.status == PassportStatus::Suspended => api_error(
            StatusCode::GONE,
            "SUSPENDED",
            "This passport has been suspended.",
        ),
        Ok(_) => api_error(
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            "DPP not found or not published.",
        ),
        Err(dpp_domain::DppError::NotFound(_)) => {
            api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "DPP not found.")
        }
        Err(e) => internal_error(e),
    }
}
