//! `POST /api/v1/dpp/{dppId}/eol` — declare a passport end-of-life.

use axum::{
    Json,
    extract::{Extension, Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use dpp_domain::domain::eol::{DeactivationReason, EolEvent};
use serde::Deserialize;

use crate::{middleware::auth::AuthContext, state::AppState};

use super::error::{
    conflict_error, internal_error, not_found_error, parse_passport_id, require_write,
};

/// EOL request body: the typed reason plus optional circularity data. The
/// passport id comes from the path; `declaredAt` is server-stamped.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EolRequest {
    /// Why the passport is being deactivated (recycled / destroyed / exported / lost).
    /// Destruction must carry a derogation (enforced by the type).
    pub reason: DeactivationReason,
    /// DID of the declaring operator; defaults to the authenticated actor.
    #[serde(default)]
    pub declared_by: Option<String>,
    /// Optional recovered-material summary (Battery Annex XIII circularity).
    #[serde(default)]
    pub material_recovery: Option<serde_json::Value>,
    /// Optional free-text notes.
    #[serde(default)]
    pub notes: Option<String>,
}

/// `POST /api/v1/dpp/{dppId}/eol` — deactivate a published or suspended passport
/// with a typed end-of-life reason. The record is retained (never deleted).
pub async fn eol_handler(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(dpp_id): Path<String>,
    Json(body): Json<EolRequest>,
) -> impl IntoResponse {
    if let Some(resp) = require_write(&auth, "Declaring a passport end-of-life") {
        return resp;
    }
    let passport_id = match parse_passport_id(&dpp_id) {
        Ok(id) => id,
        Err(e) => return e,
    };

    let declared_by = body.declared_by.unwrap_or_else(|| auth.user_id.clone());
    let mut eol = EolEvent::new(passport_id, body.reason, declared_by);
    eol.material_recovery = body.material_recovery;
    eol.notes = body.notes;

    match state.service.declare_eol(passport_id, eol, &auth).await {
        Ok(p) => (StatusCode::OK, Json(p)).into_response(),
        Err(dpp_domain::DppError::NotFound(_)) => not_found_error("DPP not found."),
        Err(dpp_domain::DppError::InvalidTransition { .. }) => {
            conflict_error("DPP cannot be deactivated from its current state.")
        }
        Err(e) => internal_error(e),
    }
}
