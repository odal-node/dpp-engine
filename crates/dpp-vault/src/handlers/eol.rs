//! `POST /api/v1/dpp/{dppId}/eol` — declare a passport end-of-life.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use dpp_domain::eol::{DeactivationReason, EolEvent};
use serde::{Deserialize, Serialize};

use crate::state::AppState;

use super::error::{
    conflict_error, field_validation_error, internal_error, not_found_error, parse_passport_id,
};
use crate::extract::Json;
use crate::middleware::scope::RequireWrite;

/// EOL request body: the typed reason plus optional circularity data. The
/// passport id comes from the path; `declaredAt` is server-stamped.
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EolRequest {
    /// Why the passport is being deactivated (recycled / destroyed / exported / lost).
    /// A destruction the ESPR Art. 25(1) ban reaches must cite a derogation, a
    /// point of Art. 2 of Delegated Regulation (EU) 2026/296 by its name
    /// (`422` otherwise). A free-text `{"category": ...}` is refused on a new
    /// declaration.
    pub reason: DeactivationReason,
    /// Whether the product was an unsold consumer product, which a passport does
    /// not record. Required with `destroyed`: with the operator's enterprise size
    /// it decides whether the destruction ban reaches the product.
    #[serde(default)]
    pub unsold: Option<bool>,
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
    // The gate is an extractor, and it precedes the body extractor
    // deliberately: axum runs body-less extractors first, so a wrong-scope
    // caller is refused before the body is buffered or parsed.
    RequireWrite(auth): RequireWrite,
    Path(dpp_id): Path<String>,
    Json(body): Json<EolRequest>,
) -> impl IntoResponse {
    let passport_id = match parse_passport_id(&dpp_id) {
        Ok(id) => id,
        Err(e) => return e,
    };

    let destroyed = matches!(body.reason, DeactivationReason::Destroyed { .. });
    let unsold = match body.unsold {
        Some(unsold) => unsold,
        None if destroyed => {
            return field_validation_error(&dpp_domain::ValidationErrors {
                errors: vec![dpp_domain::FieldError {
                    field: "/unsold".to_owned(),
                    message: "A destruction states whether the product was an unsold consumer \
                              product: ESPR Art. 25(1) bars destroying unsold products of \
                              Annex VII, and a passport does not record whether it was sold."
                        .to_owned(),
                }],
            });
        }
        None => false,
    };

    let declared_by = body.declared_by.unwrap_or_else(|| auth.user_id.clone());
    let mut eol = EolEvent::new(passport_id, body.reason, declared_by);
    eol.material_recovery = body.material_recovery;
    eol.notes = body.notes;

    match state
        .service
        .declare_eol(passport_id, eol, unsold, &auth)
        .await
    {
        Ok(p) => (StatusCode::OK, Json(crate::api::PassportResponse::from(&p))).into_response(),
        Err(dpp_domain::DppError::NotFound(_)) => not_found_error("DPP not found."),
        Err(dpp_domain::DppError::InvalidTransition { .. }) => {
            conflict_error("DPP cannot be deactivated from its current state.")
        }
        Err(dpp_domain::DppError::Validation(errs)) => field_validation_error(&errs),
        Err(e) => internal_error(e),
    }
}
