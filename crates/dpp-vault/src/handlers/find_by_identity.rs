//! `GET /api/v1/dpp/by-identity` — exact compound identity lookup for the
//! import delta-matcher (sector, GTIN, batch), across `Draft` and `Published`.

use axum::{
    Json,
    extract::{Extension, Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::Deserialize;

use dpp_domain::domain::{product_identity::ProductIdentity, sector::Sector};

use crate::{middleware::auth::AuthContext, state::AppState};

use super::error::internal_error;

/// Query parameters for the identity-lookup endpoint.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityQuery {
    pub sector: Sector,
    pub gtin: String,
    /// Omit to match only passports with no batch set.
    pub batch_id: Option<String>,
}

/// `GET /api/v1/dpp/by-identity` — `404` if no passport matches.
pub async fn find_by_identity_handler(
    State(state): State<AppState>,
    Extension(_auth): Extension<AuthContext>,
    Query(query): Query<IdentityQuery>,
) -> impl IntoResponse {
    let identity = ProductIdentity {
        sector: query.sector,
        gtin: query.gtin,
        batch_id: query.batch_id,
    };

    match state.service.find_by_identity(&identity).await {
        Ok(Some(p)) => (StatusCode::OK, Json(p)).into_response(),
        Ok(None) => dpp_common::http_problem::not_found("No passport matches that identity.")
            .into_response(),
        Err(e) => internal_error(e),
    }
}
