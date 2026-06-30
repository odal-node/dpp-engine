use std::sync::OnceLock;

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};

use dpp_crypto::access::{SectorAccessPolicy, filter_by_access_tier};
use dpp_domain::{AccessTier, SectorCatalog};

use crate::state::AppState;

use super::error::{api_error, internal_error};

fn catalog() -> &'static SectorCatalog {
    static CATALOG: OnceLock<SectorCatalog> = OnceLock::new();
    CATALOG.get_or_init(SectorCatalog::new)
}

/// Public, unauthenticated lookup of a published passport by GTIN.
///
/// Used by the resolver's `/01/{gtin}` GS1 Digital Link route. Searches by the
/// GTIN embedded in the passport's `qrCodeUrl` field. Only Battery passports
/// (which carry a GTIN) are addressable this way. Returns 404 if no published
/// passport matches.
pub async fn public_read_by_gtin_handler(
    State(state): State<AppState>,
    Path(gtin): Path<String>,
) -> impl IntoResponse {
    match state.service.find_published_by_gtin(&gtin).await {
        Ok(Some(p)) => {
            let full = match serde_json::to_value(&p) {
                Ok(v) => v,
                Err(e) => {
                    return internal_error(dpp_domain::DppError::Serialisation(e.to_string()));
                }
            };
            let mut policy = SectorAccessPolicy::passport_default();
            if let Some(sector_policy) =
                SectorAccessPolicy::from_catalog(catalog(), p.sector.catalog_key())
            {
                policy.field_tiers.extend(sector_policy.field_tiers);
            }
            let decision = filter_by_access_tier(&full, &policy, AccessTier::Public);
            (StatusCode::OK, Json(decision.filtered_data)).into_response()
        }
        Ok(None) => api_error(
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            "No published DPP found for this GTIN.",
        ),
        Err(e) => internal_error(e),
    }
}
