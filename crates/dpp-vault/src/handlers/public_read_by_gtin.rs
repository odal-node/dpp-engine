use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
};

use crate::public_view::signed_public_view;
use crate::state::AppState;

use super::error::{api_error, internal_error};
use super::public_read::{PublicReadQuery, respond_public_view};

/// Public, unauthenticated lookup of a published passport by GTIN.
///
/// Used by the resolver's `/01/{gtin}` GS1 Digital Link route. Searches by the
/// GTIN embedded in the passport's `qrCodeUrl` field. Only Battery passports
/// (which carry a GTIN) are addressable this way. Returns 404 if no published
/// passport matches.
pub async fn public_read_by_gtin_handler(
    State(state): State<AppState>,
    Path(gtin): Path<String>,
    Query(query): Query<PublicReadQuery>,
) -> impl IntoResponse {
    match state.service.find_published_by_gtin(&gtin).await {
        Ok(Some(p)) => {
            // Same signed payload the by-id route serves. Previously this
            // handler re-derived the redaction inline, which also skipped
            // `public_view`'s unknown-sector backstop; both routes now read the
            // one view that was actually signed.
            let view = match signed_public_view(&p) {
                Ok(v) => v,
                Err(e) => return internal_error(e),
            };
            respond_public_view(
                view,
                p.sector.catalog_key(),
                &p.schema_version,
                query.schema_view.as_deref(),
            )
        }
        Ok(None) => api_error(
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            "No published DPP found for this GTIN.",
        ),
        Err(e) => internal_error(e),
    }
}
