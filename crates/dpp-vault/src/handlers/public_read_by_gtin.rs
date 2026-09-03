use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use dpp_domain::status::PassportStatus;

use crate::public_view::signed_public_view;
use crate::state::AppState;

use super::error::{api_error, internal_error, not_found_error};
use super::public_read::{PublicReadQuery, respond_public_view};

/// Public, unauthenticated lookup of a passport by GTIN.
///
/// Used by the resolver's `/01/{gtin}` GS1 Digital Link route. Searches by the
/// GTIN embedded in the passport's `qrCodeUrl` field. Only passports carrying a
/// GTIN are addressable this way.
///
/// # Why the lookup ignores status
///
/// Looks up regardless of status and branches here, exactly as the by-id route
/// does. Reading through `find_published_by_gtin` folds "no such GTIN" and
/// "that GTIN resolves to a suspended passport" into the same `None`, and a
/// suspension is a **recall**: the person scanning the code on a product is
/// precisely who needs to see `410 Gone` rather than a `404` that reads as a
/// bad label. The two routes now answer a recall identically.
pub async fn public_read_by_gtin_handler(
    State(state): State<AppState>,
    Path(gtin): Path<String>,
    Query(query): Query<PublicReadQuery>,
) -> impl IntoResponse {
    match state.service.find_by_gtin_any_status(&gtin).await {
        // Deactivated serves too — see the reasoning on `public_read`, which
        // this route must not diverge from: the same passport reached by GTIN
        // rather than by id cannot answer differently.
        Ok(Some(p))
            if p.status == PassportStatus::Published || p.status == PassportStatus::Deactivated =>
        {
            // Same signed payload the by-id route serves. Previously this
            // handler re-derived the redaction inline, which also skipped
            // `public_view`'s unknown-product group backstop; both routes now read the
            // one view that was actually signed.
            let view = match signed_public_view(&p) {
                Ok(v) => v,
                Err(e) => return internal_error(e),
            };
            respond_public_view(
                view,
                p.product_group.catalog_key(),
                &p.schema_version,
                query.schema_view.as_deref(),
            )
        }
        Ok(Some(p)) if p.status == PassportStatus::Suspended => api_error(
            StatusCode::GONE,
            "SUSPENDED",
            "This passport has been suspended.",
        ),
        Ok(_) => not_found_error("No published DPP found for this GTIN."),
        Err(e) => internal_error(e),
    }
}
