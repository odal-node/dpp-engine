use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use dpp_domain::{Gtin, status::PassportStatus};
use serde::{Deserialize, Serialize};

use crate::public_view::signed_public_view;
use crate::state::AppState;

use super::error::{api_error, internal_error, not_found_error};
use super::public_read::{PublicReadQuery, respond_public_view};

/// What a printed GS1 label carries after its GTIN.
///
/// The resolver forwards the label's AI 10 and AI 21 here rather than dropping
/// them. A GTIN alone does not name one passport once a product has a record
/// per batch or per unit, and the label's own qualifier is what does.
#[derive(Debug, Default, Deserialize, Serialize)]
pub struct LabelQuery {
    /// AI 10, the batch or lot.
    pub batch: Option<String>,
    /// AI 21, the serial.
    pub serial: Option<String>,
}

/// Public, unauthenticated lookup of the passport a printed GS1 label names.
///
/// Used by the resolver's `/01/{gtin}[/10/{batch}][/21/{serial}]` routes. See
/// [`PassportService::resolve_label`](crate::domain::service::PassportService::resolve_label)
/// for which record each label shape resolves to.
///
/// An unknown serial or lot answers with the passport of the level above it, so a
/// `404` means nothing is on record at any level the label carries. The level a
/// label was found at is counted by the service and is not part of the response.
///
/// # Why the lookup ignores status
///
/// Looks up regardless of status and branches here, exactly as the by-id route
/// does. A lookup that only returned published records would fold "no such
/// label" and "that label names a suspended passport" into the same answer, and
/// a suspension is a **recall**: the person scanning the code on a product is
/// precisely who needs to see `410 Gone` rather than a `404` that reads as a
/// bad label. The two routes answer a recall identically.
pub async fn public_read_by_gtin_handler(
    State(state): State<AppState>,
    Path(gtin): Path<String>,
    Query(label): Query<LabelQuery>,
    Query(query): Query<PublicReadQuery>,
) -> impl IntoResponse {
    // Parsed here so the lookup is typed. A malformed GTIN is a malformed
    // request rather than an answer about any product, so it is not a `404`.
    let Ok(gtin) = Gtin::parse(&gtin) else {
        return api_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "INVALID_GTIN",
            "The path segment is not a valid GTIN-14.",
        );
    };
    match state
        .service
        .resolve_label(gtin, label.batch.as_deref(), label.serial.as_deref())
        .await
        .map(|found| found.map(|resolution| resolution.passport))
    {
        // Which states serve is `public_read`'s one rule, applied here too so the
        // two public routes cannot disagree about whether a passport exists.
        Ok(Some(p)) if crate::public_view::serves_publicly(&p.status) => {
            // The same signed payload the by-id route serves: both routes read
            // the one view that was actually signed.
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
        Ok(_) => not_found_error("No published DPP found for this label."),
        Err(e) => internal_error(e),
    }
}
