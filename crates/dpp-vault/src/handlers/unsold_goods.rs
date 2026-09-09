//! `/api/v1/unsold-goods` — the ESPR Art. 24 disclosure record.
//!
//! # What was missing
//!
//! `odal.unsold_goods_report` has been a migrated table since `0008` with no
//! production writer: the only references anywhere were two test files
//! enumerating table names. It is the persistence half of a feature whose write
//! path was never built, so an operator subject to Art. 24 had a schema for the
//! disclosure and no way to put anything in it.
//!
//! # Why these routes are not on a passport
//!
//! There is no digital product passport anywhere in Art. 24 or Art. 25. The
//! subject of Art. 24 is an **operator over a financial year**, its medium is
//! the operator's own website, and its trigger is *discarding unsold stock* —
//! none of which is a product placed on the market. So these sit beside the
//! other operator-scoped routes rather than under `/dpp/{dppId}`, and there is
//! deliberately no `unsold-goods` product group carrying passports.
//!
//! # The one rule worth enforcing here
//!
//! Art. 25 prohibits destroying unsold consumer products in Annex VII from
//! **19 July 2026**. `exemptDestruction` is the destination that records a
//! destruction anyway, under an exemption — so it must say which. Recording one
//! with no justification files a prohibited act as though it were routine, and
//! it is the disclosure itself that would carry the omission.
//!
//! The converse is enforced too: a justification on a donation is refused. It
//! describes nothing, and a field that is sometimes meaningful and sometimes
//! ignored is how a reviewer stops reading it.
//!
//! # What this does not decide
//!
//! Whether the goods fall inside Annex VII at all. That is a CN-code **prefix**
//! test against two code-valued headings, and the products in an unsold-stock
//! line do not arrive here with CN codes attached. `productCategory` is the
//! operator's own categorisation for Art. 24(1)(a), which prescribes no
//! vocabulary — it is not, and must not be read as, Annex VII ban scope.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse as _, Response};
use dpp_types::CreateUnsoldGoodsEntry;
use serde::{Deserialize, Serialize};

use crate::extract::{Json, Query};
use crate::handlers::error::{internal_error, validation_error};
use crate::middleware::scope::{RequireAdmin, RequireWrite};
use crate::state::AppState;

/// Narrow a listing to one reporting period.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListQuery {
    /// Financial year, as `YYYY`. Omit for every period.
    pub reporting_period: Option<String>,
}

/// A financial year, disclosed annually for "the preceding financial year".
fn is_reporting_year(period: &str) -> bool {
    period.len() == 4 && period.chars().all(|c| c.is_ascii_digit())
}

/// Record one Art. 24 disclosure line.
pub async fn unsold_goods_create_handler(
    State(state): State<AppState>,
    RequireWrite(_auth): RequireWrite,
    Json(body): Json<CreateUnsoldGoodsEntry>,
) -> Response {
    if !is_reporting_year(&body.reporting_period) {
        return validation_error(
            "reportingPeriod must be a four-digit financial year, e.g. \"2026\". Art. 24(1) \
             discloses the preceding financial year, annually.",
        );
    }
    if body.unit_count < 0 {
        return validation_error("unitCount cannot be negative.");
    }
    if !body.volume_kg.is_finite() || body.volume_kg < 0.0 {
        return validation_error("volumeKg must be a non-negative number.");
    }
    if body.country_of_disposal.len() != 2
        || !body
            .country_of_disposal
            .chars()
            .all(|c| c.is_ascii_alphabetic())
    {
        return validation_error("countryOfDisposal must be an ISO 3166-1 alpha-2 code.");
    }

    let justification = body
        .destruction_justification
        .as_deref()
        .map(str::trim)
        .filter(|j| !j.is_empty());
    if body.destination.requires_justification() {
        if justification.is_none() {
            return validation_error(
                "destructionJustification is required when destination is \
                 'exemptDestruction'. ESPR Art. 25 prohibits destroying unsold consumer \
                 products in Annex VII from 19 July 2026, so a recorded destruction has to \
                 say which exemption it relies on.",
            );
        }
    } else if justification.is_some() {
        return validation_error(
            "destructionJustification applies only to 'exemptDestruction'. Nothing was \
             destroyed, so there is no exemption to state.",
        );
    }

    // The operator is the node's own, read from its config rather than taken
    // from the request. The report is *about* this operator — supplying it would
    // let a caller file a disclosure in someone else's name, and there is no
    // second operator on a single-tenant node for it to legitimately be.
    let operator = match state
        .operator_service
        .get(dpp_types::STANDALONE_OPERATOR_ID)
        .await
    {
        Ok(cfg) => cfg,
        Err(e) => return internal_error(e),
    };

    let entry = CreateUnsoldGoodsEntry {
        destruction_justification: justification.map(ToOwned::to_owned),
        country_of_disposal: body.country_of_disposal.to_uppercase(),
        ..body
    };

    match state
        .unsold_goods_repo
        .create(
            &entry,
            &operator.operator_id,
            Some(operator.legal_name.as_str()).filter(|n| !n.is_empty()),
        )
        .await
    {
        Ok(row) => (StatusCode::CREATED, Json(row)).into_response(),
        Err(e) => internal_error(e),
    }
}

/// List the disclosure lines, newest first.
///
/// Admin rather than write: these are the operator's own annual figures, and
/// reading them back is an administrative act rather than part of producing
/// passports.
pub async fn unsold_goods_list_handler(
    State(state): State<AppState>,
    RequireAdmin(_auth): RequireAdmin,
    Query(q): Query<ListQuery>,
) -> Response {
    if let Some(period) = q.reporting_period.as_deref()
        && !is_reporting_year(period)
    {
        return validation_error("reportingPeriod must be a four-digit financial year.");
    }
    match state
        .unsold_goods_repo
        .list(q.reporting_period.as_deref())
        .await
    {
        Ok(rows) => Json(rows).into_response(),
        Err(e) => internal_error(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Art. 24(1) discloses a financial *year*, annually. A month or a quarter
    /// would make the annual figures unaddable across rows.
    #[test]
    fn a_reporting_period_is_a_four_digit_year() {
        assert!(is_reporting_year("2026"));
        for bad in ["2026-01", "26", "20268", "Q1-2026", "", "20a6"] {
            assert!(!is_reporting_year(bad), "{bad} must be refused");
        }
    }
}
