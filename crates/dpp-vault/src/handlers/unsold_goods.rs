//! `/api/v1/unsold-goods` — the ESPR Art. 24 disclosure, one financial year at
//! a time.
//!
//! # Why these routes are not on a passport
//!
//! There is no digital product passport anywhere in Art. 24 or Art. 25. The
//! subject of Art. 24 is an **operator over a financial year**, its medium is
//! the operator's own website, and its trigger is *discarding unsold stock* —
//! none of which is a product placed on the market. So these sit beside the
//! other operator-scoped routes rather than under `/dpp/{dppId}`, and a
//! disclosure is never signed, sealed, retention-locked or registered.
//!
//! # One disclosure per financial year
//!
//! Commission Implementing Regulation (EU) 2026/2 prescribes the disclosure as
//! a whole: the disclosing entity and its EUID, the financial year, the Annex I
//! table of discarded lines, and the measures taken and planned. The body is
//! dpp-domain's `UnsoldGoodsReport`, and `PUT` stores it as the disclosure for
//! the year that starts on the day the path names, replacing one stored before.
//!
//! # What is checked, and what is only reported
//!
//! The report is refused when it does not match the `unsold-goods` JSON Schema,
//! the same check a passport's product group data gets at publish, or when its
//! financial year does not start on the path's day or end after it starts.
//!
//! The plausibility checks dpp-rules carries for the disclosure (a treatment
//! split that does not total 100, a CN category at the wrong depth, a donation
//! reason claimed beside a stronger one, measures too short to describe
//! anything) are returned with the stored disclosure and refuse nothing, as a
//! passport's lint findings never refuse a publish.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse as _, Response};
use chrono::{NaiveDate, Utc};
use dpp_common::http_problem;
use dpp_domain::lint::LintFinding;
use dpp_domain::{ProductGroup, ProductGroupData, UnsoldGoodsReport};
use dpp_types::UnsoldGoodsDisclosure;
use serde::Serialize;

use crate::domain::service::{catalog, schema_registry};
use crate::extract::Json;
use crate::handlers::error::{
    field_validation_error, internal_error, not_found_error, validation_error,
};
use crate::middleware::scope::{RequireAdmin, RequireWrite};
use crate::state::AppState;

/// What `PUT` answers: the stored disclosure, and what the plausibility checks
/// found in it.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UnsoldGoodsRecorded {
    pub disclosure: UnsoldGoodsDisclosure,
    /// Advisory: none of these refused the disclosure.
    pub lint_findings: Vec<LintFinding>,
}

/// The financial year a path names, by the day it starts.
#[allow(clippy::result_large_err)]
fn financial_year_start(path: &str) -> Result<NaiveDate, Response> {
    NaiveDate::parse_from_str(path, "%Y-%m-%d").map_err(|_| {
        http_problem::bad_request(
            "Invalid financialYearStart: expected the first day of the financial year, \
             as YYYY-MM-DD",
        )
        .into_response()
    })
}

/// The report against the `unsold-goods` JSON Schema.
#[allow(clippy::result_large_err)]
fn check_against_schema(report: &UnsoldGoodsReport) -> Result<(), Response> {
    let key = ProductGroup::UnsoldGoods.catalog_key();
    // The catalog's current version, as the integrator's schema route resolves
    // it, so the schema a client fetches is the one its report is checked by.
    let Some(version) = catalog().current_schema_version(key) else {
        return Err(internal_error(format!(
            "the catalog names no current schema for `{key}`"
        )));
    };
    let data = serde_json::to_value(report).map_err(internal_error)?;
    schema_registry()
        .validate_strict(key, version, &data)
        .map_err(|errors| field_validation_error(&errors))
}

/// Record the disclosure for the financial year that starts on
/// `financialYearStart`, replacing any stored before.
pub async fn unsold_goods_put_handler(
    State(state): State<AppState>,
    RequireWrite(auth): RequireWrite,
    Path(start): Path<String>,
    Json(report): Json<UnsoldGoodsReport>,
) -> Response {
    let start = match financial_year_start(&start) {
        Ok(start) => start,
        Err(response) => return response,
    };
    if report.financial_year.start != start {
        return validation_error(&format!(
            "financialYear.start is {}, but the path names the financial year starting {start}. \
             A disclosure is stored under the year it covers.",
            report.financial_year.start
        ));
    }
    if report.financial_year.end <= report.financial_year.start {
        return validation_error("financialYear.end must be after financialYear.start.");
    }
    if let Err(response) = check_against_schema(&report) {
        return response;
    }

    let lint_findings = dpp_domain::lint_product_group_data(
        &ProductGroupData::UnsoldGoods(report.clone()),
        Utc::now(),
    );
    match state.unsold_goods_repo.put(&report, &auth.user_id).await {
        Ok(disclosure) => (
            StatusCode::OK,
            Json(UnsoldGoodsRecorded {
                disclosure,
                lint_findings,
            }),
        )
            .into_response(),
        Err(e) => internal_error(e),
    }
}

/// The disclosure for the financial year that starts on `financialYearStart`.
///
/// Admin rather than write, like the listing: these are the operator's own
/// annual figures, and reading them back is an administrative act rather than
/// part of producing passports.
pub async fn unsold_goods_get_handler(
    State(state): State<AppState>,
    RequireAdmin(_auth): RequireAdmin,
    Path(start): Path<String>,
) -> Response {
    let start = match financial_year_start(&start) {
        Ok(start) => start,
        Err(response) => return response,
    };
    match state.unsold_goods_repo.get(start).await {
        Ok(Some(disclosure)) => Json(disclosure).into_response(),
        Ok(None) => not_found_error(&format!(
            "No unsold-goods disclosure is stored for the financial year starting {start}."
        )),
        Err(e) => internal_error(e),
    }
}

/// Every stored disclosure, the latest financial year first.
pub async fn unsold_goods_list_handler(
    State(state): State<AppState>,
    RequireAdmin(_auth): RequireAdmin,
) -> Response {
    match state.unsold_goods_repo.list().await {
        Ok(disclosures) => Json(disclosures).into_response(),
        Err(e) => internal_error(e),
    }
}
