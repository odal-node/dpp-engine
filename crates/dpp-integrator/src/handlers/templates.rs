//! `GET /api/v1/templates/{sector}` — serve the canonical CSV import template for a sector.

use axum::{
    extract::{Path, Query},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Deserialize;

// Templates are embedded at compile time — zero runtime I/O on the hot path.
const BATTERY_TEMPLATE: &str = include_str!("../../templates/battery-v1.csv");
const TEXTILE_TEMPLATE: &str = include_str!("../../templates/textile-v1.csv");
const STEEL_TEMPLATE: &str = include_str!("../../templates/steel-v1.csv");
const ALUMINIUM_TEMPLATE: &str = include_str!("../../templates/aluminium-v1.csv");
const TYRE_TEMPLATE: &str = include_str!("../../templates/tyre-v1.csv");

/// Query parameters for the template download endpoint.
#[derive(Debug, Deserialize)]
pub struct TemplateQuery {
    /// Requested format. Accepts `"csv"` (default) or `"xlsx"` (returns 501).
    pub format: Option<String>,
}

/// `GET /api/v1/templates/{sector}[?format=csv|xlsx]`
///
/// Returns the canonical import CSV template for the requested sector.
/// XLSX download is not yet implemented (returns 501).
pub async fn get_template(
    Path(sector): Path<String>,
    Query(query): Query<TemplateQuery>,
) -> Response {
    let format = query.format.as_deref().unwrap_or("csv");

    if format == "xlsx" {
        return (
            StatusCode::NOT_IMPLEMENTED,
            "XLSX template export is not yet available — download the CSV template and open it \
             with any spreadsheet application (Excel, LibreOffice Calc, Google Sheets).",
        )
            .into_response();
    }

    let (content, filename): (&str, &str) = match sector.as_str() {
        "battery" => (BATTERY_TEMPLATE, "odal-battery-template.csv"),
        "textile" => (TEXTILE_TEMPLATE, "odal-textile-template.csv"),
        "steel" => (STEEL_TEMPLATE, "odal-steel-template.csv"),
        "aluminium" => (ALUMINIUM_TEMPLATE, "odal-aluminium-template.csv"),
        "tyre" => (TYRE_TEMPLATE, "odal-tyre-template.csv"),
        _ => {
            return (
                StatusCode::NOT_FOUND,
                format!(
                    "No template available for sector: '{sector}'. Valid values: battery, \
                     textile, steel, aluminium, tyre."
                ),
            )
                .into_response();
        }
    };

    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        "text/csv; charset=utf-8".parse().unwrap(),
    );
    headers.insert(
        header::CONTENT_DISPOSITION,
        format!("attachment; filename=\"{filename}\"")
            .parse()
            .unwrap(),
    );
    headers.insert(
        header::CACHE_CONTROL,
        "max-age=3600, public".parse().unwrap(),
    );

    (StatusCode::OK, headers, content).into_response()
}

/// Golden-pairing test: each shipped template's own example rows must be
/// accepted by that sector's row validator. Without this, a validator's
/// required-field list can silently drift away from the header set the
/// template actually ships (or vice versa) with nothing catching it.
#[cfg(test)]
mod template_validator_pairing {
    use super::{
        ALUMINIUM_TEMPLATE, BATTERY_TEMPLATE, STEEL_TEMPLATE, TEXTILE_TEMPLATE, TYRE_TEMPLATE,
    };
    use crate::domain::{csv_parser, validate};

    fn assert_all_rows_validate(sector: &str, csv: &str) {
        let rows = csv_parser::parse_csv(csv.as_bytes()).expect("template must parse as CSV");
        assert!(!rows.is_empty(), "{sector} template has no example rows");
        for (i, row) in rows.iter().enumerate() {
            let row_num = i + 1;
            if let Err(validate::RowValidationError::Invalid(errs)) =
                validate::validate_row(sector, row, row_num)
            {
                panic!("{sector} template row {row_num} failed validation: {errs:?}");
            }
        }
    }

    #[test]
    fn battery_template_rows_pass_battery_validator() {
        assert_all_rows_validate("battery", BATTERY_TEMPLATE);
    }

    #[test]
    fn textile_template_rows_pass_textile_validator() {
        assert_all_rows_validate("textile", TEXTILE_TEMPLATE);
    }

    #[test]
    fn steel_template_rows_pass_steel_validator() {
        assert_all_rows_validate("steel", STEEL_TEMPLATE);
    }

    #[test]
    fn aluminium_template_rows_pass_aluminium_validator() {
        assert_all_rows_validate("aluminium", ALUMINIUM_TEMPLATE);
    }

    #[test]
    fn tyre_template_rows_pass_tyre_validator() {
        assert_all_rows_validate("tyre", TYRE_TEMPLATE);
    }
}
