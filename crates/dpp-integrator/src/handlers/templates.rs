//! `GET /api/v1/templates/{product group}` — serve the canonical CSV import template for a product group.

use axum::{
    extract::{Path, Query},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};

use crate::domain::validate;

// Templates are embedded at compile time — zero runtime I/O on the hot path.
const BATTERY_TEMPLATE: &str = include_str!("../../templates/battery-v1.csv");
const TEXTILE_TEMPLATE: &str = include_str!("../../templates/textile-v1.csv");
const STEEL_TEMPLATE: &str = include_str!("../../templates/steel-v1.csv");
const ALUMINIUM_TEMPLATE: &str = include_str!("../../templates/aluminium-v1.csv");
const TYRE_TEMPLATE: &str = include_str!("../../templates/tyre-v1.csv");
const MATTRESS_TEMPLATE: &str = include_str!("../../templates/mattress-v1.csv");
const FURNITURE_TEMPLATE: &str = include_str!("../../templates/furniture-v1.csv");
const TOY_TEMPLATE: &str = include_str!("../../templates/toy-v1.csv");
const CONSTRUCTION_TEMPLATE: &str = include_str!("../../templates/construction-v1.csv");

/// The committed CSV template for a product group, or `None` where there is no
/// row validator for it.
///
/// Separate from the handler so the drift test in `domain::validate` can compare
/// each committed header against the columns its validator declares. A template
/// nobody can read from a test is a template nothing can check.
#[must_use]
pub fn template_for(product_group: &str) -> Option<&'static str> {
    match product_group {
        "battery" => Some(BATTERY_TEMPLATE),
        "textile" => Some(TEXTILE_TEMPLATE),
        "steel" => Some(STEEL_TEMPLATE),
        "aluminium" => Some(ALUMINIUM_TEMPLATE),
        "tyre" => Some(TYRE_TEMPLATE),
        "mattress" => Some(MATTRESS_TEMPLATE),
        "furniture" => Some(FURNITURE_TEMPLATE),
        "toy" => Some(TOY_TEMPLATE),
        "construction" => Some(CONSTRUCTION_TEMPLATE),
        _ => None,
    }
}

/// Query parameters for the template download endpoint.
#[derive(Debug, Deserialize, Serialize)]
pub struct TemplateQuery {
    /// Requested format. Accepts `"csv"` (default) or `"xlsx"` (returns 501).
    pub format: Option<String>,
}

/// `GET /api/v1/templates/{product group}[?format=csv|xlsx]`
///
/// Returns the canonical import CSV template for the requested product group.
/// XLSX download is not yet implemented (returns 501).
pub async fn get_template(
    Path(product_group): Path<String>,
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

    let Some(content) = template_for(&product_group) else {
        return (
            StatusCode::NOT_FOUND,
            format!(
                "No template available for product_group: '{product_group}'. Valid values: {}.",
                validate::SUPPORTED_PRODUCT_GROUPS.join(", ")
            ),
        )
            .into_response();
    };
    let filename = format!("odal-{product_group}-template.csv");

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
/// accepted by that product group's row validator. Without this, a validator's
/// required-field list can silently drift away from the header set the
/// template actually ships (or vice versa) with nothing catching it.
#[cfg(test)]
mod template_validator_pairing {
    use super::{
        ALUMINIUM_TEMPLATE, BATTERY_TEMPLATE, STEEL_TEMPLATE, TEXTILE_TEMPLATE, TYRE_TEMPLATE,
    };
    use crate::domain::{csv_parser, validate};

    fn assert_all_rows_validate(product_group: &str, csv: &str) {
        let rows = csv_parser::parse_csv(csv.as_bytes()).expect("template must parse as CSV");
        assert!(
            !rows.is_empty(),
            "{product_group} template has no example rows"
        );
        for (i, row) in rows.iter().enumerate() {
            let row_num = i + 1;
            if let Err(validate::RowValidationError::Invalid(errs)) =
                validate::validate_row(product_group, row, row_num)
            {
                panic!("{product_group} template row {row_num} failed validation: {errs:?}");
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
