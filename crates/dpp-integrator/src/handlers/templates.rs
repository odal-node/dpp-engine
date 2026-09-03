//! `GET /api/v1/templates/{product group}` — serve the canonical CSV import template for a product group.

use axum::{
    extract::{Path, Query},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use dpp_common::http_problem;
use serde::{Deserialize, Serialize};

// Templates are embedded at compile time — zero runtime I/O on the hot path.
//
// One table, because this list had three homes and they disagreed: the `match`
// below, a hand-written "Valid values:" sentence inside its own 404, and the API
// description (which named two of the five). Lookup and message now both read
// from here, so adding a template is one edit and the refusal cannot go stale.
const TEMPLATES: &[(&str, &str, &str)] = &[
    (
        "battery",
        include_str!("../../templates/battery-v1.csv"),
        "odal-battery-template.csv",
    ),
    (
        "textile",
        include_str!("../../templates/textile-v1.csv"),
        "odal-textile-template.csv",
    ),
    (
        "steel",
        include_str!("../../templates/steel-v1.csv"),
        "odal-steel-template.csv",
    ),
    (
        "aluminium",
        include_str!("../../templates/aluminium-v1.csv"),
        "odal-aluminium-template.csv",
    ),
    (
        "tyre",
        include_str!("../../templates/tyre-v1.csv"),
        "odal-tyre-template.csv",
    ),
];

/// The product groups this endpoint serves, for the refusal message. Derived,
/// never restated.
fn served_keys() -> String {
    TEMPLATES
        .iter()
        .map(|(k, _, _)| *k)
        .collect::<Vec<_>>()
        .join(", ")
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

    // RFC 7807, like every other error surface here. These two answered a bare
    // string with `text/plain`, while `GET /schemas/{pg}` and
    // `GET /product-groups/{pg}` — same crate, same failure class — already
    // answered `application/problem+json`.
    if format == "xlsx" {
        return http_problem::Problem::new(StatusCode::NOT_IMPLEMENTED, "Not Implemented")
            .with_detail(
                "XLSX template export is not yet available — download the CSV template and                  open it with any spreadsheet application (Excel, LibreOffice Calc, Google                  Sheets).",
            )
            .into_response();
    }

    let Some((_, content, filename)) = TEMPLATES
        .iter()
        .find(|(key, _, _)| *key == product_group.as_str())
    else {
        return http_problem::not_found(format!(
            "No template available for product_group: '{product_group}'. Valid values: {}.",
            served_keys()
        ))
        .into_response();
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

    (StatusCode::OK, headers, *content).into_response()
}

/// Golden-pairing test: each shipped template's own example rows must be
/// accepted by that product group's row validator. Without this, a validator's
/// required-field list can silently drift away from the header set the
/// template actually ships (or vice versa) with nothing catching it.
#[cfg(test)]
mod template_validator_pairing {
    use super::TEMPLATES;
    use crate::domain::{csv_parser, validate};

    /// Every shipped template, driven from the same table the handler serves.
    ///
    /// This was five near-identical tests naming five constants. Iterating the
    /// table instead means a template added to `TEMPLATES` is validated the
    /// moment it is added — the drift the table exists to prevent, closed on the
    /// test side too rather than only on the serving side.
    #[test]
    fn every_shipped_template_passes_its_own_validator() {
        for (product_group, csv, _) in TEMPLATES {
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
    }

    /// The table is the only list; this is what makes "the only" true.
    ///
    /// A template whose key is not a product group the rest of the node knows
    /// would serve a CSV nothing can import. Cheap to assert, and it is the
    /// check that would have caught the key list drifting in the first place.
    #[test]
    fn every_served_key_is_a_known_product_group() {
        let known = dpp_domain::catalog::ProductGroupCatalog::new();
        for (key, _, _) in TEMPLATES {
            assert!(
                known.get(key).is_some(),
                "{key} has a template but is not in the product-group catalog"
            );
        }
    }
}
