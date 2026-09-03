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
// One table, because this list had three homes and they disagreed: the lookup,
// a hand-written "Valid values:" sentence inside its own 404, and the API
// description (which named two of the five). Lookup, refusal message and
// `template_for` now all read from here, so adding a template is one edit and
// none of the three can go stale.
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
    (
        "mattress",
        include_str!("../../templates/mattress-v1.csv"),
        "odal-mattress-template.csv",
    ),
    (
        "furniture",
        include_str!("../../templates/furniture-v1.csv"),
        "odal-furniture-template.csv",
    ),
    (
        "toy",
        include_str!("../../templates/toy-v1.csv"),
        "odal-toy-template.csv",
    ),
    (
        "construction",
        include_str!("../../templates/construction-v1.csv"),
        "odal-construction-template.csv",
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

/// The committed CSV template for a product group, or `None` where there is no
/// row validator for it.
///
/// Separate from the handler so the drift test in `domain::validate` can compare
/// each committed header against the columns its validator declares. A template
/// nobody can read from a test is a template nothing can check.
///
/// Reads [`TEMPLATES`] rather than carrying its own `match`. The table exists
/// because this list previously had three homes that disagreed; a second lookup
/// beside it would have re-created the problem the table was introduced to end.
#[must_use]
pub fn template_for(product_group: &str) -> Option<&'static str> {
    TEMPLATES
        .iter()
        .find(|(key, _, _)| *key == product_group)
        .map(|(_, content, _)| *content)
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

#[cfg(test)]
mod template_validator_pairing {
    use super::TEMPLATES;

    /// The table is the only list; this is what makes "the only" true.
    ///
    /// A template whose key is not a product group the rest of the node knows
    /// would serve a CSV nothing can import.
    ///
    /// Kept when its sibling was dropped as duplicated, because this one is not.
    /// `validate`'s `supported_product_groups_and_templates_are_the_same_set`
    /// reads as though it covers this, and does not: it iterates
    /// `SUPPORTED_PRODUCT_GROUPS` and asserts each has a template, which is one
    /// inclusion of the two its name claims. This is the other direction, and it
    /// checks against `dpp-domain`'s catalog rather than the integrator's own
    /// list — so a template keyed to something the domain does not recognise
    /// fails here and nowhere else.
    ///
    /// The row-validation half *was* duplicated, by
    /// `every_template_example_row_passes_its_own_validator`, and is gone.
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
