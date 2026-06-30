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
        "electronics" => {
            return (
                StatusCode::NOT_FOUND,
                "Electronics sector template not yet available.",
            )
                .into_response();
        }
        _ => {
            return (
                StatusCode::NOT_FOUND,
                format!("Unknown sector: '{sector}'. Valid values: battery, textile."),
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
