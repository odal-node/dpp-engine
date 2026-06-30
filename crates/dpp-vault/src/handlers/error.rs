use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use dpp_common::http_problem::{self, Problem};
use uuid::Uuid;

/// Build an RFC 7807 Problem response.
///
/// The `_code` parameter was the legacy `"error"` JSON field; it is kept for
/// call-site compatibility but discarded — the `type` URI in the Problem object
/// now distinguishes error kinds.
pub fn api_error(status: StatusCode, _code: &str, detail: &str) -> Response {
    Problem::new(status, status.canonical_reason().unwrap_or("Error"))
        .with_detail(detail)
        .into_response()
}

/// Log an unexpected error and return a generic RFC 7807 500.
pub fn internal_error(e: impl std::fmt::Display) -> Response {
    tracing::error!(error = %e, "internal error processing request");
    http_problem::internal_error("An internal error occurred.").into_response()
}

/// Parse a UUID string into a `PassportId`, returning an RFC 7807 400 on failure.
#[allow(clippy::result_large_err)]
pub fn parse_passport_id(s: &str) -> Result<dpp_domain::domain::passport::PassportId, Response> {
    use dpp_domain::domain::passport::PassportId;
    Uuid::parse_str(s)
        .map(PassportId)
        .map_err(|_| http_problem::bad_request("Invalid dppId").into_response())
}
