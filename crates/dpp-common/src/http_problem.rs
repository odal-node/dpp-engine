//! RFC 7807 Problem Details — error response type and shorthand constructors.

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;

/// RFC 7807 Problem Details object.
///
/// Serialises to a JSON body with a `type` URI derived from the `title`.
/// Use [`Problem::new`] to construct, then chain [`Problem::with_detail`] /
/// [`Problem::with_instance`] as needed.
#[derive(Debug, Serialize)]
pub struct Problem {
    /// Absolute URI identifying the problem type
    /// (`https://problems.odal-node.io/<title-slug>`).
    #[serde(rename = "type")]
    pub problem_type: String,
    /// Short human-readable summary of the problem.
    pub title: String,
    /// HTTP status code mirrored in the body for clients that can't read headers.
    pub status: u16,
    /// Human-readable explanation for this specific occurrence.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// URI reference that identifies this specific occurrence.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance: Option<String>,
}

impl Problem {
    /// Construct a Problem with a derived `type` URI and no detail.
    pub fn new(status: StatusCode, title: impl Into<String>) -> Self {
        let title = title.into();
        Self {
            problem_type: format!(
                "https://problems.odal-node.io/{}",
                title.to_lowercase().replace(' ', "-")
            ),
            title,
            status: status.as_u16(),
            detail: None,
            instance: None,
        }
    }

    /// Attach a human-readable explanation for this specific occurrence.
    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    /// Attach a URI reference that identifies this specific occurrence.
    pub fn with_instance(mut self, instance: impl Into<String>) -> Self {
        self.instance = Some(instance.into());
        self
    }
}

impl IntoResponse for Problem {
    fn into_response(self) -> Response {
        let status = StatusCode::from_u16(self.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let mut response = (status, Json(self)).into_response();
        // RFC 7807 §3: the media type is `application/problem+json`, not the
        // `application/json` that Axum's `Json` sets by default.
        response.headers_mut().insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/problem+json"),
        );
        response
    }
}

/// Shorthand constructors for the most common problem responses.
///
/// `404 Not Found` problem with the given detail message.
pub fn not_found(detail: impl Into<String>) -> Problem {
    Problem::new(StatusCode::NOT_FOUND, "Not Found").with_detail(detail)
}

/// `400 Bad Request` problem with the given detail message.
pub fn bad_request(detail: impl Into<String>) -> Problem {
    Problem::new(StatusCode::BAD_REQUEST, "Bad Request").with_detail(detail)
}

/// `500 Internal Server Error` problem with the given detail message.
pub fn internal_error(detail: impl Into<String>) -> Problem {
    Problem::new(StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error").with_detail(detail)
}

/// `422 Unprocessable Entity` problem with the given detail message.
pub fn unprocessable(detail: impl Into<String>) -> Problem {
    Problem::new(StatusCode::UNPROCESSABLE_ENTITY, "Unprocessable Entity").with_detail(detail)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::header::CONTENT_TYPE;

    #[test]
    fn problem_response_uses_problem_json_content_type() {
        let resp = not_found("missing passport").into_response();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            resp.headers()
                .get(CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/problem+json"),
            "RFC 7807 requires the application/problem+json media type"
        );
    }

    #[test]
    fn problem_type_uri_is_derived_from_title() {
        let p = Problem::new(StatusCode::BAD_REQUEST, "Bad Request");
        assert_eq!(p.problem_type, "https://problems.odal-node.io/bad-request");
    }
}
