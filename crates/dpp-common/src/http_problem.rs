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
///
/// # `type` URIs are API surface, not incidental
///
/// Because `problem_type` is derived from `title`, the `title` string passed
/// to [`Problem::new`] at each call site *is* the catalogue key — changing a
/// title changes the `type` URI a client may have started depending on. Once
/// EN 18222 conformance claims are made, treat every distinct `title` used
/// across the codebase as stable API surface, on par with a route path.
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
    /// The individual field failures behind this problem, when there are any.
    ///
    /// RFC 7807 §3.2 permits extension members, and this is one. It exists
    /// because `detail` is a single string and a validation failure is not: a
    /// battery rejected for missing Annex XIII content produces upwards of
    /// thirty distinct field errors, and flattening them into one
    /// semicolon-joined sentence is the difference between a client that can
    /// point at `/productGroupData/batteryModelId` and a human squinting at a
    /// four-thousand-character line.
    ///
    /// `detail` keeps the joined rendering, so a client written against the
    /// older shape is unaffected. Absent for problems that are not about
    /// fields.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<ProblemFieldError>>,
}

/// One field's failure inside a [`Problem`].
///
/// Deliberately a `dpp-common` type rather than a re-export of the domain's
/// `FieldError`: this crate is infrastructure and carries no dependency on
/// `dpp-domain`, and the wire shape should not move when the domain type does.
/// The conversion lives with the caller that owns both.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProblemFieldError {
    /// JSON Pointer (RFC 6901) to the offending member — `/productGroupData/gtin`.
    /// Empty when the failure is about the document as a whole.
    pub field: String,
    /// What is wrong with it, in one sentence.
    pub message: String,
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
            errors: None,
        }
    }

    /// Attach a human-readable explanation for this specific occurrence.
    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    /// Attach the individual field failures behind this problem.
    ///
    /// An empty list is stored as absent rather than as `[]`, so a client can
    /// read "the `errors` member is present" as "there is per-field detail
    /// here" without also having to check its length.
    pub fn with_field_errors(mut self, errors: Vec<ProblemFieldError>) -> Self {
        self.errors = (!errors.is_empty()).then_some(errors);
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

    fn field(f: &str, m: &str) -> ProblemFieldError {
        ProblemFieldError {
            field: f.to_owned(),
            message: m.to_owned(),
        }
    }

    /// The whole point of the extension member: a client can address one field
    /// without parsing a sentence. Pins that `errors` survives serialisation
    /// under that exact name, as an array of `{field, message}`.
    #[test]
    fn field_errors_reach_the_wire_as_an_addressable_array() {
        let p = unprocessable("a; b").with_field_errors(vec![
            field("/productGroupData/batteryModelId", "a"),
            field("/productGroupData/manufacturingDate", "b"),
        ]);
        let v: serde_json::Value = serde_json::to_value(&p).expect("problem serialises");

        let errors = v["errors"].as_array().expect("errors is an array");
        assert_eq!(errors.len(), 2);
        assert_eq!(errors[0]["field"], "/productGroupData/batteryModelId");
        assert_eq!(errors[0]["message"], "a");
        // `detail` keeps the joined rendering — an older client is unaffected.
        assert_eq!(v["detail"], "a; b");
    }

    /// A problem that is not about fields must not grow an empty `errors` key:
    /// a client should be able to read "the member is present" as "there is
    /// per-field detail here" without also checking its length.
    #[test]
    fn a_problem_without_field_errors_omits_the_member_entirely() {
        let plain: serde_json::Value = serde_json::to_value(not_found("no such passport")).unwrap();
        assert!(
            plain.get("errors").is_none(),
            "a field-less problem must omit `errors`, got {plain}"
        );

        let emptied: serde_json::Value =
            serde_json::to_value(unprocessable("x").with_field_errors(vec![])).unwrap();
        assert!(
            emptied.get("errors").is_none(),
            "an empty list must serialise as absent, not as [], got {emptied}"
        );
    }
}
