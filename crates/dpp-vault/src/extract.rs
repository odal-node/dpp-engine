//! Extractors that refuse in RFC 7807, like the rest of this service.
//!
//! # What was wrong
//!
//! `dpp-common::http_problem::Problem` is the error shape for every HTTP surface
//! here — that is a standing convention, not a preference. But it only ever
//! applied to errors a *handler* raised. A request that failed before the
//! handler ran — malformed JSON, a missing query parameter, the wrong
//! content-type — was refused by axum's own extractor, which answers with a bare
//! string and `content-type: text/plain; charset=utf-8`.
//!
//! So the same route answered two different error formats depending on how far
//! the request got:
//!
//! ```text
//! POST /api/v1/dpp/validate  {}          -> 422 text/plain  "Failed to deserialize the JSON body..."
//! POST /api/v1/dpp/validate  {valid}     -> 422 application/problem+json
//! ```
//!
//! A client cannot parse one shape, and the published API description documents
//! only the second.
//!
//! # What these change, and what they deliberately do not
//!
//! Only the envelope. The status code and the message text are taken from
//! axum's own rejection (`status()` and `body_text()`), so a caller sees the
//! same code and the same words — now inside the document the rest of the API
//! returns. Nothing is re-classified; a syntax error stays `400` and a shape
//! mismatch stays `422`.
//!
//! # Usage
//!
//! Import these in place of `axum::Json` / `axum::extract::Query`. They deref to
//! the same tuple-struct shape, so `Json(body): Json<T>` is unchanged at the
//! call site.

use axum::{
    extract::{FromRequest, FromRequestParts, Request, rejection::JsonRejection},
    http::request::Parts,
    response::{IntoResponse, Response},
};
use dpp_common::http_problem::Problem;
use serde::de::DeserializeOwned;

/// `axum::Json`, refusing in RFC 7807.
///
/// Also implements [`IntoResponse`], because `Json` is used for both halves of a
/// handler here — `Json(body): Json<T>` to read and `Json(value)` to write. A
/// wrapper that only replaced the reading half would have needed a second name
/// and a per-call-site decision about which one to use; being a drop-in means
/// the swap is an import, and nothing at the call sites moves.
pub struct Json<T>(pub T);

impl<T: serde::Serialize> IntoResponse for Json<T> {
    fn into_response(self) -> Response {
        axum::Json(self.0).into_response()
    }
}

/// `axum::extract::Query`, refusing in RFC 7807.
pub struct Query<T>(pub T);

/// Carry axum's own verdict into a problem document.
///
/// The status and the text come from the rejection rather than being restated,
/// so this cannot drift from what axum actually decided — and a future axum that
/// adds a rejection variant is carried automatically instead of falling through
/// a `match` into a wrong code.
fn problem_from(status: axum::http::StatusCode, detail: String) -> Response {
    Problem::new(status, status.canonical_reason().unwrap_or("Error"))
        .with_detail(detail)
        .into_response()
}

impl<T, S> FromRequest<S> for Json<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        match axum::Json::<T>::from_request(req, state).await {
            Ok(axum::Json(value)) => Ok(Self(value)),
            Err(rejection) => Err(json_problem(&rejection)),
        }
    }
}

fn json_problem(rejection: &JsonRejection) -> Response {
    problem_from(rejection.status(), rejection.body_text())
}

/// `Option<Json<T>>` — a body that may legitimately be absent.
///
/// `POST /dpp/{id}/suspend` takes an optional reason, so the absence of a body
/// is not an error there. Delegating to axum's own optional impl keeps "absent"
/// and "present but malformed" told apart exactly as before; only the malformed
/// case changes shape.
impl<T, S> axum::extract::OptionalFromRequest<S> for Json<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request(req: Request, state: &S) -> Result<Option<Self>, Self::Rejection> {
        match <axum::Json<T> as axum::extract::OptionalFromRequest<S>>::from_request(req, state)
            .await
        {
            Ok(Some(axum::Json(value))) => Ok(Some(Self(value))),
            Ok(None) => Ok(None),
            Err(rejection) => Err(json_problem(&rejection)),
        }
    }
}

impl<T, S> FromRequestParts<S> for Query<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        match axum::extract::Query::<T>::from_request_parts(parts, state).await {
            Ok(axum::extract::Query(value)) => Ok(Self(value)),
            Err(rejection) => Err(problem_from(rejection.status(), rejection.body_text())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, body::Body, http::Request as HttpRequest, routing::post};
    use serde::Deserialize;
    use tower::ServiceExt as _;

    #[derive(Deserialize)]
    #[allow(dead_code)]
    struct Payload {
        name: String,
    }

    async fn refuse(
        body: &'static str,
        content_type: &str,
    ) -> (axum::http::StatusCode, String, String) {
        let app = Router::new().route("/j", post(|Json(_): Json<Payload>| async { "ok" }));
        let resp = app
            .oneshot(
                HttpRequest::builder()
                    .method("POST")
                    .uri("/j")
                    .header("content-type", content_type)
                    .body(Body::from(body))
                    .expect("request"),
            )
            .await
            .expect("response");
        let status = resp.status();
        let ct = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .expect("body");
        (status, ct, String::from_utf8_lossy(&bytes).into_owned())
    }

    /// The finding: a body the parser rejects came back as `text/plain`, so a
    /// client had to handle two error formats on one route.
    #[tokio::test]
    async fn a_shape_mismatch_is_refused_as_a_problem_document() {
        let (status, content_type, body) = refuse("{}", "application/json").await;
        assert_eq!(status, axum::http::StatusCode::UNPROCESSABLE_ENTITY);
        assert!(
            content_type.starts_with("application/problem+json"),
            "got {content_type}"
        );
        assert!(body.contains("\"status\":422"), "got {body}");
    }

    /// The status is axum's, not ours — a syntax error is still `400`, so this
    /// change is the envelope and nothing else. If these two ever return the
    /// same code, the mapping has started re-classifying.
    #[tokio::test]
    async fn a_syntax_error_keeps_its_own_status() {
        let (syntax, _, _) = refuse("not json", "application/json").await;
        let (shape, _, _) = refuse("{}", "application/json").await;
        assert_eq!(syntax, axum::http::StatusCode::BAD_REQUEST);
        assert_ne!(syntax, shape, "the two must not collapse to one code");
    }

    /// The wrong content-type is refused before the body is looked at, and is
    /// also a problem document.
    #[tokio::test]
    async fn a_missing_json_content_type_is_a_problem_document_too() {
        let (status, content_type, _) = refuse("{}", "text/plain").await;
        assert_eq!(status, axum::http::StatusCode::UNSUPPORTED_MEDIA_TYPE);
        assert!(
            content_type.starts_with("application/problem+json"),
            "got {content_type}"
        );
    }
}
