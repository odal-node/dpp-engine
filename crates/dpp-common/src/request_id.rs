//! UUIDv7 request-id generation and injection into error response bodies.

use axum::{
    body::Body,
    extract::Request,
    http::{HeaderValue, Response},
    middleware::Next,
    response::IntoResponse,
};
use tower_http::request_id::{MakeRequestId, RequestId};

/// Maximum error-body size buffered to inject `requestId`. Larger bodies are
/// passed through unmodified (the id remains in the `x-request-id` header).
const MAX_INJECT_BYTES: usize = 64 * 1024;

/// Whether a `Content-Type` names a JSON media type: plain `application/json`
/// or any RFC 6839 `+json` structured suffix — including this platform's
/// `application/problem+json` error type, which `contains("application/json")`
/// alone does **not** match.
fn is_json_content_type(content_type: &str) -> bool {
    content_type.contains("application/json") || content_type.contains("+json")
}

/// Generates a UUIDv7-based request ID for `SetRequestIdLayer`.
#[derive(Clone, Default)]
pub struct UuidRequestId;

impl MakeRequestId for UuidRequestId {
    fn make_request_id<B>(&mut self, _: &axum::http::Request<B>) -> Option<RequestId> {
        let id = uuid::Uuid::now_v7().to_string();
        HeaderValue::from_str(&id).ok().map(RequestId::new)
    }
}

/// Middleware that injects the `x-request-id` value into non-2xx JSON response
/// bodies as a `"requestId"` field, enabling support conversations to start
/// with a stable identifier ("what's the request id?").
///
/// Must run AFTER `SetRequestIdLayer` in the request direction (i.e., be
/// added BEFORE it in the `.layer()` call sequence).
pub async fn inject_request_id(request: Request, next: Next) -> impl IntoResponse {
    let request_id = request
        .extensions()
        .get::<RequestId>()
        .and_then(|id| id.header_value().to_str().ok())
        .map(|s| s.to_owned());

    let response = next.run(request).await;

    let Some(id) = request_id else {
        return response;
    };

    // Only inject into non-2xx responses with a JSON content-type.
    if response.status().is_success() {
        return response;
    }

    let is_json = response
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(is_json_content_type);

    if !is_json {
        return response;
    }

    let (parts, body) = response.into_parts();

    // A large error body (e.g. a batch-import validation report) can't be
    // buffered to inject `requestId` without risking unbounded memory. When
    // `Content-Length` already says it exceeds the limit, pass it through
    // unmodified rather than dropping it — the id is still in the `x-request-id`
    // header regardless.
    if parts
        .headers
        .get(axum::http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<usize>().ok())
        .is_some_and(|len| len > MAX_INJECT_BYTES)
    {
        return Response::from_parts(parts, body);
    }

    let bytes = match axum::body::to_bytes(body, MAX_INJECT_BYTES).await {
        Ok(b) => b,
        Err(e) => {
            // A streamed body with no Content-Length that overran the limit; it
            // is consumed and can't be recovered, so return empty — but never
            // silently, so the truncation is visible in logs.
            tracing::warn!(
                error = %e,
                status = %parts.status,
                "error response body exceeded {MAX_INJECT_BYTES} bytes; \
                 requestId not injected and body dropped"
            );
            return Response::from_parts(parts, Body::empty());
        }
    };

    let mut json: serde_json::Value = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(_) => return Response::from_parts(parts, Body::from(bytes.to_vec())),
    };

    if let Some(obj) = json.as_object_mut() {
        obj.insert("requestId".to_owned(), serde_json::Value::String(id));
    }

    let new_body = serde_json::to_vec(&json).unwrap_or_else(|_| bytes.to_vec());
    Response::from_parts(parts, Body::from(new_body))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_content_type_matches_problem_json() {
        assert!(is_json_content_type("application/json"));
        assert!(is_json_content_type("application/json; charset=utf-8"));
        // The platform's actual error media type — the case the old
        // `contains("application/json")` check silently missed.
        assert!(is_json_content_type("application/problem+json"));
        assert!(is_json_content_type(
            "application/problem+json; charset=utf-8"
        ));
        assert!(is_json_content_type("application/ld+json"));
        // Non-JSON must not match.
        assert!(!is_json_content_type("text/html"));
        assert!(!is_json_content_type("text/plain; charset=utf-8"));
    }
}
