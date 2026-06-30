//! UUIDv7 request-id generation and injection into error response bodies.

use axum::{
    body::Body,
    extract::Request,
    http::{HeaderValue, Response},
    middleware::Next,
    response::IntoResponse,
};
use tower_http::request_id::{MakeRequestId, RequestId};

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
        .is_some_and(|v| v.contains("application/json"));

    if !is_json {
        return response;
    }

    let (parts, body) = response.into_parts();

    let bytes = match axum::body::to_bytes(body, 64 * 1024).await {
        Ok(b) => b,
        Err(_) => return Response::from_parts(parts, Body::empty()),
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
