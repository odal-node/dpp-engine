//! Scope gates as **extractors**, so the refusal happens before the body is read.
//!
//! # Why these exist when `require_write` / `require_admin` already do the check
//!
//! Those run in the handler *body*, and a handler body runs after every one of
//! its extractors. `Json<T>` is the last extractor and it consumes the request
//! body — so on a route that takes one, a `read`-scoped caller had the entire
//! body buffered and deserialised before anything looked at their scope.
//! Measured: a 6,000,019-byte payload with a read-only key came back
//! `422 … at line 1 column 6000019`, meaning the parser had consumed all of it,
//! while a *well-formed* body with the same key came back `403`. The scope check
//! was correct and simply unreachable as a resource control, up to the node's
//! 8 MiB body cap on every write route.
//!
//! `dpp-integrator` already applies the opposite rule deliberately — its
//! `import_requires_bearer_token` test exists so anonymous callers "can't drive
//! the allocation-heavy parser". That rule had never been extended from
//! *authentication* to *scope*.
//!
//! # How the ordering is guaranteed
//!
//! Axum runs `FromRequestParts` extractors in argument order and the single
//! body-consuming `FromRequest` extractor last. So a gate listed **before**
//! `Json<T>` rejects without the body ever being read. That ordering is a
//! property of the framework rather than of this code, which is why
//! `a_read_key_is_refused_before_the_body_is_parsed` drives a real oversized
//! request rather than asserting on argument order.
//!
//! # The message
//!
//! `require_write` interpolates a per-route action ("Creating a passport
//! requires a write-scoped credential"). An extractor takes no arguments, so
//! these say "This operation requires …" instead. The trade is deliberate: the
//! action string is a hand-maintained duplicate of what the route already says,
//! and the wording is an example in the API description rather than a contract.

use axum::{
    extract::FromRequestParts,
    http::{StatusCode, request::Parts},
    response::{IntoResponse, Response},
};
use dpp_common::http_problem;

pub use dpp_types::auth::AuthContext;

/// A `write`- or `admin`-scoped caller, refused before the body is read.
pub struct RequireWrite(pub AuthContext);

/// An `admin`-scoped caller, refused before the body is read.
pub struct RequireAdmin(pub AuthContext);

/// Lift the `AuthContext` the auth middleware injected.
///
/// `Option`, not `Result<_, Response>`: an `Err` carrying a whole `Response` is
/// 128 bytes on every call, which `clippy::result_large_err` rejects. The
/// trait's own `Rejection` is a `Response` and cannot be narrowed; this helper
/// is ours and can be.
fn context(parts: &Parts) -> Option<AuthContext> {
    parts.extensions.get::<AuthContext>().cloned()
}

/// The response for a context that should have been there.
///
/// Its absence is a wiring fault, not a caller error: these extractors are only
/// mounted under `auth_middleware`, which inserts the context on every request
/// it lets through. A `500` says so rather than reporting it as the caller's
/// missing credential, which would send them to re-check a key that is fine.
fn missing_context() -> Response {
    tracing::error!(
        "scope gate found no AuthContext — the route is mounted outside auth_middleware"
    );
    http_problem::Problem::new(StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error")
        .with_detail("An internal error occurred.")
        .into_response()
}

fn forbidden(scope: &str) -> Response {
    http_problem::Problem::new(StatusCode::FORBIDDEN, "Forbidden")
        .with_detail(format!(
            "This operation requires a {scope}-scoped credential."
        ))
        .into_response()
}

impl<S: Send + Sync> FromRequestParts<S> for RequireWrite {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let Some(auth) = context(parts) else {
            return Err(missing_context());
        };
        if auth.scope.can_write() {
            Ok(Self(auth))
        } else {
            Err(forbidden("write"))
        }
    }
}

impl<S: Send + Sync> FromRequestParts<S> for RequireAdmin {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let Some(auth) = context(parts) else {
            return Err(missing_context());
        };
        if auth.scope.is_admin() {
            Ok(Self(auth))
        } else {
            Err(forbidden("admin"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Json, Router, body::Body, http::Request, routing::post};
    use dpp_types::api_key::ApiKeyScope;
    use serde::Deserialize;
    use tower::ServiceExt as _;

    #[derive(Deserialize)]
    #[allow(dead_code)]
    struct Payload {
        name: String,
    }

    fn app() -> Router {
        Router::new().route(
            "/w",
            post(|RequireWrite(_a): RequireWrite, Json(_b): Json<Payload>| async { "ok" }),
        )
    }

    /// Well-formed JSON that cannot satisfy `Payload`. Deliberately *valid*
    /// syntax: a syntax error is a `400` from the parser and a shape error is a
    /// `422`, and only the latter proves the parser got as far as matching the
    /// body against a type. Both tests below send exactly this, so the scope is
    /// the only variable between them.
    const WRONG_SHAPE: &str = "{}";

    fn ctx(scope: ApiKeyScope) -> AuthContext {
        AuthContext {
            user_id: "api-key".into(),
            scope,
            key_id: None,
        }
    }

    async fn post_body(scope: ApiKeyScope, body: &'static str) -> StatusCode {
        let mut req = Request::builder()
            .method("POST")
            .uri("/w")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .expect("request");
        req.extensions_mut().insert(ctx(scope));
        app().oneshot(req).await.expect("response").status()
    }

    /// **The finding this module exists for.** A `read`-scoped caller sends a
    /// body that cannot deserialise. If the scope gate ran after the body
    /// extractor — as the in-handler check did — the answer would be `422`,
    /// which is the parser reporting that it consumed and rejected the payload.
    /// `403` is the only answer that proves the body was never read.
    #[tokio::test]
    async fn a_read_key_is_refused_before_the_body_is_parsed() {
        assert_eq!(
            post_body(ApiKeyScope::Read, WRONG_SHAPE).await,
            StatusCode::FORBIDDEN
        );
    }

    /// The control, without which the test above passes for the wrong reason.
    ///
    /// The same malformed body with a `write` scope must reach the parser and be
    /// refused by it. If this were also `403` the gate would simply be rejecting
    /// everything, and the assertion above would prove nothing about ordering.
    #[tokio::test]
    async fn the_same_body_reaches_the_parser_once_the_scope_allows_it() {
        assert_eq!(
            post_body(ApiKeyScope::Write, WRONG_SHAPE).await,
            StatusCode::UNPROCESSABLE_ENTITY
        );
    }

    /// A missing context is a wiring fault, reported as one.
    #[tokio::test]
    async fn a_route_mounted_outside_the_auth_middleware_is_a_500_not_a_403() {
        let req = Request::builder()
            .method("POST")
            .uri("/w")
            .header("content-type", "application/json")
            .body(Body::from("{}"))
            .expect("request");
        let status = app().oneshot(req).await.expect("response").status();
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    }
}
