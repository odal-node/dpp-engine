use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use dpp_common::http_problem::{self, Problem};
use uuid::Uuid;

use crate::middleware::auth::AuthContext;

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

/// 404 Not Found — the standard response for a `DppError::NotFound` (or
/// equivalent "no such record") case.
pub fn not_found_error(detail: &str) -> Response {
    api_error(StatusCode::NOT_FOUND, "NOT_FOUND", detail)
}

/// 409 Conflict — the standard response for a `DppError::InvalidTransition`
/// (or other state-conflict) case.
pub fn conflict_error(detail: &str) -> Response {
    api_error(StatusCode::CONFLICT, "CONFLICT", detail)
}

/// 422 Unprocessable Entity — the standard response for a `DppError::Validation` case.
///
/// Prefer [`field_validation_error`] wherever the caller still holds the
/// `ValidationErrors` itself: this one can only produce the joined sentence.
pub fn validation_error(detail: &str) -> Response {
    api_error(StatusCode::UNPROCESSABLE_ENTITY, "VALIDATION_ERROR", detail)
}

/// 422 Unprocessable Entity carrying the per-field failures, not just their
/// joined rendering.
///
/// `ValidationErrors` is a list, and `Display` collapses it with `"; "`. That
/// collapse is lossy in the way that matters: publishing an industrial battery
/// missing its Annex XIII content yields around thirty `FieldError`s, each
/// repeating the same explanatory clause, and the joined string is a single
/// unreadable line no client can index into. `detail` keeps that rendering for
/// compatibility; `errors` carries the structure the domain actually produced.
pub fn field_validation_error(errors: &dpp_domain::ValidationErrors) -> Response {
    problem_with_field_errors(StatusCode::UNPROCESSABLE_ENTITY, errors)
}

/// 409 Conflict carrying per-field failures — the state-conflict twin of
/// [`field_validation_error`], for the paths where a `DppError::Validation`
/// means "the record is in the wrong state" rather than "the input is wrong".
pub fn field_conflict_error(errors: &dpp_domain::ValidationErrors) -> Response {
    problem_with_field_errors(StatusCode::CONFLICT, errors)
}

fn problem_with_field_errors(
    status: StatusCode,
    errors: &dpp_domain::ValidationErrors,
) -> Response {
    Problem::new(status, status.canonical_reason().unwrap_or("Error"))
        .with_detail(errors.to_display())
        .with_field_errors(
            errors
                .errors
                .iter()
                .map(|e| http_problem::ProblemFieldError {
                    field: e.field.clone(),
                    message: e.message.clone(),
                })
                .collect(),
        )
        .into_response()
}

/// Parse a UUID string into a `PassportId`, returning an RFC 7807 400 on failure.
#[allow(clippy::result_large_err)]
pub fn parse_passport_id(s: &str) -> Result<dpp_domain::passport::PassportId, Response> {
    use dpp_domain::passport::PassportId;
    Uuid::parse_str(s)
        .map(PassportId)
        .map_err(|_| http_problem::bad_request("Invalid dppId").into_response())
}

/// Require an admin-scoped credential, or short-circuit with a 403.
///
/// The message is [`crate::middleware::scope::forbidden`]'s, so an in-handler
/// gate and an extractor gate are indistinguishable to a caller. This used to
/// take an `action` to interpolate; see that module on why naming the route in
/// the sentence was twenty duplicates of something the caller already knows.
pub fn require_admin(auth: &AuthContext) -> Option<Response> {
    if auth.scope.is_admin() {
        None
    } else {
        Some(crate::middleware::scope::forbidden("admin"))
    }
}

/// Require a write-scoped (or admin) credential, or short-circuit with a 403.
pub fn require_write(auth: &AuthContext) -> Option<Response> {
    if auth.scope.can_write() {
        None
    } else {
        Some(crate::middleware::scope::forbidden("write"))
    }
}

#[cfg(test)]
mod guard_tests {
    use super::*;
    use dpp_types::api_key::ApiKeyScope;

    fn ctx(scope: ApiKeyScope) -> AuthContext {
        AuthContext {
            user_id: "test".into(),
            scope,
            key_id: None,
        }
    }

    #[test]
    fn require_admin_allows_admin_scope_only() {
        assert!(require_admin(&ctx(ApiKeyScope::Admin)).is_none());
        for scope in [ApiKeyScope::Write, ApiKeyScope::Read] {
            let resp = require_admin(&ctx(scope)).expect("non-admin must be blocked");
            assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        }
    }

    #[test]
    fn require_write_allows_write_and_admin_scope() {
        assert!(require_write(&ctx(ApiKeyScope::Admin)).is_none());
        assert!(require_write(&ctx(ApiKeyScope::Write)).is_none());
        let resp = require_write(&ctx(ApiKeyScope::Read)).expect("read must be blocked");
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    /// The two gates are indistinguishable to a caller.
    ///
    /// A route gated in the handler and a route gated by an extractor answer
    /// the same refusal, byte for byte. They used to answer two different
    /// sentences — one naming the route, one saying "This operation" — which
    /// made one API look like two, and put the naming half in twenty
    /// hand-maintained strings. Comparing them here is what keeps the single
    /// builder single: reintroducing a per-call-site message fails this.
    #[tokio::test]
    async fn both_gates_refuse_in_the_same_words() {
        async fn detail(resp: Response) -> String {
            let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
                .await
                .expect("body");
            serde_json::from_slice::<serde_json::Value>(&bytes).expect("problem document")["detail"]
                .as_str()
                .expect("detail")
                .to_owned()
        }

        let from_helper = detail(require_admin(&ctx(ApiKeyScope::Read)).unwrap()).await;
        let from_extractor = detail(crate::middleware::scope::forbidden("admin")).await;
        assert_eq!(from_helper, from_extractor);
        assert_eq!(
            from_helper,
            "This operation requires an admin-scoped credential."
        );

        let from_helper = detail(require_write(&ctx(ApiKeyScope::Read)).unwrap()).await;
        let from_extractor = detail(crate::middleware::scope::forbidden("write")).await;
        assert_eq!(from_helper, from_extractor);
        assert_eq!(
            from_helper,
            "This operation requires a write-scoped credential."
        );
    }

    #[test]
    fn not_found_error_is_a_404() {
        assert_eq!(not_found_error("x").status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn conflict_error_is_a_409() {
        assert_eq!(conflict_error("x").status(), StatusCode::CONFLICT);
    }

    #[test]
    fn validation_error_is_a_422() {
        assert_eq!(
            validation_error("x").status(),
            StatusCode::UNPROCESSABLE_ENTITY
        );
    }
}
