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

/// Parse a UUID string into a `PassportId`, returning an RFC 7807 400 on failure.
#[allow(clippy::result_large_err)]
pub fn parse_passport_id(s: &str) -> Result<dpp_domain::domain::passport::PassportId, Response> {
    use dpp_domain::domain::passport::PassportId;
    Uuid::parse_str(s)
        .map(PassportId)
        .map_err(|_| http_problem::bad_request("Invalid dppId").into_response())
}

/// Require an admin-scoped credential, or short-circuit with a 403. `action`
/// names the operation being gated (e.g. `"Webhook management"`) and is
/// interpolated into the detail message.
pub fn require_admin(auth: &AuthContext, action: &str) -> Option<Response> {
    if auth.scope.is_admin() {
        None
    } else {
        Some(api_error(
            StatusCode::FORBIDDEN,
            "FORBIDDEN",
            &format!("{action} requires an admin-scoped credential."),
        ))
    }
}

/// Require a write-scoped (or admin) credential, or short-circuit with a 403.
/// `action` names the operation being gated (e.g. `"Creating a passport"`) and
/// is interpolated into the detail message.
pub fn require_write(auth: &AuthContext, action: &str) -> Option<Response> {
    if auth.scope.can_write() {
        None
    } else {
        Some(api_error(
            StatusCode::FORBIDDEN,
            "FORBIDDEN",
            &format!("{action} requires a write-scoped credential."),
        ))
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
        assert!(require_admin(&ctx(ApiKeyScope::Admin), "X").is_none());
        for scope in [ApiKeyScope::Write, ApiKeyScope::Read] {
            let resp = require_admin(&ctx(scope), "X").expect("non-admin must be blocked");
            assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        }
    }

    #[test]
    fn require_write_allows_write_and_admin_scope() {
        assert!(require_write(&ctx(ApiKeyScope::Admin), "X").is_none());
        assert!(require_write(&ctx(ApiKeyScope::Write), "X").is_none());
        let resp = require_write(&ctx(ApiKeyScope::Read), "X").expect("read must be blocked");
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn detail_message_interpolates_the_action() {
        let resp = require_admin(&ctx(ApiKeyScope::Read), "Widget management").unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }
}
