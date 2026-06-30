//! Bearer token authentication middleware for the vault's `/api/v1/*` routes.

use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Json, Response},
};
use dpp_common::{event_codes, http_problem};

pub use dpp_types::auth::{AuthContext, AuthError};

use crate::state::AppState;

/// Axum middleware that validates the `Authorization: Bearer` header and injects
/// [`AuthContext`] into request extensions for downstream handlers.
///
/// Rejects with `401 Unauthorized` if the header is missing, the token is
/// invalid, or the token has expired. Returns `403 Forbidden` for a suspended
/// operator — this cannot be overridden by another provider in the chain.
pub async fn auth_middleware(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Response {
    let token = match extract_bearer(&request) {
        Some(t) => t,
        None => {
            metrics::counter!("auth_failures_total", "reason" => "missing").increment(1);
            return unauthorized("Missing or invalid Authorization header.");
        }
    };

    match state.auth_provider.authenticate(&token).await {
        Ok(ctx) => {
            request.extensions_mut().insert(ctx);
            next.run(request).await
        }
        Err(AuthError::Suspended) => {
            metrics::counter!("auth_failures_total", "reason" => "suspended").increment(1);
            http_problem::Problem::new(StatusCode::FORBIDDEN, "Forbidden")
                .with_detail("Operator account is suspended.")
                .into_response()
        }
        Err(e) => {
            metrics::counter!("auth_failures_total", "reason" => "invalid").increment(1);
            tracing::warn!(code = event_codes::AUTH_FAILED, reason = %e, "auth validation failed");
            unauthorized("Invalid or expired token.")
        }
    }
}

fn unauthorized(detail: &str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(axum::http::header::WWW_AUTHENTICATE, "Bearer")],
        Json(
            http_problem::Problem::new(StatusCode::UNAUTHORIZED, "Unauthorized")
                .with_detail(detail),
        ),
    )
        .into_response()
}

fn extract_bearer(request: &Request) -> Option<String> {
    let header = request.headers().get("Authorization")?.to_str().ok()?;
    header.strip_prefix("Bearer ").map(|s| s.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    // F7 regression: 401 responses must carry WWW-Authenticate: Bearer so
    // clients know how to authenticate (RFC 6750 §3).
    #[test]
    fn unauthorized_response_has_www_authenticate_bearer() {
        use axum::http::header::WWW_AUTHENTICATE;
        let resp = unauthorized("test message");
        assert!(
            resp.headers().contains_key(WWW_AUTHENTICATE),
            "401 must include WWW-Authenticate header"
        );
        assert_eq!(
            resp.headers().get(WWW_AUTHENTICATE).unwrap(),
            "Bearer",
            "WWW-Authenticate must be 'Bearer'"
        );
    }
}
