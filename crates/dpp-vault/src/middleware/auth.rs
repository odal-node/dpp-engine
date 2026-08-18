//! Bearer/Basic authentication middleware for the vault's `/api/v1/*` routes.

use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Json, Response},
};
use dpp_common::{event_codes, http_problem};

pub use dpp_types::auth::{AuthContext, AuthError, AuthProvider};

use crate::state::AppState;

/// The two schemes this middleware recognises, and the opaque credential
/// payload each carries (already stripped of the scheme prefix). Kept
/// distinct end to end — see [`route`] for why.
enum Credential {
    Bearer(String),
    Basic(String),
}

/// Axum middleware that validates the `Authorization` header (`Bearer` or
/// `Basic`) and injects [`AuthContext`] into request extensions for
/// downstream handlers.
///
/// Rejects with `401 Unauthorized` if the header is missing or malformed, the
/// scheme is neither `Bearer` nor `Basic`, or the credential is invalid.
/// Returns `403 Forbidden` for a suspended operator — this cannot be
/// overridden by another provider in the chain.
pub async fn auth_middleware(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Response {
    let credential = match extract_credential(&request) {
        Some(c) => c,
        None => {
            metrics::counter!("auth_failures_total", "reason" => "missing").increment(1);
            return unauthorized("Missing or invalid Authorization header.");
        }
    };

    match route(
        credential,
        state.auth_provider.as_ref(),
        state.local_auth_provider.as_deref(),
    )
    .await
    {
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

/// Route a credential to the provider(s) for *its own* scheme — never the
/// other one. A `Bearer` token is only ever tried against `bearer_provider`
/// (API keys, and any future Bearer-scheme provider); a `Basic` credential is
/// only ever tried against `basic_provider` (the local admin bootstrap
/// credential). This is deliberate, not incidental: `LocalAuthProvider`
/// itself just base64-decodes whatever string it is handed, so without this
/// split a `Bearer base64(user:pass)` token would authenticate as admin too.
async fn route(
    credential: Credential,
    bearer_provider: &dyn AuthProvider,
    basic_provider: Option<&dyn AuthProvider>,
) -> Result<AuthContext, AuthError> {
    match credential {
        Credential::Bearer(token) => bearer_provider.authenticate(&token).await,
        Credential::Basic(token) => match basic_provider {
            Some(p) => p.authenticate(&token).await,
            None => Err(AuthError::Invalid(
                "local admin auth is not configured".to_owned(),
            )),
        },
    }
}

fn unauthorized(detail: &str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(axum::http::header::WWW_AUTHENTICATE, "Bearer, Basic")],
        Json(
            http_problem::Problem::new(StatusCode::UNAUTHORIZED, "Unauthorized")
                .with_detail(detail),
        ),
    )
        .into_response()
}

/// Split an `Authorization` header into its scheme and credential.
///
/// The scheme match is **case-insensitive**: RFC 7235 §2.1 defines `auth-scheme`
/// as a case-insensitive token, and several HTTP clients and proxies normalise
/// it to lowercase. Matching `"Bearer "` exactly meant a conforming client
/// sending `authorization: bearer odal_sk_…` got a `401` with
/// `WWW-Authenticate: Bearer, Basic` — an interoperability failure that reads to
/// the caller as an invalid key.
///
/// The credential itself stays byte-exact. Only the scheme token is
/// case-folded, and the split is still on the **first** space, so a credential
/// beginning with whitespace or containing one is unchanged.
fn extract_credential(request: &Request) -> Option<Credential> {
    let header = request.headers().get("Authorization")?.to_str().ok()?;
    let (scheme, credential) = header.split_once(' ')?;
    if scheme.eq_ignore_ascii_case("bearer") {
        return Some(Credential::Bearer(credential.to_owned()));
    }
    if scheme.eq_ignore_ascii_case("basic") {
        return Some(Credential::Basic(credential.to_owned()));
    }
    None
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;

    use super::*;

    // F7 regression: 401 responses must carry a WWW-Authenticate header
    // naming every scheme this middleware accepts (RFC 6750 §3 / RFC 7617).
    #[test]
    fn unauthorized_response_has_www_authenticate_header() {
        use axum::http::header::WWW_AUTHENTICATE;
        let resp = unauthorized("test message");
        assert_eq!(
            resp.headers().get(WWW_AUTHENTICATE).unwrap(),
            "Bearer, Basic"
        );
    }

    #[test]
    fn extract_credential_recognises_bearer_and_basic() {
        let bearer = Request::builder()
            .header("Authorization", "Bearer abc")
            .body(axum::body::Body::empty())
            .unwrap();
        assert!(matches!(
            extract_credential(&bearer),
            Some(Credential::Bearer(t)) if t == "abc"
        ));

        let basic = Request::builder()
            .header("Authorization", "Basic def")
            .body(axum::body::Body::empty())
            .unwrap();
        assert!(matches!(
            extract_credential(&basic),
            Some(Credential::Basic(t)) if t == "def"
        ));

        let none = Request::builder().body(axum::body::Body::empty()).unwrap();
        assert!(extract_credential(&none).is_none());

        let other_scheme = Request::builder()
            .header("Authorization", "Digest xyz")
            .body(axum::body::Body::empty())
            .unwrap();
        assert!(extract_credential(&other_scheme).is_none());
    }

    /// RFC 7235 §2.1: `auth-scheme` is a case-insensitive token, and clients and
    /// proxies do normalise it. Matching `"Bearer "` exactly turned a conforming
    /// request into a 401 that reads as an invalid key.
    #[test]
    fn the_scheme_matches_case_insensitively() {
        for header in ["bearer abc", "BEARER abc", "BeArEr abc"] {
            let req = Request::builder()
                .header("Authorization", header)
                .body(axum::body::Body::empty())
                .unwrap();
            assert!(
                matches!(extract_credential(&req), Some(Credential::Bearer(t)) if t == "abc"),
                "{header:?} must be recognised as Bearer"
            );
        }
        for header in ["basic ZGVm", "BASIC ZGVm"] {
            let req = Request::builder()
                .header("Authorization", header)
                .body(axum::body::Body::empty())
                .unwrap();
            assert!(
                matches!(extract_credential(&req), Some(Credential::Basic(t)) if t == "ZGVm"),
                "{header:?} must be recognised as Basic"
            );
        }
    }

    /// Only the scheme is case-folded. The credential is byte-exact — an API key
    /// and a base64 payload are both case-sensitive, and folding either would
    /// turn a wrong key into a working one.
    #[test]
    fn the_credential_is_not_case_folded_or_trimmed() {
        let req = Request::builder()
            .header("Authorization", "Bearer  AbC ")
            .body(axum::body::Body::empty())
            .unwrap();
        // Split on the FIRST space, so the leading space of the credential and
        // its trailing space both survive.
        assert!(
            matches!(extract_credential(&req), Some(Credential::Bearer(t)) if t == " AbC "),
            "the credential must be passed through byte-exact"
        );
    }

    /// A scheme with no credential is not a credential. `split_once` yields
    /// `None` for a header with no space at all.
    #[test]
    fn a_bare_scheme_is_not_a_credential() {
        for header in ["Bearer", "Basic", ""] {
            let req = Request::builder()
                .header("Authorization", header)
                .body(axum::body::Body::empty())
                .unwrap();
            assert!(
                extract_credential(&req).is_none(),
                "{header:?} must not parse as a credential"
            );
        }
    }

    struct AlwaysFail;

    #[async_trait]
    impl AuthProvider for AlwaysFail {
        async fn authenticate(&self, _: &str) -> Result<AuthContext, AuthError> {
            Err(AuthError::Invalid("nope".to_owned()))
        }
    }

    // The behavior this whole split exists for: a Basic-scheme credential
    // authenticates as local admin, but the identical payload carried as a
    // Bearer token does not — even though `LocalAuthProvider` itself doesn't
    // care what scheme it arrived under.
    #[tokio::test]
    async fn basic_reaches_local_admin_bearer_with_the_same_payload_does_not() {
        use base64::Engine;

        let local = crate::infra::auth::local_provider::LocalAuthProvider::new(
            "alice".to_owned(),
            "secret123".to_owned(),
        );
        let payload = base64::engine::general_purpose::STANDARD.encode("alice:secret123");

        let ok = route(
            Credential::Basic(payload.clone()),
            &AlwaysFail,
            Some(&local),
        )
        .await;
        assert!(
            ok.is_ok(),
            "Basic with valid admin credentials must authenticate"
        );

        let err = route(Credential::Bearer(payload), &AlwaysFail, Some(&local)).await;
        assert!(
            err.is_err(),
            "Bearer carrying the same base64(user:pass) payload must NOT authenticate as admin"
        );
    }

    #[tokio::test]
    async fn basic_with_no_local_provider_configured_is_rejected() {
        let err = route(Credential::Basic("anything".to_owned()), &AlwaysFail, None).await;
        assert!(matches!(err, Err(AuthError::Invalid(_))));
    }
}
