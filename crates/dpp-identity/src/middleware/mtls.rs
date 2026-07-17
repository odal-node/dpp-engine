//! mTLS client-certificate enforcement middleware.
//!
//! In production the TLS terminator (e.g. Nginx, Envoy, or a cloud load
//! balancer) verifies the client certificate and forwards the verified subject
//! distinguished name (DN) in the `X-Client-Cert-Subject` header.  This
//! middleware reads that header, checks that the `CN` component equals the
//! configured allowed common name (default: `odal-vault`), and rejects
//! any request that fails that check when `MTLS_ENFORCE=true`.
//!
//! # Phase-2 work
//!
//! - Support a configurable allow-list of trusted certificate subjects.
//! - When mutual TLS is terminated in-process (Rustls), inspect the
//!   `rustls::ServerConnection` peer certificates directly.
//!
//! # Threat model
//!
//! This gates the standalone identity service's `/internal/sign` and
//! `/internal/keys/rotate` endpoints — the only callers with the authority to
//! produce a JWS signature or rotate an operator's signing key. Only a caller
//! presenting a certificate whose subject `CN` equals `ALLOWED_CN`
//! (`odal-vault`) *and* whose issuer `CN` matches `MTLS_REQUIRED_ISSUER_CN`
//! may reach them — i.e. only the vault service, over a connection the
//! terminating proxy has already verified. In the fused `dpp-node` binary
//! these endpoints aren't mounted at all (signing happens in-process via
//! `LocalIdentityService`), so this layer only matters when identity runs as
//! a separate process; see the crate README for when that's the case.

use axum::{
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use dpp_common::http_problem::Problem;

/// The HTTP header name populated by the TLS-terminating reverse proxy with the
/// verified client certificate subject DN.
pub const CLIENT_CERT_SUBJECT_HEADER: &str = "X-Client-Cert-Subject";

/// The only common name (`CN=`) that is permitted to call internal endpoints.
const ALLOWED_CN: &str = "odal-vault";

/// The HTTP header name populated by the TLS-terminating reverse proxy with the
/// verified client certificate issuer distinguished name (DN).
/// Nginx: `proxy_set_header X-Client-Cert-Issuer $ssl_client_i_dn;`
pub const CLIENT_CERT_ISSUER_HEADER: &str = "X-Client-Cert-Issuer";

/// Read the expected issuer `CN=` from the `MTLS_REQUIRED_ISSUER_CN` env var.
/// Defaults to `"Odal Internal CA"` when the variable is not set.
fn required_issuer_cn() -> String {
    std::env::var("MTLS_REQUIRED_ISSUER_CN").unwrap_or_else(|_| "Odal Internal CA".to_owned())
}

/// Header the terminating proxy sets to prove that *it* — not a client that
/// reached this listener directly — is the origin of the forwarded cert headers.
pub const PROXY_AUTH_HEADER: &str = "X-Proxy-Auth";

/// Constant-time byte comparison, so a wrong secret can't be recovered by timing.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Bind trust in the forwarded `X-Client-Cert-*` headers to the terminating
/// proxy. When `MTLS_PROXY_SHARED_SECRET` is configured, the request must carry
/// a matching [`PROXY_AUTH_HEADER`], so a caller that reaches this listener
/// directly (bypassing the proxy, e.g. a network misconfiguration) cannot forge
/// the cert headers. When the secret is unset, binding is disabled — logged as a
/// warning so the deployment gap is visible rather than silent.
fn proxy_binding_ok(request: &Request) -> bool {
    let secret = match std::env::var("MTLS_PROXY_SHARED_SECRET") {
        Ok(s) if !s.is_empty() => s,
        _ => {
            tracing::warn!(
                "mTLS: MTLS_PROXY_SHARED_SECRET is not set — forwarded client-certificate \
                 headers are trusted without proxy binding (set it in production)"
            );
            return true;
        }
    };
    request
        .headers()
        .get(PROXY_AUTH_HEADER)
        .and_then(|h| h.to_str().ok())
        .is_some_and(|presented| ct_eq(presented.as_bytes(), secret.as_bytes()))
}

/// Extract the value of the `CN=` component from an RFC 4514 subject DN string.
///
/// Matches both `CN=foo` and `cn=foo` (case-insensitive key).
fn extract_cn(subject_dn: &str) -> Option<&str> {
    for part in subject_dn.split(',') {
        let part = part.trim();
        if let Some(value) = part
            .strip_prefix("CN=")
            .or_else(|| part.strip_prefix("cn="))
        {
            return Some(value.trim());
        }
    }
    None
}

/// Enforce mTLS: reject requests that do not carry a verified client certificate
/// subject header, or whose `CN` does not equal `ALLOWED_CN`, when the
/// `MTLS_ENFORCE` environment variable is set to `true`.
pub async fn mtls_middleware(request: Request, next: Next) -> Response {
    // Fail CLOSED by default: the internal signing/rotation endpoints require a
    // verified client identity. Enforcement can only be disabled by explicitly
    // setting `MTLS_ALLOW_INSECURE=true` for local dev/CI. (The fused `dpp-node`
    // does not mount these endpoints at all and signs in-process; this guard is
    // defense-in-depth for the standalone identity service.)
    let allow_insecure = std::env::var("MTLS_ALLOW_INSECURE")
        .map(|v| v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let enforce = !allow_insecure;

    // Before trusting any forwarded cert header, confirm the request actually
    // came through the terminating proxy (when a binding secret is configured).
    if enforce && !proxy_binding_ok(&request) {
        tracing::warn!("mTLS: rejecting request — missing or invalid proxy binding secret");
        return Problem::new(StatusCode::UNAUTHORIZED, "Unauthorized")
            .with_detail("Request did not arrive through the trusted terminating proxy.")
            .into_response();
    }

    match request.headers().get(CLIENT_CERT_SUBJECT_HEADER) {
        Some(subject) => {
            let subject_str = subject.to_str().unwrap_or("<non-utf8>");
            let cn = extract_cn(subject_str);

            tracing::debug!(
                cert_subject = subject_str,
                cert_cn = cn.unwrap_or("<none>"),
                "mTLS client certificate present"
            );

            if enforce {
                match cn {
                    Some(cn) if cn == ALLOWED_CN => {
                        // Subject CN matches.  Now verify the issuer to confirm
                        // the certificate was signed by the Odal internal CA.
                        let expected_issuer = required_issuer_cn();
                        let issuer_valid = request
                            .headers()
                            .get(CLIENT_CERT_ISSUER_HEADER)
                            .and_then(|h| h.to_str().ok())
                            .and_then(|dn| extract_cn(dn))
                            .map(|issuer_cn| issuer_cn == expected_issuer)
                            .unwrap_or(false);

                        if issuer_valid {
                            next.run(request).await
                        } else {
                            tracing::warn!(
                                expected_issuer_cn = %expected_issuer,
                                "mTLS: rejecting request — missing or invalid certificate issuer"
                            );
                            Problem::new(StatusCode::FORBIDDEN, "Forbidden")
                                .with_detail(
                                    "Client certificate issuer is not the Odal internal CA.",
                                )
                                .into_response()
                        }
                    }
                    Some(cn) => {
                        tracing::warn!(
                            cert_cn = cn,
                            allowed_cn = ALLOWED_CN,
                            "mTLS: rejecting request — CN mismatch"
                        );
                        Problem::new(StatusCode::FORBIDDEN, "Forbidden")
                            .with_detail("Client certificate CN is not authorised.")
                            .into_response()
                    }
                    None => {
                        tracing::warn!(
                            cert_subject = subject_str,
                            "mTLS: rejecting request — CN not found in subject DN"
                        );
                        Problem::new(StatusCode::FORBIDDEN, "Forbidden")
                            .with_detail("Client certificate subject does not contain a CN.")
                            .into_response()
                    }
                }
            } else {
                next.run(request).await
            }
        }
        None if enforce => {
            tracing::warn!("mTLS: rejecting request — client certificate required");
            Problem::new(StatusCode::UNAUTHORIZED, "Unauthorized")
                .with_detail("A valid client certificate is required.")
                .into_response()
        }
        None => {
            // Enforcement disabled — allow unauthenticated connections (dev / CI).
            next.run(request).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_cn_from_full_dn() {
        let dn = "CN=odal-vault, O=Odal, C=EU";
        assert_eq!(extract_cn(dn), Some("odal-vault"));
    }

    #[test]
    fn extracts_cn_case_insensitive() {
        let dn = "cn=odal-vault,O=Odal";
        assert_eq!(extract_cn(dn), Some("odal-vault"));
    }

    #[test]
    fn returns_none_when_no_cn() {
        let dn = "O=Odal, C=EU";
        assert_eq!(extract_cn(dn), None);
    }

    #[test]
    fn rejects_wrong_cn() {
        let dn = "CN=evil-service, O=Attacker";
        let cn = extract_cn(dn).unwrap();
        assert_ne!(cn, ALLOWED_CN);
    }
}

/// HTTP-level integration tests — spin up a minimal Axum router and drive it
/// through `tower::ServiceExt::oneshot`.
#[cfg(test)]
mod http_tests {
    use super::*;
    use axum::{Router, body::Body, http::Request, middleware, routing::get};
    use serial_test::serial;
    use tower::ServiceExt;

    // env::set_var/remove_var are unsafe in edition 2024 (process-global, not
    // thread-safe). Sound here: every test is #[serial], so no two run concurrently.

    async fn ok_handler() -> StatusCode {
        StatusCode::OK
    }

    fn build_test_router() -> Router {
        Router::new()
            .route("/test", get(ok_handler))
            .layer(middleware::from_fn(mtls_middleware))
    }

    /// No cert header → 401 (enforcement is on by default via MTLS_ALLOW_INSECURE absence).
    #[tokio::test]
    #[serial]
    async fn missing_cert_returns_401_when_enforced() {
        let response = build_test_router()
            .oneshot(Request::builder().uri("/test").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    /// Correct header present but wrong CN → 403.
    #[tokio::test]
    #[serial]
    async fn wrong_cn_returns_403_when_enforced() {
        let response = build_test_router()
            .oneshot(
                Request::builder()
                    .uri("/test")
                    .header(CLIENT_CERT_SUBJECT_HEADER, "CN=evil-service, O=Attacker")
                    .header(CLIENT_CERT_ISSUER_HEADER, "CN=Odal Internal CA, O=Odal")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    /// Correct CN but unrecognised issuer → 403.
    #[tokio::test]
    #[serial]
    async fn invalid_issuer_returns_403_when_enforced() {
        unsafe { std::env::set_var("MTLS_REQUIRED_ISSUER_CN", "Odal Internal CA") };
        let response = build_test_router()
            .oneshot(
                Request::builder()
                    .uri("/test")
                    .header(CLIENT_CERT_SUBJECT_HEADER, "CN=odal-vault, O=Odal")
                    .header(CLIENT_CERT_ISSUER_HEADER, "CN=Unknown CA, O=Evil")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        unsafe { std::env::remove_var("MTLS_REQUIRED_ISSUER_CN") };
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    /// Proxy secret configured, but the request carries no `X-Proxy-Auth` — even
    /// with otherwise-valid cert headers it is rejected (didn't come via proxy).
    #[tokio::test]
    #[serial]
    async fn proxy_secret_configured_rejects_unbound_request() {
        unsafe { std::env::set_var("MTLS_PROXY_SHARED_SECRET", "s3cr3t") };
        unsafe { std::env::set_var("MTLS_REQUIRED_ISSUER_CN", "Odal Internal CA") };
        let response = build_test_router()
            .oneshot(
                Request::builder()
                    .uri("/test")
                    .header(CLIENT_CERT_SUBJECT_HEADER, "CN=odal-vault, O=Odal")
                    .header(CLIENT_CERT_ISSUER_HEADER, "CN=Odal Internal CA, O=Odal")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        unsafe { std::env::remove_var("MTLS_PROXY_SHARED_SECRET") };
        unsafe { std::env::remove_var("MTLS_REQUIRED_ISSUER_CN") };
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    /// Proxy secret configured and the matching `X-Proxy-Auth` present → 200.
    #[tokio::test]
    #[serial]
    async fn proxy_secret_configured_allows_bound_request() {
        unsafe { std::env::set_var("MTLS_PROXY_SHARED_SECRET", "s3cr3t") };
        unsafe { std::env::set_var("MTLS_REQUIRED_ISSUER_CN", "Odal Internal CA") };
        let response = build_test_router()
            .oneshot(
                Request::builder()
                    .uri("/test")
                    .header(PROXY_AUTH_HEADER, "s3cr3t")
                    .header(CLIENT_CERT_SUBJECT_HEADER, "CN=odal-vault, O=Odal")
                    .header(CLIENT_CERT_ISSUER_HEADER, "CN=Odal Internal CA, O=Odal")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        unsafe { std::env::remove_var("MTLS_PROXY_SHARED_SECRET") };
        unsafe { std::env::remove_var("MTLS_REQUIRED_ISSUER_CN") };
        assert_eq!(response.status(), StatusCode::OK);
    }

    /// Correct CN and correct issuer → 200.
    #[tokio::test]
    #[serial]
    async fn valid_cert_passes_when_enforced() {
        unsafe { std::env::set_var("MTLS_REQUIRED_ISSUER_CN", "Odal Internal CA") };
        let response = build_test_router()
            .oneshot(
                Request::builder()
                    .uri("/test")
                    .header(CLIENT_CERT_SUBJECT_HEADER, "CN=odal-vault, O=Odal")
                    .header(CLIENT_CERT_ISSUER_HEADER, "CN=Odal Internal CA, O=Odal")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        unsafe { std::env::remove_var("MTLS_REQUIRED_ISSUER_CN") };
        assert_eq!(response.status(), StatusCode::OK);
    }
}
