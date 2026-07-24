//! mTLS client-certificate enforcement, shared by every internal endpoint that
//! must trust only a specific named peer.
//!
//! The model is **proxy-terminated**: the TLS terminator (Caddy, Nginx, Envoy,
//! or a cloud load balancer) verifies the client certificate and forwards the
//! verified subject/issuer DNs in `X-Client-Cert-Subject` / `X-Client-Cert-Issuer`.
//! [`enforce`] reads those, checks the subject `CN` equals the caller's expected
//! `allowed_cn`, checks the issuer `CN` equals `MTLS_REQUIRED_ISSUER_CN` (the
//! Odal internal CA), and binds trust in the forwarded headers to the proxy via
//! an `X-Proxy-Auth` shared secret so a caller reaching the listener directly
//! cannot forge them. It fails **closed** unless `MTLS_ALLOW_INSECURE=true`.
//!
//! Each internal endpoint wraps [`enforce`] with its own expected `CN`
//! (`odal-vault` for the identity signer, `odal-resolver` for scan ingest), so
//! there is one audited implementation and the allow-list is explicit at the
//! call site.
//!
//! In-process Rustls peer-certificate inspection (terminating TLS in the app
//! rather than at a proxy) is a future option; the forwarded-header model is
//! what ships.

use axum::{
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};

use crate::http_problem::Problem;

/// Header the TLS-terminating proxy populates with the verified client
/// certificate subject DN.
pub const CLIENT_CERT_SUBJECT_HEADER: &str = "X-Client-Cert-Subject";

/// Header the TLS-terminating proxy populates with the verified client
/// certificate issuer DN. Nginx: `proxy_set_header X-Client-Cert-Issuer $ssl_client_i_dn;`
pub const CLIENT_CERT_ISSUER_HEADER: &str = "X-Client-Cert-Issuer";

/// Header the terminating proxy sets to prove that *it* — not a client that
/// reached this listener directly — is the origin of the forwarded cert headers.
pub const PROXY_AUTH_HEADER: &str = "X-Proxy-Auth";

/// Read the expected issuer `CN=` from `MTLS_REQUIRED_ISSUER_CN`. Defaults to
/// `"Odal Internal CA"` when unset.
fn required_issuer_cn() -> String {
    std::env::var("MTLS_REQUIRED_ISSUER_CN").unwrap_or_else(|_| "Odal Internal CA".to_owned())
}

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
/// a matching [`PROXY_AUTH_HEADER`]; when it is unset, binding is disabled and a
/// warning is logged so the deployment gap is visible rather than silent.
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

/// Enforce mTLS for one internal endpoint: reject any request that does not carry
/// a proxy-verified client certificate whose subject `CN` equals `allowed_cn` and
/// whose issuer `CN` is the configured internal CA. Fails **closed** unless
/// `MTLS_ALLOW_INSECURE=true` (local dev / CI only).
pub async fn enforce(request: Request, next: Next, allowed_cn: &str) -> Response {
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

            if !enforce {
                return next.run(request).await;
            }

            match cn {
                Some(cn) if cn == allowed_cn => {
                    // Subject CN matches. Now verify the issuer to confirm the
                    // certificate was signed by the Odal internal CA.
                    let expected_issuer = required_issuer_cn();
                    let issuer_valid = request
                        .headers()
                        .get(CLIENT_CERT_ISSUER_HEADER)
                        .and_then(|h| h.to_str().ok())
                        .and_then(extract_cn)
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
                            .with_detail("Client certificate issuer is not the Odal internal CA.")
                            .into_response()
                    }
                }
                Some(cn) => {
                    tracing::warn!(
                        cert_cn = cn,
                        allowed_cn,
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
        }
        None if enforce => {
            tracing::warn!("mTLS: rejecting request — client certificate required");
            Problem::new(StatusCode::UNAUTHORIZED, "Unauthorized")
                .with_detail("A valid client certificate is required.")
                .into_response()
        }
        None => next.run(request).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_cn_from_full_dn() {
        assert_eq!(
            extract_cn("CN=odal-vault, O=Odal, C=EU"),
            Some("odal-vault")
        );
    }

    #[test]
    fn extracts_cn_case_insensitive() {
        assert_eq!(extract_cn("cn=odal-resolver,O=Odal"), Some("odal-resolver"));
    }

    #[test]
    fn returns_none_when_no_cn() {
        assert_eq!(extract_cn("O=Odal, C=EU"), None);
    }

    #[test]
    fn ct_eq_matches_only_identical() {
        assert!(ct_eq(b"secret", b"secret"));
        assert!(!ct_eq(b"secret", b"secreu"));
        assert!(!ct_eq(b"secret", b"secre"));
    }
}
