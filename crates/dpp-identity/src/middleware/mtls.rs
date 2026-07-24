//! mTLS enforcement for the standalone identity service's internal endpoints.
//!
//! The implementation is shared: this delegates to [`dpp_common::mtls::enforce`]
//! with the identity signer's expected caller — only the vault (`CN=odal-vault`)
//! may reach `/internal/sign` and `/internal/keys/rotate`. In the fused
//! `dpp-node` binary these endpoints aren't mounted at all (signing happens
//! in-process), so this layer only matters when identity runs as its own
//! process; see the crate README for when that is.

use axum::{extract::Request, middleware::Next, response::Response};

pub use dpp_common::mtls::{
    CLIENT_CERT_ISSUER_HEADER, CLIENT_CERT_SUBJECT_HEADER, PROXY_AUTH_HEADER,
};

/// The only common name permitted to call the identity internal endpoints.
const ALLOWED_CN: &str = "odal-vault";

/// Enforce mTLS for the identity internal endpoints (caller must be the vault).
pub async fn mtls_middleware(request: Request, next: Next) -> Response {
    dpp_common::mtls::enforce(request, next, ALLOWED_CN).await
}
