//! Auth context, error types, and the `AuthProvider` port.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::api_key::ApiKeyScope;

/// Identity of an authenticated caller.
///
/// Single-tenant: there is exactly one operator per node, so the operator is
/// implicit and is **not** carried here. This describes *which user/key* made
/// the request, for audit attribution and (optional) scoping — not *which
/// tenant*. Tenant isolation is an infrastructure boundary (one node per
/// operator), never an in-process discriminator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthContext {
    /// Caller identity — API key id, username, or similar token principal.
    pub user_id: String,
    /// Authorization scope of the credential. Admin Basic auth and
    /// pre-scope API keys are `Admin`; least-privilege keys carry their stored
    /// scope. Handlers for key management and operator config require `Admin`.
    #[serde(default)]
    pub scope: ApiKeyScope,
    /// Id of the API key that authenticated this request, when the caller used a
    /// Bearer API key. `None` for local-admin Basic auth (which has no key row).
    /// Used to forbid a key from revoking *itself* (self-lockout guard).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_id: Option<Uuid>,
}

/// Authentication error returned by `AuthProvider::authenticate`.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    /// No credentials were supplied with the request.
    #[error("missing credentials")]
    Missing,
    /// Credentials were supplied but are unrecognised, expired, or revoked.
    #[error("invalid credentials: {0}")]
    Invalid(String),
    /// The operator account has been suspended by Odal Node operations.
    #[error("operator suspended")]
    Suspended,
}

/// Port trait for authenticating an inbound bearer token.
#[async_trait]
pub trait AuthProvider: Send + Sync {
    /// Parse and validate a raw bearer token, returning the caller's `AuthContext`.
    ///
    /// # Errors
    /// Returns [`AuthError::Missing`] if `token` is empty, [`AuthError::Invalid`]
    /// if the token does not correspond to an active credential, or
    /// [`AuthError::Suspended`] if the operator account is suspended.
    async fn authenticate(&self, token: &str) -> Result<AuthContext, AuthError>;
}
