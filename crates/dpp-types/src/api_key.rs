//! API key types and repository port.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use dpp_domain::DppError;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Authorization scope granted to an API key (N-2).
///
/// Before scopes, every key was implicitly full-admin: a single leaked key could
/// mint further keys (persistence) and revoke the operator's own keys (lockout).
/// Scopes give operators a least-privilege path for integration/partner keys.
///
/// - `Read`  — read-only access (GET passport/operator/key listings).
/// - `Write` — passport lifecycle (create/update/publish/suspend/archive) but
///   NOT key management or operator-config mutation.
/// - `Admin` — everything, including `/api-keys` and operator-config `PATCH`.
///
/// The default is `Admin` for backward compatibility (pre-scope keys and the
/// bootstrap key remain fully capable). Issue `Write`/`Read` keys to integrations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ApiKeyScope {
    Read,
    Write,
    #[default]
    Admin,
}

impl ApiKeyScope {
    /// Whether this scope authorizes administrative actions: API-key management
    /// (`/api-keys` create/list/revoke) and operator-config mutation.
    #[must_use]
    pub fn is_admin(self) -> bool {
        matches!(self, ApiKeyScope::Admin)
    }

    /// Whether this scope authorizes passport writes (create/update/lifecycle).
    #[must_use]
    pub fn can_write(self) -> bool {
        matches!(self, ApiKeyScope::Write | ApiKeyScope::Admin)
    }

    /// Stable lowercase token used for the `scopes` DB column.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            ApiKeyScope::Read => "read",
            ApiKeyScope::Write => "write",
            ApiKeyScope::Admin => "admin",
        }
    }

    /// Collapse the DB `scopes TEXT[]` array into the effective (highest) scope.
    ///
    /// A NULL/empty array — i.e. a key written before scopes were enforced —
    /// maps to `Admin`, preserving the pre-scope "full access" behaviour. The
    /// service only ever writes a single-element array, but reading the highest
    /// privilege present keeps this robust to manual edits.
    #[must_use]
    pub fn from_scopes(scopes: &[String]) -> Self {
        if scopes.is_empty() || scopes.iter().any(|s| s == "admin") {
            ApiKeyScope::Admin
        } else if scopes.iter().any(|s| s == "write") {
            ApiKeyScope::Write
        } else if scopes.iter().any(|s| s == "read") {
            ApiKeyScope::Read
        } else {
            ApiKeyScope::Admin
        }
    }
}

/// API key metadata as returned by list/get endpoints.
///
/// The plaintext secret is never stored or retrievable after creation;
/// only the prefix (for display/lookup) and a SHA-256 hash (for auth) are kept.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiKey {
    /// Unique identifier for this key.
    pub id: Uuid,
    /// Human-readable name assigned at creation (e.g. `"CI pipeline"`).
    pub name: String,
    /// First 8 characters of the key secret, stored in plain-text for display/lookup.
    pub key_prefix: String,
    /// Whether the key can currently be used for authentication.
    pub is_active: bool,
    /// Authorization scope (N-2). Defaults to `Admin` for pre-scope keys.
    #[serde(default)]
    pub scope: ApiKeyScope,
    /// When the key was issued.
    pub created_at: DateTime<Utc>,
    /// Last successful authentication with this key.
    pub last_used_at: Option<DateTime<Utc>>,
    /// Optional hard expiry after which the key is rejected regardless of `is_active`.
    pub expires_at: Option<DateTime<Utc>>,
}

/// Internal record pairing the public `ApiKey` metadata with its stored hash.
///
/// The hash is the SHA-256 of the full key secret; the secret itself is never
/// stored or retrievable. This type only crosses the DAL boundary — it is never
/// serialised to an API response.
pub struct ApiKeyRecord {
    pub key: ApiKey,
    /// SHA-256 hex of the full key secret.
    pub key_hash: String,
}

/// Response returned when a new key is created — includes the one-time plaintext secret.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NewApiKey {
    /// Key metadata (same shape as what future GET requests return).
    pub key: ApiKey,
    /// The full plaintext key secret. Shown once; store it securely.
    pub secret: String,
}

/// Request body for `POST /api/v1/api-keys`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateApiKeyRequest {
    /// Human-readable name for the key (e.g. `"CI pipeline"`, `"Mobile app"`).
    pub name: String,
    /// Optional hard expiry date. `None` = never expires.
    pub expires_at: Option<DateTime<Utc>>,
    /// Scope to grant (N-2). Omitted = `Admin` (backward compatible). Set
    /// `"write"` or `"read"` for least-privilege integration keys.
    #[serde(default)]
    pub scope: Option<ApiKeyScope>,
}

/// Port trait for API key persistence.
#[async_trait]
pub trait ApiKeyRepository: Send + Sync {
    /// List all active (non-revoked, non-expired) keys.
    async fn list_active(&self) -> Result<Vec<ApiKey>, DppError>;

    /// Look up an active key by its prefix for auth. Returns `None` if no active
    /// key with this prefix exists (expired or revoked keys are excluded).
    async fn find_active_by_prefix(&self, prefix: &str) -> Result<Option<ApiKeyRecord>, DppError>;

    /// Look up a key by prefix regardless of active/expiry status.
    ///
    /// Used only as a diagnostic fallback to distinguish expired vs revoked vs unknown.
    async fn find_any_by_prefix(&self, prefix: &str) -> Result<Option<ApiKey>, DppError>;

    /// Persist a newly-created key record.
    async fn create(&self, record: ApiKeyRecord) -> Result<ApiKey, DppError>;

    /// Revoke a key by id. Returns `true` if the key existed and was revoked.
    async fn revoke(&self, id: Uuid) -> Result<bool, DppError>;
}
