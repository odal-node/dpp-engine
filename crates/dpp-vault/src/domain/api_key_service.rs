//! `ApiKeyService` — lifecycle management for operator API keys.

use std::sync::Arc;

use base64::Engine as _;
use chrono::{DateTime, Utc};
use rand::RngCore;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use dpp_domain::domain::error::DppError;
use dpp_types::api_key::{ApiKey, ApiKeyRecord, ApiKeyRepository, ApiKeyScope, NewApiKey};

const KEY_PREFIX: &str = "odal_sk_";
const KEY_ENTROPY_BYTES: usize = 24;

/// Number of leading characters of a secret stored as its lookup prefix.
/// Must be identical on the storage side (here) and the lookup side
/// (`ApiKeyAuthProvider`) — otherwise the exact-match prefix query never hits.
const KEY_PREFIX_LEN: usize = KEY_PREFIX.len() + 4;

/// Derive the indexed lookup prefix from a full API-key secret.
///
/// Both key creation and authentication MUST use this function so the stored
/// prefix and the query prefix always have the same length.
pub fn lookup_prefix(secret: &str) -> String {
    secret.chars().take(KEY_PREFIX_LEN).collect()
}

/// Application service for API key lifecycle: create, list, and revoke.
///
/// Only the SHA-256 hash of each secret is stored — the plaintext is returned
/// once at creation time and never held again.
pub struct ApiKeyService {
    pub repo: Arc<dyn ApiKeyRepository>,
}

impl ApiKeyService {
    /// Construct with the given repository adapter.
    pub fn new(repo: Arc<dyn ApiKeyRepository>) -> Self {
        Self { repo }
    }

    /// Return all active (non-revoked) API keys without secrets.
    pub async fn list(&self) -> Result<Vec<ApiKey>, DppError> {
        self.repo.list_active().await
    }

    /// Generate and persist a new API key, returning the plaintext secret.
    ///
    /// The `secret` field in [`NewApiKey`] is the **only** opportunity to
    /// retrieve the plaintext — it is not stored and cannot be recovered.
    ///
    /// # Errors
    ///
    /// Returns `DppError::Validation` if `name` is blank.
    pub async fn create(
        &self,
        name: &str,
        scope: ApiKeyScope,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<NewApiKey, DppError> {
        let name = name.trim();
        if name.is_empty() {
            return Err(DppError::Validation("API key name is required".into()));
        }

        let secret = generate_secret();
        let key_hash = hex::encode(Sha256::digest(secret.as_bytes()));
        let key_prefix = lookup_prefix(&secret);

        let key = ApiKey {
            id: Uuid::now_v7(),
            name: name.to_owned(),
            key_prefix,
            is_active: true,
            scope,
            created_at: Utc::now(),
            last_used_at: None,
            expires_at,
        };

        let stored = self
            .repo
            .create(ApiKeyRecord {
                key: key.clone(),
                key_hash,
            })
            .await?;

        Ok(NewApiKey {
            key: stored,
            secret,
        })
    }

    /// Revoke a key by id.
    ///
    /// # Errors
    ///
    /// Returns `DppError::NotFound` if `id` does not match an active key.
    pub async fn revoke(&self, id: Uuid) -> Result<(), DppError> {
        let revoked = self.repo.revoke(id).await?;
        if !revoked {
            return Err(DppError::NotFound(id.to_string()));
        }
        Ok(())
    }
}

fn generate_secret() -> String {
    let mut buf = [0u8; KEY_ENTROPY_BYTES];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    let random = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf);
    format!("{KEY_PREFIX}{random}")
}
