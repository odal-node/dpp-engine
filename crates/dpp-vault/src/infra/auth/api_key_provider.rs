//! `ApiKeyAuthProvider` — authenticates `Bearer` tokens against SHA-256 hashes in the DB.

use std::sync::Arc;

use async_trait::async_trait;
use chrono::Utc;
use sha2::{Digest, Sha256};

use dpp_common::event_codes;
use dpp_types::{
    api_key::ApiKeyRepository,
    auth::{AuthContext, AuthError, AuthProvider},
};

/// Auth provider that validates `odal_sk_…` Bearer tokens via SHA-256 hash comparison.
///
/// Only the token hash is stored in the database; the plaintext is never kept
/// after initial creation. Hash comparison uses constant-time equality to
/// prevent timing attacks leaking how many prefix bytes matched.
pub struct ApiKeyAuthProvider {
    repo: Arc<dyn ApiKeyRepository>,
}

impl ApiKeyAuthProvider {
    /// Construct with the given API key repository.
    pub fn new(repo: Arc<dyn ApiKeyRepository>) -> Self {
        Self { repo }
    }
}

#[async_trait]
impl AuthProvider for ApiKeyAuthProvider {
    #[tracing::instrument(skip(self, token), fields(key_prefix = tracing::field::Empty))]
    async fn authenticate(&self, token: &str) -> Result<AuthContext, AuthError> {
        let hash = hex::encode(Sha256::digest(token.as_bytes()));
        let prefix = crate::domain::api_key_service::lookup_prefix(token);
        tracing::Span::current().record("key_prefix", prefix.as_str());

        let record = match self.repo.find_active_by_prefix(&prefix).await {
            Err(e) => return Err(AuthError::Invalid(format!("key lookup failed: {e}"))),
            Ok(Some(r)) => r,
            Ok(None) => {
                // Key not found among active, unexpired keys. Check if it
                // exists at all so we can emit the right audit code.
                match self.repo.find_any_by_prefix(&prefix).await.ok().flatten() {
                    Some(key) if !key.is_active => {
                        tracing::warn!(
                            code = event_codes::AUTH_KEY_REVOKED,
                            key_prefix = %prefix,
                            "revoked API key used"
                        );
                        return Err(AuthError::Invalid("API key has been revoked".to_owned()));
                    }
                    Some(key) if key.expires_at.map(|e| e < Utc::now()).unwrap_or(false) => {
                        tracing::warn!(
                            code = event_codes::AUTH_KEY_EXPIRED,
                            key_prefix = %prefix,
                            "expired API key used"
                        );
                        return Err(AuthError::Invalid("API key has expired".to_owned()));
                    }
                    _ => return Err(AuthError::Invalid("unknown API key".to_owned())),
                }
            }
        };

        // Constant-time comparison of the SHA-256 hashes so the duration of a
        // failed auth does not leak how many leading bytes matched.
        use subtle::ConstantTimeEq;
        let stored = record.key_hash.as_bytes();
        let computed = hash.as_bytes();
        let matches = stored.len() == computed.len() && bool::from(stored.ct_eq(computed));
        if !matches {
            return Err(AuthError::Invalid("invalid API key".to_owned()));
        }

        Ok(AuthContext {
            user_id: "api-key".to_owned(),
            // Carry the key's stored scope so admin-only routes can reject
            // least-privilege keys.
            scope: record.key.scope,
            // Carry the key id so the revoke handler can forbid a key from
            // revoking itself (self-lockout guard).
            key_id: Some(record.key.id),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use dpp_domain::domain::error::DppError;
    use dpp_types::api_key::{ApiKey, ApiKeyRecord};
    use sha2::{Digest, Sha256};
    use uuid::Uuid;

    struct MockRepo {
        // ApiKeyRecord doesn't impl Clone, so store parts separately.
        record: Option<(ApiKey, String)>,
    }

    #[async_trait::async_trait]
    impl dpp_types::api_key::ApiKeyRepository for MockRepo {
        async fn list_active(&self) -> Result<Vec<ApiKey>, DppError> {
            Ok(vec![])
        }

        async fn find_active_by_prefix(
            &self,
            _prefix: &str,
        ) -> Result<Option<ApiKeyRecord>, DppError> {
            Ok(self.record.as_ref().map(|(key, hash)| ApiKeyRecord {
                key: key.clone(),
                key_hash: hash.clone(),
            }))
        }

        async fn find_any_by_prefix(&self, _prefix: &str) -> Result<Option<ApiKey>, DppError> {
            Ok(self.record.as_ref().map(|(key, _)| key.clone()))
        }

        async fn create(&self, _: ApiKeyRecord) -> Result<ApiKey, DppError> {
            unimplemented!()
        }

        async fn revoke(&self, _: Uuid) -> Result<bool, DppError> {
            unimplemented!()
        }
    }

    fn record_for(secret: &str) -> (ApiKey, String) {
        let hash = hex::encode(Sha256::digest(secret.as_bytes()));
        let prefix = crate::domain::api_key_service::lookup_prefix(secret);
        let key = ApiKey {
            id: Uuid::now_v7(),
            name: "k".into(),
            key_prefix: prefix,
            is_active: true,
            scope: dpp_types::api_key::ApiKeyScope::Admin,
            created_at: Utc::now(),
            last_used_at: None,
            expires_at: None,
        };
        (key, hash)
    }

    #[tokio::test]
    async fn valid_key_authenticates() {
        let secret = "odal_sk_testkey000000000000";
        let (key, hash) = record_for(secret);
        let repo = Arc::new(MockRepo {
            record: Some((key, hash)),
        });
        let ctx = ApiKeyAuthProvider::new(repo)
            .authenticate(secret)
            .await
            .unwrap();
        assert_eq!(ctx.user_id, "api-key");
    }

    #[tokio::test]
    async fn wrong_hash_rejected() {
        let secret = "odal_sk_testkey000000000000";
        let (key, _) = record_for(secret);
        let wrong = hex::encode([0u8; 32]);
        let repo = Arc::new(MockRepo {
            record: Some((key, wrong)),
        });
        assert!(matches!(
            ApiKeyAuthProvider::new(repo).authenticate(secret).await,
            Err(AuthError::Invalid(_))
        ));
    }

    #[tokio::test]
    async fn unknown_prefix_rejected() {
        let repo = Arc::new(MockRepo { record: None });
        assert!(matches!(
            ApiKeyAuthProvider::new(repo)
                .authenticate("odal_sk_unknown000000000000")
                .await,
            Err(AuthError::Invalid(_))
        ));
    }
}
