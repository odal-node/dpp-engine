//! `ApiKeyRepository` on PostgreSQL. `key_prefix` is UNIQUE at the schema
//! level (collision gap closed); auth lookups use the partial active index.

use async_trait::async_trait;
use sqlx::Row;
use uuid::Uuid;

use dpp_domain::DppError;
use dpp_types::api_key::{ApiKey, ApiKeyRecord, ApiKeyRepository, ApiKeyScope};

use super::{PgDal, db_err};

/// PostgreSQL implementation of [`ApiKeyRepository`].
///
/// Only the SHA-256 hash of each key is stored; the plaintext is discarded
/// at creation time and is never retrievable from the DB.
pub struct PgApiKeyRepo {
    dal: PgDal,
}

impl PgApiKeyRepo {
    /// Construct a repo sharing the given pool handle.
    pub fn new(dal: PgDal) -> Self {
        Self { dal }
    }

    fn key_from_row(r: &sqlx::postgres::PgRow) -> ApiKey {
        // `scopes TEXT[]` may be NULL for keys written before scopes were
        // enforced; `from_scopes` maps NULL/empty to Admin (pre-scope behaviour).
        let scope = ApiKeyScope::from_scopes(
            &r.try_get::<Option<Vec<String>>, _>("scopes")
                .ok()
                .flatten()
                .unwrap_or_default(),
        );
        ApiKey {
            id: r.get("id"),
            name: r.get("name"),
            key_prefix: r.get("key_prefix"),
            is_active: r.get("is_active"),
            scope,
            created_at: r.get("created_at"),
            last_used_at: r.get("last_used_at"),
            expires_at: r.get("expires_at"),
        }
    }
}

#[async_trait]
impl ApiKeyRepository for PgApiKeyRepo {
    /// List all keys with `is_active = true` regardless of expiry.
    async fn list_active(&self) -> Result<Vec<ApiKey>, DppError> {
        let rows = sqlx::query(
            r#"SELECT id, name, key_prefix, is_active, scopes, created_at, last_used_at, expires_at
               FROM odal.api_key WHERE is_active ORDER BY created_at DESC"#,
        )
        .fetch_all(self.dal.pool())
        .await
        .map_err(db_err)?;
        Ok(rows.iter().map(Self::key_from_row).collect())
    }

    /// Auth hot-path: look up the hash record by prefix via the partial
    /// active index; also enforces expiry — returns `None` for expired keys.
    async fn find_active_by_prefix(&self, prefix: &str) -> Result<Option<ApiKeyRecord>, DppError> {
        let row = sqlx::query(
            r#"SELECT id, name, key_prefix, key_hash, is_active, scopes,
                      created_at, last_used_at, expires_at
               FROM odal.api_key
               WHERE key_prefix = $1 AND is_active
                 AND (expires_at IS NULL OR expires_at > now())"#,
        )
        .bind(prefix)
        .fetch_optional(self.dal.pool())
        .await
        .map_err(db_err)?;
        Ok(row.map(|r| ApiKeyRecord {
            key: Self::key_from_row(&r),
            key_hash: r.get("key_hash"),
        }))
    }

    /// Prefix lookup without active or expiry filter — used to verify a key
    /// exists before revocation.
    async fn find_any_by_prefix(&self, prefix: &str) -> Result<Option<ApiKey>, DppError> {
        let row = sqlx::query(
            r#"SELECT id, name, key_prefix, is_active, scopes, created_at, last_used_at, expires_at
               FROM odal.api_key WHERE key_prefix = $1"#,
        )
        .bind(prefix)
        .fetch_optional(self.dal.pool())
        .await
        .map_err(db_err)?;
        Ok(row.as_ref().map(Self::key_from_row))
    }

    /// Persist a new key record; stores the hash, never the plaintext key.
    async fn create(&self, record: ApiKeyRecord) -> Result<ApiKey, DppError> {
        sqlx::query(
            r#"INSERT INTO odal.api_key
                 (id, name, key_hash, key_prefix, is_active, scopes, created_at, expires_at)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8)"#,
        )
        .bind(record.key.id)
        .bind(&record.key.name)
        .bind(&record.key_hash)
        .bind(&record.key.key_prefix)
        .bind(record.key.is_active)
        .bind(vec![record.key.scope.as_str().to_owned()])
        .bind(record.key.created_at)
        .bind(record.key.expires_at)
        .execute(self.dal.pool())
        .await
        .map_err(db_err)?;
        Ok(record.key)
    }

    /// Set `is_active = false`. Returns `true` if the key existed, `false`
    /// if no matching row was found.
    async fn revoke(&self, id: Uuid) -> Result<bool, DppError> {
        let res = sqlx::query("UPDATE odal.api_key SET is_active = false WHERE id = $1")
            .bind(id)
            .execute(self.dal.pool())
            .await
            .map_err(db_err)?;
        Ok(res.rows_affected() > 0)
    }
}
