//! S3/MinIO adapter implementing `BackupCopyPort` — the ESPR Art. 10(4)
//! back-up copy, held by an Art. 2(32) independent provider. Not ESPR Art. 13,
//! which is the registry.
//!
//! **Not EN 18221 clause 4.2 archiving either — but not because a back-up
//! provider is exempt from it.** Clause 4.2 expects a passport's archived
//! versions to be held by the back-up provider as well as by the main one. It
//! is that this adapter implements a port with no series in it: one key per
//! content hash, `retrieve` answering with one passport. This node's clause 4.2
//! archiving is `ArchivingPassportRepo` in the DAL, and a provider's is the
//! provider's to build.
//!
//! Key scheme: `passports/{passport_id}/{sha256_hex}` — content-addressed, idempotent.
//! Same content → same key. Different content (new version) → different key.
//!
//! # Configuration
//!
//! | Variable                       | Required | Default       |
//! |--------------------------------|----------|---------------|
//! | `BACKUP_S3_BUCKET`            | Yes      | —             |
//! | `BACKUP_S3_ACCESS_KEY_ID`     | Yes      | —             |
//! | `BACKUP_S3_SECRET_ACCESS_KEY` | Yes      | —             |
//! | `BACKUP_S3_ENDPOINT`          | No       | real AWS      |
//! | `BACKUP_S3_REGION`            | No       | `us-east-1`   |
//!
//! Set `BACKUP_S3_ENDPOINT` to a MinIO URL (e.g. `http://localhost:9000`) for
//! local dev. Leave it unset to target real AWS S3, Cloudflare R2, or Hetzner.

use async_trait::async_trait;
use chrono::Utc;
use dpp_domain::{
    error::DppError,
    passport::{Passport, PassportId},
    ports::backup::{BackupCopyPort, BackupReceipt, BackupStatus, BackupVerification},
};

/// Build the back-up adapter from env: the real S3 adapter if the `s3` build
/// feature is enabled and `BACKUP_S3_BUCKET` is set, [`NoOpBackup`] otherwise.
pub fn from_env() -> (
    std::sync::Arc<dyn BackupCopyPort>,
    dpp_types::trust::TrustMode,
) {
    #[cfg(feature = "s3")]
    if let Some(cfg) = S3BackupConfig::from_env() {
        tracing::info!(bucket = %cfg.bucket, "ESPR back-up copy: S3 adapter active");
        return (
            std::sync::Arc::new(S3BackupAdapter::new(cfg)),
            dpp_types::trust::TrustMode::Live,
        );
    }
    tracing::info!(
        "ESPR back-up copy: no-op — set BACKUP_S3_BUCKET (and build with --features s3) to enable"
    );
    (
        std::sync::Arc::new(NoOpBackup),
        dpp_types::trust::TrustMode::Ghost,
    )
}

#[cfg(feature = "s3")]
use aws_sdk_s3::{
    Client,
    config::{BehaviorVersion, Builder as ConfigBuilder, Credentials, Region},
    primitives::ByteStream,
};
#[cfg(feature = "s3")]
use sha2::{Digest, Sha256};

// ─── Config ──────────────────────────────────────────────────────────────────

#[cfg(feature = "s3")]
pub struct S3BackupConfig {
    pub endpoint: Option<String>,
    pub bucket: String,
    pub access_key_id: String,
    pub secret_access_key: String,
    pub region: String,
}

#[cfg(feature = "s3")]
impl S3BackupConfig {
    /// Load from env vars. Returns `None` if `BACKUP_S3_BUCKET` is absent or empty.
    pub fn from_env() -> Option<Self> {
        let bucket = std::env::var("BACKUP_S3_BUCKET")
            .ok()
            .filter(|s| !s.is_empty())?;
        let access_key_id = std::env::var("BACKUP_S3_ACCESS_KEY_ID")
            .ok()
            .filter(|s| !s.is_empty())?;
        let secret_access_key = std::env::var("BACKUP_S3_SECRET_ACCESS_KEY")
            .ok()
            .filter(|s| !s.is_empty())?;
        let endpoint = std::env::var("BACKUP_S3_ENDPOINT")
            .ok()
            .filter(|s| !s.is_empty());
        let region = std::env::var("BACKUP_S3_REGION").unwrap_or_else(|_| "us-east-1".into());
        Some(Self {
            endpoint,
            bucket,
            access_key_id,
            secret_access_key,
            region,
        })
    }
}

// ─── Adapter ─────────────────────────────────────────────────────────────────

#[cfg(feature = "s3")]
pub struct S3BackupAdapter {
    client: Client,
    bucket: String,
}

#[cfg(feature = "s3")]
impl S3BackupAdapter {
    pub fn new(cfg: S3BackupConfig) -> Self {
        let credentials = Credentials::new(
            cfg.access_key_id,
            cfg.secret_access_key,
            None,
            None,
            "static",
        );

        let mut builder = ConfigBuilder::new()
            .credentials_provider(credentials)
            .region(Region::new(cfg.region))
            .behavior_version(BehaviorVersion::latest());

        if let Some(endpoint) = cfg.endpoint {
            // Path-style is required for MinIO and most S3-compatible stores.
            builder = builder.endpoint_url(endpoint).force_path_style(true);
        }

        Self {
            client: Client::from_conf(builder.build()),
            bucket: cfg.bucket,
        }
    }

    /// Create the bucket if it does not already exist. Call once at startup.
    pub async fn ensure_bucket(&self) -> Result<(), DppError> {
        match self
            .client
            .create_bucket()
            .bucket(&self.bucket)
            .send()
            .await
        {
            Ok(_) => Ok(()),
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("BucketAlreadyOwnedByYou") || msg.contains("BucketAlreadyExists") {
                    Ok(())
                } else {
                    Err(DppError::Internal(format!("S3 bucket init failed: {e}")))
                }
            }
        }
    }

    fn hash(passport: &Passport) -> Result<(Vec<u8>, String), DppError> {
        let bytes =
            serde_json::to_vec(passport).map_err(|e| DppError::Serialisation(e.to_string()))?;
        let hash = hex::encode(Sha256::digest(&bytes));
        Ok((bytes, hash))
    }

    fn object_key(passport_id: PassportId, hash: &str) -> String {
        format!("passports/{passport_id}/{hash}")
    }

    async fn put(&self, key: &str, bytes: Vec<u8>) -> Result<(), DppError> {
        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(key)
            .body(ByteStream::from(bytes))
            .content_type("application/json")
            .send()
            .await
            .map_err(|e| DppError::Internal(format!("S3 PUT failed: {e}")))?;
        Ok(())
    }
}

#[cfg(feature = "s3")]
#[async_trait]
impl BackupCopyPort for S3BackupAdapter {
    async fn store(
        &self,
        passport: &Passport,
        retention_years: u32,
    ) -> Result<BackupReceipt, DppError> {
        let (bytes, hash) = Self::hash(passport)?;
        let key = Self::object_key(passport.id, &hash);
        self.put(&key, bytes).await?;

        let now = Utc::now();
        Ok(BackupReceipt {
            backup_id: key,
            passport_id: passport.id,
            content_hash: hash,
            stored_at: now,
            retention_until: now + chrono::Duration::days(365 * retention_years as i64),
        })
    }

    async fn update(&self, passport: &Passport) -> Result<BackupReceipt, DppError> {
        // New content → new hash → new key. All versions coexist in the bucket
        // (append-only store). `retrieve()` returns the most recently written.
        let (bytes, hash) = Self::hash(passport)?;
        let key = Self::object_key(passport.id, &hash);
        self.put(&key, bytes).await?;

        let now = Utc::now();
        Ok(BackupReceipt {
            backup_id: key,
            passport_id: passport.id,
            content_hash: hash,
            stored_at: now,
            retention_until: now + chrono::Duration::days(365 * 10),
        })
    }

    async fn verify(
        &self,
        passport_id: PassportId,
        expected_hash: &str,
    ) -> Result<BackupVerification, DppError> {
        let key = Self::object_key(passport_id, expected_hash);
        let exists = self
            .client
            .head_object()
            .bucket(&self.bucket)
            .key(&key)
            .send()
            .await
            .is_ok();

        Ok(BackupVerification {
            integrity_ok: exists,
            accessible: exists,
            status: if exists {
                BackupStatus::Active
            } else {
                BackupStatus::Expired
            },
            last_verified_at: Utc::now(),
        })
    }

    async fn retrieve(&self, passport_id: PassportId) -> Result<Option<Passport>, DppError> {
        let prefix = format!("passports/{passport_id}/");

        let list = self
            .client
            .list_objects_v2()
            .bucket(&self.bucket)
            .prefix(&prefix)
            .send()
            .await
            .map_err(|e| DppError::Internal(format!("S3 LIST failed: {e}")))?;

        let objects = list.contents.unwrap_or_default();

        // Pick the most recently written version.
        let key = objects
            .iter()
            .filter_map(|o| o.key.as_deref().zip(o.last_modified.as_ref()))
            .max_by_key(|(_, ts)| ts.secs())
            .map(|(k, _)| k.to_owned());

        let Some(key) = key else {
            return Ok(None);
        };

        let resp = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(&key)
            .send()
            .await
            .map_err(|e| DppError::Internal(format!("S3 GET failed: {e}")))?;

        let data = resp
            .body
            .collect()
            .await
            .map_err(|e| DppError::Internal(format!("S3 body read failed: {e}")))?
            .into_bytes();

        let passport: Passport = serde_json::from_slice(&data)
            .map_err(|e| DppError::Serialisation(format!("corrupt back-up record: {e}")))?;

        Ok(Some(passport))
    }
}

// ─── NoOp fallback ───────────────────────────────────────────────────────────

/// Used when `BACKUP_S3_BUCKET` is not configured (dev / CI without object storage).
/// Logs a warning on every back-up call and returns a stub receipt.
pub struct NoOpBackup;

#[async_trait]
impl BackupCopyPort for NoOpBackup {
    async fn store(
        &self,
        passport: &Passport,
        _retention_years: u32,
    ) -> Result<BackupReceipt, DppError> {
        tracing::warn!(
            passport_id = %passport.id,
            "ESPR back-up copy skipped — BACKUP_S3_BUCKET not configured"
        );
        Ok(BackupReceipt {
            backup_id: "no-op".into(),
            passport_id: passport.id,
            content_hash: String::new(),
            stored_at: Utc::now(),
            retention_until: Utc::now() + chrono::Duration::days(365 * 10),
        })
    }

    async fn update(&self, passport: &Passport) -> Result<BackupReceipt, DppError> {
        tracing::warn!(
            passport_id = %passport.id,
            "ESPR back-up refresh skipped — BACKUP_S3_BUCKET not configured"
        );
        Ok(BackupReceipt {
            backup_id: "no-op".into(),
            passport_id: passport.id,
            content_hash: String::new(),
            stored_at: Utc::now(),
            retention_until: Utc::now() + chrono::Duration::days(365 * 10),
        })
    }

    async fn verify(
        &self,
        _passport_id: PassportId,
        _expected_hash: &str,
    ) -> Result<BackupVerification, DppError> {
        Ok(BackupVerification {
            integrity_ok: false,
            accessible: false,
            status: BackupStatus::Expired,
            last_verified_at: Utc::now(),
        })
    }

    async fn retrieve(&self, _passport_id: PassportId) -> Result<Option<Passport>, DppError> {
        Ok(None)
    }
}
