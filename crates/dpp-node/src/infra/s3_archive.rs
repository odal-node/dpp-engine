//! S3/MinIO adapter implementing `ArchivePort` for ESPR Art. 13 DPP archival.
//!
//! Key scheme: `passports/{passport_id}/{sha256_hex}` — content-addressed, idempotent.
//! Same content → same key. Different content (new version) → different key.
//!
//! # Configuration
//!
//! | Variable                       | Required | Default       |
//! |--------------------------------|----------|---------------|
//! | `ARCHIVE_S3_BUCKET`            | Yes      | —             |
//! | `ARCHIVE_S3_ACCESS_KEY_ID`     | Yes      | —             |
//! | `ARCHIVE_S3_SECRET_ACCESS_KEY` | Yes      | —             |
//! | `ARCHIVE_S3_ENDPOINT`          | No       | real AWS      |
//! | `ARCHIVE_S3_REGION`            | No       | `us-east-1`   |
//!
//! Set `ARCHIVE_S3_ENDPOINT` to a MinIO URL (e.g. `http://localhost:9000`) for
//! local dev. Leave it unset to target real AWS S3, Cloudflare R2, or Hetzner.

use async_trait::async_trait;
use aws_sdk_s3::{
    Client,
    config::{BehaviorVersion, Builder as ConfigBuilder, Credentials, Region},
    primitives::ByteStream,
};
use chrono::Utc;
use dpp_domain::{
    domain::{
        error::DppError,
        passport::{Passport, PassportId},
    },
    ports::archive::{ArchivePort, ArchiveReceipt, ArchiveStatus, ArchiveVerification},
};
use sha2::{Digest, Sha256};

// ─── Config ──────────────────────────────────────────────────────────────────

pub struct S3ArchiveConfig {
    pub endpoint: Option<String>,
    pub bucket: String,
    pub access_key_id: String,
    pub secret_access_key: String,
    pub region: String,
}

impl S3ArchiveConfig {
    /// Load from env vars. Returns `None` if `ARCHIVE_S3_BUCKET` is absent or empty.
    pub fn from_env() -> Option<Self> {
        let bucket = std::env::var("ARCHIVE_S3_BUCKET")
            .ok()
            .filter(|s| !s.is_empty())?;
        let access_key_id = std::env::var("ARCHIVE_S3_ACCESS_KEY_ID")
            .ok()
            .filter(|s| !s.is_empty())?;
        let secret_access_key = std::env::var("ARCHIVE_S3_SECRET_ACCESS_KEY")
            .ok()
            .filter(|s| !s.is_empty())?;
        let endpoint = std::env::var("ARCHIVE_S3_ENDPOINT")
            .ok()
            .filter(|s| !s.is_empty());
        let region = std::env::var("ARCHIVE_S3_REGION").unwrap_or_else(|_| "us-east-1".into());
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

pub struct S3ArchiveAdapter {
    client: Client,
    bucket: String,
}

impl S3ArchiveAdapter {
    pub fn new(cfg: S3ArchiveConfig) -> Self {
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

#[async_trait]
impl ArchivePort for S3ArchiveAdapter {
    async fn archive(
        &self,
        passport: &Passport,
        retention_years: u32,
    ) -> Result<ArchiveReceipt, DppError> {
        let (bytes, hash) = Self::hash(passport)?;
        let key = Self::object_key(passport.id, &hash);
        self.put(&key, bytes).await?;

        let now = Utc::now();
        Ok(ArchiveReceipt {
            archive_id: key,
            passport_id: passport.id,
            content_hash: hash,
            archived_at: now,
            retention_until: now + chrono::Duration::days(365 * retention_years as i64),
        })
    }

    async fn update_archive(&self, passport: &Passport) -> Result<ArchiveReceipt, DppError> {
        // New content → new hash → new key. All versions coexist in the bucket
        // (append-only archive). `retrieve()` returns the most recently written.
        let (bytes, hash) = Self::hash(passport)?;
        let key = Self::object_key(passport.id, &hash);
        self.put(&key, bytes).await?;

        let now = Utc::now();
        Ok(ArchiveReceipt {
            archive_id: key,
            passport_id: passport.id,
            content_hash: hash,
            archived_at: now,
            retention_until: now + chrono::Duration::days(365 * 10),
        })
    }

    async fn verify(
        &self,
        passport_id: PassportId,
        expected_hash: &str,
    ) -> Result<ArchiveVerification, DppError> {
        let key = Self::object_key(passport_id, expected_hash);
        let exists = self
            .client
            .head_object()
            .bucket(&self.bucket)
            .key(&key)
            .send()
            .await
            .is_ok();

        Ok(ArchiveVerification {
            integrity_ok: exists,
            accessible: exists,
            status: if exists {
                ArchiveStatus::Active
            } else {
                ArchiveStatus::Expired
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
            .map_err(|e| DppError::Serialisation(format!("corrupt archive record: {e}")))?;

        Ok(Some(passport))
    }
}

// ─── NoOp fallback ───────────────────────────────────────────────────────────

/// Used when `ARCHIVE_S3_BUCKET` is not configured (dev / CI without object storage).
/// Logs a warning on every archive call and returns a stub receipt.
pub struct NoOpArchive;

#[async_trait]
impl ArchivePort for NoOpArchive {
    async fn archive(
        &self,
        passport: &Passport,
        _retention_years: u32,
    ) -> Result<ArchiveReceipt, DppError> {
        tracing::warn!(
            passport_id = %passport.id,
            "ESPR archive skipped — ARCHIVE_S3_BUCKET not configured"
        );
        Ok(ArchiveReceipt {
            archive_id: "no-op".into(),
            passport_id: passport.id,
            content_hash: String::new(),
            archived_at: Utc::now(),
            retention_until: Utc::now() + chrono::Duration::days(365 * 10),
        })
    }

    async fn update_archive(&self, passport: &Passport) -> Result<ArchiveReceipt, DppError> {
        tracing::warn!(
            passport_id = %passport.id,
            "ESPR archive update skipped — ARCHIVE_S3_BUCKET not configured"
        );
        Ok(ArchiveReceipt {
            archive_id: "no-op".into(),
            passport_id: passport.id,
            content_hash: String::new(),
            archived_at: Utc::now(),
            retention_until: Utc::now() + chrono::Duration::days(365 * 10),
        })
    }

    async fn verify(
        &self,
        _passport_id: PassportId,
        _expected_hash: &str,
    ) -> Result<ArchiveVerification, DppError> {
        Ok(ArchiveVerification {
            integrity_ok: false,
            accessible: false,
            status: ArchiveStatus::Expired,
            last_verified_at: Utc::now(),
        })
    }

    async fn retrieve(&self, _passport_id: PassportId) -> Result<Option<Passport>, DppError> {
        Ok(None)
    }
}
