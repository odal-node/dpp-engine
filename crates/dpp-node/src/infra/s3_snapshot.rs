//! S3/MinIO adapter implementing `SnapshotStore` — the static continuity tier.
//!
//! Writes the byte-identical public passport view to a **public** bucket under
//! `{dpp_id}/public.json`, so a CDN or bucket-website can serve it under a stable
//! path when the live node is unreachable. This bucket is deliberately separate
//! from the (private) ESPR Art. 13 archive bucket: snapshots are public by
//! design, archives are not — never colocate them.
//!
//! # Configuration
//!
//! | Variable                        | Required | Default     |
//! |---------------------------------|----------|-------------|
//! | `SNAPSHOT_S3_BUCKET`            | Yes      | —           |
//! | `SNAPSHOT_S3_ACCESS_KEY_ID`     | Yes      | —           |
//! | `SNAPSHOT_S3_SECRET_ACCESS_KEY` | Yes      | —           |
//! | `SNAPSHOT_S3_ENDPOINT`          | No       | real AWS    |
//! | `SNAPSHOT_S3_REGION`            | No       | `us-east-1` |
//!
//! The bucket must be configured for public read (bucket policy / website / CDN);
//! objects are written without a per-object ACL so MinIO and S3 behave alike.

use async_trait::async_trait;
use aws_sdk_s3::{
    Client,
    config::{BehaviorVersion, Builder as ConfigBuilder, Credentials, Region},
    primitives::ByteStream,
};
use dpp_domain::domain::error::DppError;
use dpp_types::snapshot::SnapshotStore;

pub struct S3SnapshotConfig {
    pub endpoint: Option<String>,
    pub bucket: String,
    pub access_key_id: String,
    pub secret_access_key: String,
    pub region: String,
}

impl S3SnapshotConfig {
    /// Load from env. Returns `None` if `SNAPSHOT_S3_BUCKET` is absent or empty
    /// (the continuity tier is then disabled).
    pub fn from_env() -> Option<Self> {
        let bucket = std::env::var("SNAPSHOT_S3_BUCKET")
            .ok()
            .filter(|s| !s.is_empty())?;
        let access_key_id = std::env::var("SNAPSHOT_S3_ACCESS_KEY_ID")
            .ok()
            .filter(|s| !s.is_empty())?;
        let secret_access_key = std::env::var("SNAPSHOT_S3_SECRET_ACCESS_KEY")
            .ok()
            .filter(|s| !s.is_empty())?;
        let endpoint = std::env::var("SNAPSHOT_S3_ENDPOINT")
            .ok()
            .filter(|s| !s.is_empty());
        let region = std::env::var("SNAPSHOT_S3_REGION").unwrap_or_else(|_| "us-east-1".into());
        Some(Self {
            endpoint,
            bucket,
            access_key_id,
            secret_access_key,
            region,
        })
    }
}

pub struct S3SnapshotStore {
    client: Client,
    bucket: String,
}

impl S3SnapshotStore {
    pub fn new(cfg: S3SnapshotConfig) -> Self {
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

    fn key(dpp_id: &str) -> String {
        format!("{dpp_id}/public.json")
    }
}

#[async_trait]
impl SnapshotStore for S3SnapshotStore {
    async fn put_public_json(&self, dpp_id: &str, bytes: &[u8]) -> Result<(), DppError> {
        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(Self::key(dpp_id))
            .body(ByteStream::from(bytes.to_vec()))
            .content_type("application/json")
            .send()
            .await
            .map_err(|e| DppError::Internal(format!("snapshot S3 PUT failed: {e}")))?;
        Ok(())
    }

    async fn remove(&self, dpp_id: &str) -> Result<(), DppError> {
        // S3 `DeleteObject` is idempotent — a missing key succeeds — so retiring
        // a snapshot for a passport that never had one is not an error.
        self.client
            .delete_object()
            .bucket(&self.bucket)
            .key(Self::key(dpp_id))
            .send()
            .await
            .map_err(|e| DppError::Internal(format!("snapshot S3 DELETE failed: {e}")))?;
        Ok(())
    }
}
