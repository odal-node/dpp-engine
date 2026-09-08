//! S3/MinIO adapter implementing `SnapshotStore` — the static continuity tier.
//!
//! Writes the passport's signed public view, bounded by its own `asOf` /
//! `validUntil` proof, to a **public** bucket under `{dpp_id}/public.json`, so a
//! CDN or bucket-website can serve it under a stable
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
use dpp_domain::error::DppError;
use dpp_types::snapshot::{SnapshotMeta, SnapshotStore, snapshot_html_key, snapshot_json_key};

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

    /// Delegates to `dpp-types` rather than formatting here. `publish` builds
    /// the registry back-up URL from the same definition, and the two used to
    /// disagree by a path segment.
    fn key(dpp_id: &str) -> String {
        snapshot_json_key(dpp_id)
    }

    fn html_key(dpp_id: &str) -> String {
        snapshot_html_key(dpp_id)
    }

    /// Apply the staleness headers every snapshot object carries.
    ///
    /// The signed `validUntil` inside the payload is the claim that matters;
    /// this is the part of it a *direct* reader gets. Until now the only
    /// staleness signal was a header the reverse proxy added on its own path,
    /// which meant a reader who went to the object store — the copy is public,
    /// so anyone can — received no signal at all.
    ///
    /// `Cache-Control` comes from the refresh cadence rather than the validity
    /// window: a newer object exists after one refresh cycle, so authorising a
    /// cache to hold this one for the full week would let it serve a copy the
    /// node has already replaced, including one it replaced with a deletion.
    ///
    /// The `x-amz-meta-*` pair keeps `asOf`/`validUntil` legible to anything
    /// that inspects the object rather than parsing the body. Neither is
    /// covered by a signature, and neither is offered as if it were.
    fn with_snapshot_meta(
        req: aws_sdk_s3::operation::put_object::builders::PutObjectFluentBuilder,
        meta: SnapshotMeta,
    ) -> aws_sdk_s3::operation::put_object::builders::PutObjectFluentBuilder {
        let rfc3339 =
            |t: chrono::DateTime<chrono::Utc>| t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        req.cache_control(format!("public, max-age={}", meta.max_age.as_secs()))
            .metadata("odal-snapshot", "true")
            .metadata("odal-as-of", rfc3339(meta.as_of))
            .metadata("odal-valid-until", rfc3339(meta.valid_until))
    }
}

#[async_trait]
impl SnapshotStore for S3SnapshotStore {
    async fn put_public_json(
        &self,
        dpp_id: &str,
        bytes: &[u8],
        meta: SnapshotMeta,
    ) -> Result<(), DppError> {
        Self::with_snapshot_meta(
            self.client
                .put_object()
                .bucket(&self.bucket)
                .key(Self::key(dpp_id))
                .body(ByteStream::from(bytes.to_vec()))
                .content_type("application/json"),
            meta,
        )
        .send()
        .await
        .map_err(|e| DppError::Internal(format!("snapshot S3 PUT failed: {e}")))?;
        Ok(())
    }

    async fn put_public_html(
        &self,
        dpp_id: &str,
        bytes: &[u8],
        meta: SnapshotMeta,
    ) -> Result<(), DppError> {
        Self::with_snapshot_meta(
            self.client
                .put_object()
                .bucket(&self.bucket)
                .key(Self::html_key(dpp_id))
                .body(ByteStream::from(bytes.to_vec()))
                .content_type("text/html; charset=utf-8"),
            meta,
        )
        .send()
        .await
        .map_err(|e| DppError::Internal(format!("snapshot S3 PUT (html) failed: {e}")))?;
        Ok(())
    }

    async fn remove(&self, dpp_id: &str) -> Result<(), DppError> {
        // S3 `DeleteObject` is idempotent — a missing key succeeds — so retiring
        // a snapshot for a passport that never had one is not an error.
        //
        // Both representations are retired, and the HTML goes first: if the pair
        // is ever left half-removed, the survivor must be the signed JSON rather
        // than the page a consumer would read and believe.
        self.client
            .delete_object()
            .bucket(&self.bucket)
            .key(Self::html_key(dpp_id))
            .send()
            .await
            .map_err(|e| DppError::Internal(format!("snapshot S3 DELETE (html) failed: {e}")))?;
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
