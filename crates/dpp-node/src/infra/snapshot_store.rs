//! Entry point for building the continuity-snapshot store, regardless of
//! whether the `s3` build feature (see `s3_snapshot`) is enabled.

/// Build the continuity-snapshot store from env: the real S3 tier if the `s3`
/// build feature is enabled and `SNAPSHOT_S3_BUCKET` is set, `None` (tier
/// disabled) otherwise. `s3_snapshot` has no NoOp counterpart of its own — the
/// disabled state already *is* `None`, which every caller already treats as
/// "no continuity tier".
pub fn from_env() -> Option<std::sync::Arc<dyn dpp_types::snapshot::SnapshotStore>> {
    #[cfg(feature = "s3")]
    if let Some(cfg) = super::s3_snapshot::S3SnapshotConfig::from_env() {
        tracing::info!(bucket = %cfg.bucket, "continuity snapshots: S3 tier active");
        return Some(std::sync::Arc::new(
            super::s3_snapshot::S3SnapshotStore::new(cfg),
        ));
    }
    tracing::info!(
        "continuity snapshots: disabled — set SNAPSHOT_S3_BUCKET (and build with --features s3) to enable"
    );
    None
}
