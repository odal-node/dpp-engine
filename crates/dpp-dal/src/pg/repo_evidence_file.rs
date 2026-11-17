//! `EvidenceStore` on PostgreSQL (`ops/pg/0053`).
//!
//! A file is keyed by the SHA-256 of its bytes, so storing a document a second
//! time, for a second record, writes nothing: the row is already there.

use async_trait::async_trait;

use dpp_domain::DppError;
use dpp_types::EvidenceStore;

use super::{PgDal, db_err};

/// PostgreSQL implementation of the content-addressed evidence store.
pub struct PgEvidenceFileRepo {
    dal: PgDal,
}

impl PgEvidenceFileRepo {
    /// Construct a repo sharing the given pool handle.
    pub fn new(dal: PgDal) -> Self {
        Self { dal }
    }
}

#[async_trait]
impl EvidenceStore for PgEvidenceFileRepo {
    async fn put(&self, sha256: &str, bytes: &[u8]) -> Result<bool, DppError> {
        let result = sqlx::query(
            "INSERT INTO odal.evidence_file (sha256, content)
             VALUES ($1, $2)
             ON CONFLICT (sha256) DO NOTHING",
        )
        .bind(sha256)
        .bind(bytes)
        .execute(self.dal.pool())
        .await
        .map_err(db_err)?;
        Ok(result.rows_affected() == 1)
    }
}
