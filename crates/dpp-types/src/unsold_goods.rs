//! Discard records and the documents behind them: the storage ports for ESPR
//! Art. 24 and Art. 25.
//!
//! # What the law says is core's
//!
//! The record, the evidence kinds each derogation needs, how long a document is
//! kept and the yearly aggregation are `dpp_domain::unsold_goods`. This module
//! holds only what the node stores: a record exactly as core models it, the
//! passports it names, and documents attached under a kind, addressed by SHA-256.
//!
//! # Why this is not a passport
//!
//! Art. 24's subject is an operator over a financial year, not a product placed
//! on the market, so a discard is never a passport and carries no product group.
//! Its routes sit beside the other operator-scoped ones.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use dpp_domain::{
    DppError,
    unsold_goods::{DiscardRecord, EvidenceKind, FinancialYear},
};
use serde::Serialize;
use uuid::Uuid;

/// The largest document one evidence file may be: 25 MiB.
pub const EVIDENCE_FILE_MAX_BYTES: usize = 25 * 1024 * 1024;

/// A stored discard record, with the passports it names.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StoredDiscardRecord {
    /// Minted by the store and never reused.
    pub id: Uuid,
    /// The version of core's discard-record schema the record was checked against.
    pub schema_version: String,
    /// The record, as core models it.
    pub record: DiscardRecord,
    /// The passports of the units this discard names. Sorted.
    pub passport_ids: Vec<Uuid>,
    /// When the record was stored.
    pub created_at: DateTime<Utc>,
}

/// Persistence for discard records and the evidence they cite.
#[async_trait]
pub trait DiscardRecordStore: Send + Sync {
    /// Store a record and the passports it names, in one transaction.
    ///
    /// # Errors
    /// `Validation` when a named passport is not held by this node; database
    /// failures otherwise.
    async fn create(
        &self,
        record: &DiscardRecord,
        schema_version: &str,
        passport_ids: &[Uuid],
    ) -> Result<StoredDiscardRecord, DppError>;

    /// The record with `id`, or `None` when this node holds none.
    ///
    /// # Errors
    /// Database failures.
    async fn get(&self, id: Uuid) -> Result<Option<StoredDiscardRecord>, DppError>;

    /// Every record discarded within `year`, by day of discard, earliest first.
    ///
    /// # Errors
    /// Database failures.
    async fn list_for_year(
        &self,
        year: FinancialYear,
    ) -> Result<Vec<StoredDiscardRecord>, DppError>;

    /// Attach a stored document to a record under `kind`. `false` when the record
    /// already holds that document under that kind.
    ///
    /// # Errors
    /// Database failures.
    async fn attach(
        &self,
        record_id: Uuid,
        kind: EvidenceKind,
        sha256: &str,
    ) -> Result<bool, DppError>;

    /// The kinds of the documents attached to a record.
    ///
    /// # Errors
    /// Database failures.
    async fn held_kinds(&self, record_id: Uuid) -> Result<Vec<EvidenceKind>, DppError>;
}

/// Content-addressed storage for evidence documents.
#[async_trait]
pub trait EvidenceStore: Send + Sync {
    /// Store `bytes` under `sha256`, the lower-case hex SHA-256 of the bytes.
    /// `true` when the file was new, `false` when it was already held.
    ///
    /// # Errors
    /// Database failures.
    async fn put(&self, sha256: &str, bytes: &[u8]) -> Result<bool, DppError>;
}
