//! `AuditRepository` on PostgreSQL — append-only by trigger, not convention.

use async_trait::async_trait;
use sqlx::Row;

use dpp_domain::DppError;
use dpp_types::audit::{
    AuditChainBreak, AuditEntry, AuditRepository, GENESIS_PREV_HASH, verify_audit_chain,
};

use super::{PgDal, db_err};

/// PostgreSQL implementation of [`AuditRepository`].
///
/// The DB enforces append-only via a trigger; any UPDATE/DELETE raises
/// `ODAL_AUDIT` which `db_err` maps to `DppError::Internal`.
pub struct PgAuditRepo {
    dal: PgDal,
}

impl PgAuditRepo {
    /// Construct a repo sharing the given pool handle.
    pub fn new(dal: PgDal) -> Self {
        Self { dal }
    }
}

#[async_trait]
impl AuditRepository for PgAuditRepo {
    /// Write one audit entry; the DB trigger enforces immutability —
    /// no updates or deletes are permitted on this table.
    ///
    /// # Errors
    /// Returns `DppError::Internal` on DB error or trigger constraint violation.
    async fn append(&self, entry: AuditEntry) -> Result<(), DppError> {
        // Normalise the timestamp to microsecond precision *before* hashing:
        // Postgres `timestamptz` is microsecond-resolution, so the value we hash
        // must equal the value it stores, or the chain won't verify after a
        // round-trip (the sub-microsecond part of `Utc::now()` is dropped on read).
        let mut entry = entry;
        if let Some(ts) =
            chrono::DateTime::from_timestamp_micros(entry.timestamp.timestamp_micros())
        {
            entry.timestamp = ts;
        }
        let mut tx = self.dal.begin().await?;
        // Chain link: read this passport's current head under the same tx,
        // then hash this entry's content folded with the head's hash. The
        // append-only trigger guarantees the head cannot have been rewritten.
        let prev_hash: String = sqlx::query_scalar(
            r#"SELECT entry_hash FROM odal.passport_audit
               WHERE passport_id = $1
               ORDER BY ts DESC, id DESC
               LIMIT 1"#,
        )
        .bind(&entry.passport_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_err)?
        .flatten()
        .unwrap_or_else(|| GENESIS_PREV_HASH.to_owned());
        let entry_hash = entry.chain_hash(&prev_hash);
        sqlx::query(
            r#"INSERT INTO odal.passport_audit
                 (id, passport_id, actor, action,
                  previous_status, new_status, metadata, ts, prev_hash, entry_hash)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)"#,
        )
        .bind(entry.id)
        .bind(&entry.passport_id)
        .bind(&entry.actor)
        .bind(&entry.action)
        .bind(&entry.previous_status)
        .bind(&entry.new_status)
        .bind(&entry.metadata)
        .bind(entry.timestamp)
        .bind(&prev_hash)
        .bind(&entry_hash)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;
        tx.commit().await.map_err(db_err)
    }

    /// Retrieve all audit entries for a passport in ascending timestamp order.
    async fn list_by_passport(&self, passport_id: &str) -> Result<Vec<AuditEntry>, DppError> {
        let mut tx = self.dal.begin().await?;
        let rows = sqlx::query(
            r#"SELECT id, passport_id, actor, action,
                      previous_status, new_status, metadata, ts, prev_hash, entry_hash
               FROM odal.passport_audit
               WHERE passport_id = $1
               ORDER BY ts ASC, id ASC"#,
        )
        .bind(passport_id)
        .fetch_all(&mut *tx)
        .await
        .map_err(db_err)?;
        tx.commit().await.map_err(db_err)?;
        Ok(rows
            .into_iter()
            .map(|r| AuditEntry {
                id: r.get("id"),
                passport_id: r.get("passport_id"),
                actor: r.get("actor"),
                action: r.get("action"),
                previous_status: r.get("previous_status"),
                new_status: r.get("new_status"),
                metadata: r.get("metadata"),
                timestamp: r.get("ts"),
                prev_hash: r.get("prev_hash"),
                entry_hash: r.get("entry_hash"),
            })
            .collect())
    }
}

impl PgAuditRepo {
    /// Verify a passport's audit chain is intact. Returns `None` when
    /// every link verifies, or the first [`AuditChainBreak`] otherwise — the
    /// tamper-evidence surface behind `GET /provenance/{id}/proof`.
    ///
    /// The entries are read in chain order (ts, id) and replayed through
    /// [`verify_audit_chain`]; entries chained since 0015 carry `entry_hash`.
    pub async fn verify_chain(
        &self,
        passport_id: &str,
    ) -> Result<Option<AuditChainBreak>, DppError> {
        let entries = self.list_by_passport(passport_id).await?;
        Ok(verify_audit_chain(&entries).err())
    }
}
