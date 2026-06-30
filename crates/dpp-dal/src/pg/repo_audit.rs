//! `AuditRepository` on PostgreSQL — append-only by trigger, not convention.

use async_trait::async_trait;
use sqlx::Row;

use dpp_domain::DppError;
use dpp_types::audit::{AuditEntry, AuditRepository};

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
        let mut tx = self.dal.begin().await?;
        sqlx::query(
            r#"INSERT INTO odal.passport_audit
                 (id, passport_id, actor, action,
                  previous_status, new_status, metadata, ts)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8)"#,
        )
        .bind(entry.id)
        .bind(&entry.passport_id)
        .bind(&entry.actor)
        .bind(&entry.action)
        .bind(&entry.previous_status)
        .bind(&entry.new_status)
        .bind(&entry.metadata)
        .bind(entry.timestamp)
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
                      previous_status, new_status, metadata, ts
               FROM odal.passport_audit
               WHERE passport_id = $1
               ORDER BY ts ASC"#,
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
            })
            .collect())
    }
}
