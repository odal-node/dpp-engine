//! `RegistryTransferOutbox` on PostgreSQL — the transactional outbox for EU
//! Central Registry transfer-of-responsibility notifications (`ops/pg/0029`).
//!
//! One row per **transfer** (`transfer_id PRIMARY KEY`), not per passport: a
//! passport changes hands many times, and each handover is a separate
//! notification. The load-bearing method is
//! [`PgRegistryTransferRepo::commit_accept`], which writes the updated transfer
//! chain and enqueues the notification in a **single** transaction, so a crash
//! can never leave an accepted transfer without a queued notification.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::Row;
use uuid::Uuid;

use dpp_domain::{DppError, passport::PassportId, transfer::TransferChain};
use dpp_types::{
    RegistryTransferCounts, RegistryTransferOutbox, RegistryTransferRow, RegistryTransferStatus,
};

use super::{PgDal, db_err, require_updated};

/// PostgreSQL implementation of [`RegistryTransferOutbox`].
pub struct PgRegistryTransferRepo {
    dal: PgDal,
}

impl PgRegistryTransferRepo {
    /// Construct a repo sharing the given pool handle.
    pub fn new(dal: PgDal) -> Self {
        Self { dal }
    }
}

/// Build a row from a `SELECT *` over `odal.registry_transfer`.
fn to_row(r: &sqlx::postgres::PgRow) -> RegistryTransferRow {
    RegistryTransferRow {
        transfer_id: r.get::<Uuid, _>("transfer_id"),
        passport_id: PassportId(r.get::<Uuid, _>("passport_id")),
        status: RegistryTransferStatus::from_db(r.get::<&str, _>("status")),
        payload: r.get::<serde_json::Value, _>("payload"),
        registry_id: r.get::<Option<String>, _>("registry_id"),
        message: r.get::<Option<String>, _>("message"),
        attempts: r.get::<i32, _>("attempts"),
        next_attempt_at: r.get::<DateTime<Utc>, _>("next_attempt_at"),
    }
}

#[async_trait]
impl RegistryTransferOutbox for PgRegistryTransferRepo {
    async fn commit_accept(
        &self,
        chain: &TransferChain,
        transfer_id: Uuid,
        payload: serde_json::Value,
    ) -> Result<(), DppError> {
        let doc = serde_json::to_value(chain)
            .map_err(|e| DppError::Internal(format!("serialize transfer chain: {e}")))?;
        let mut tx = self.dal.begin().await?;

        // Same transaction as the chain write — the atomicity guarantee.
        sqlx::query(
            r#"INSERT INTO odal.passport_transfer (passport_id, chain, updated_at)
               VALUES ($1, $2, now())
               ON CONFLICT (passport_id)
               DO UPDATE SET chain = EXCLUDED.chain, updated_at = now()"#,
        )
        .bind(chain.passport_id.0)
        .bind(&doc)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;

        // A transfer is accepted once, so a conflict here is a retry of the same
        // handover rather than a new one: leave the existing row alone. In
        // particular this must not reset a row already `notified` back to
        // `pending`, which would notify the registry of the same transfer twice.
        sqlx::query(
            r#"INSERT INTO odal.registry_transfer (transfer_id, passport_id, payload, status)
               VALUES ($1, $2, $3, 'pending')
               ON CONFLICT (transfer_id) DO NOTHING"#,
        )
        .bind(transfer_id)
        .bind(chain.passport_id.0)
        .bind(&payload)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;

        tx.commit().await.map_err(db_err)?;
        Ok(())
    }

    async fn due(&self, limit: i64) -> Result<Vec<RegistryTransferRow>, DppError> {
        let rows = sqlx::query(
            r#"SELECT * FROM odal.registry_transfer
               WHERE status = 'pending' AND next_attempt_at <= now()
               ORDER BY next_attempt_at ASC
               LIMIT $1"#,
        )
        .bind(limit)
        .fetch_all(self.dal.pool())
        .await
        .map_err(db_err)?;
        Ok(rows.iter().map(to_row).collect())
    }

    async fn mark_notified(&self, transfer_id: Uuid, registry_id: String) -> Result<(), DppError> {
        let res = sqlx::query(
            r#"UPDATE odal.registry_transfer SET
                 status = 'notified',
                 registry_id = $2,
                 notified_at = now(),
                 last_attempt_at = now(),
                 message = NULL,
                 updated_at = now()
               WHERE transfer_id = $1"#,
        )
        .bind(transfer_id)
        .bind(&registry_id)
        .execute(self.dal.pool())
        .await
        .map_err(db_err)?;
        require_updated(&res, "registry_transfer row", transfer_id)
    }

    async fn mark_rejected(&self, transfer_id: Uuid, message: String) -> Result<(), DppError> {
        let res = sqlx::query(
            r#"UPDATE odal.registry_transfer SET
                 status = 'rejected',
                 message = $2,
                 last_attempt_at = now(),
                 updated_at = now()
               WHERE transfer_id = $1"#,
        )
        .bind(transfer_id)
        .bind(&message)
        .execute(self.dal.pool())
        .await
        .map_err(db_err)?;
        require_updated(&res, "registry_transfer row", transfer_id)
    }

    /// See the trait. `attempts` is untouched and the retry delay is a short
    /// fixed one — the row is waiting on another row, not backing off from a
    /// failing endpoint, so there is nothing for exponential backoff to protect.
    async fn mark_deferred(&self, transfer_id: Uuid, message: String) -> Result<(), DppError> {
        let res = sqlx::query(
            r#"UPDATE odal.registry_transfer SET
                 message = $2,
                 last_attempt_at = now(),
                 next_attempt_at = now() + interval '60 seconds'
               WHERE transfer_id = $1"#,
        )
        .bind(transfer_id)
        .bind(&message)
        .execute(self.dal.pool())
        .await
        .map_err(db_err)?;
        require_updated(&res, "registry_transfer row", transfer_id)
    }

    async fn mark_attempt_failed(
        &self,
        transfer_id: Uuid,
        message: String,
    ) -> Result<(), DppError> {
        // Exponential backoff on the *new* attempt count, capped at 1h, with
        // 0.75–1.25× jitter to avoid thundering-herd retries. Matches the
        // registration outbox so the two queues behave identically under load.
        let res = sqlx::query(
            r#"UPDATE odal.registry_transfer SET
                 attempts = attempts + 1,
                 message = $2,
                 last_attempt_at = now(),
                 next_attempt_at = now()
                   + (LEAST(power(2, attempts + 1), 3600) * (0.75 + random() * 0.5))
                     * interval '1 second'
               WHERE transfer_id = $1"#,
        )
        .bind(transfer_id)
        .bind(&message)
        .execute(self.dal.pool())
        .await
        .map_err(db_err)?;
        require_updated(&res, "registry_transfer row", transfer_id)
    }

    async fn rows_for(
        &self,
        passport_id: PassportId,
    ) -> Result<Vec<RegistryTransferRow>, DppError> {
        let rows = sqlx::query(
            r#"SELECT * FROM odal.registry_transfer
               WHERE passport_id = $1
               ORDER BY created_at DESC"#,
        )
        .bind(passport_id.0)
        .fetch_all(self.dal.pool())
        .await
        .map_err(db_err)?;
        Ok(rows.iter().map(to_row).collect())
    }

    async fn status_counts(
        &self,
        stall_threshold: i32,
    ) -> Result<RegistryTransferCounts, DppError> {
        let r = sqlx::query(
            r#"SELECT
                 count(*) FILTER (WHERE status = 'pending')   AS pending,
                 count(*) FILTER (WHERE status = 'notified')  AS notified,
                 count(*) FILTER (WHERE status = 'rejected')  AS rejected,
                 count(*) FILTER (WHERE status = 'pending' AND attempts >= $1) AS stalled
               FROM odal.registry_transfer"#,
        )
        .bind(stall_threshold)
        .fetch_one(self.dal.pool())
        .await
        .map_err(db_err)?;
        Ok(RegistryTransferCounts {
            pending: r.get::<i64, _>("pending"),
            notified: r.get::<i64, _>("notified"),
            rejected: r.get::<i64, _>("rejected"),
            stalled: r.get::<i64, _>("stalled"),
        })
    }
}
