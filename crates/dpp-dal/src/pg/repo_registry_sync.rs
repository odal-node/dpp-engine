//! `RegistrySyncOutbox` on PostgreSQL — the transactional outbox for EU Central
//! Registry registration (`ops/pg/0006`).
//!
//! One row per passport (`passport_id UNIQUE`). The load-bearing method is
//! [`PgRegistrySyncRepo::commit_publish`]: it writes the published passport and
//! enqueues its registration row in a **single** transaction, so a crash can
//! never leave a Published passport without a queued registration.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::Row;
use uuid::Uuid;

use dpp_domain::{
    DppError,
    domain::passport::{Passport, PassportId},
};
use dpp_types::{RegistrySyncCounts, RegistrySyncOutbox, RegistrySyncRow, RegistrySyncStatus};

use super::{PgDal, db_err, repo_passport::update_passport_in_tx};

/// PostgreSQL implementation of [`RegistrySyncOutbox`].
pub struct PgRegistrySyncRepo {
    dal: PgDal,
}

impl PgRegistrySyncRepo {
    /// Construct a repo sharing the given pool handle.
    pub fn new(dal: PgDal) -> Self {
        Self { dal }
    }

    fn row_to_sync(row: &sqlx::postgres::PgRow) -> RegistrySyncRow {
        RegistrySyncRow {
            passport_id: PassportId(row.get::<Uuid, _>("passport_id")),
            status: RegistrySyncStatus::from_db(&row.get::<String, _>("status")),
            registry_id: row.get::<Option<String>, _>("registry_id"),
            payload: row.get::<Option<serde_json::Value>, _>("payload"),
            message: row.get::<Option<String>, _>("message"),
            attempts: row.get::<i32, _>("attempts"),
            next_attempt_at: row.get::<DateTime<Utc>, _>("next_attempt_at"),
        }
    }
}

#[async_trait]
impl RegistrySyncOutbox for PgRegistrySyncRepo {
    async fn commit_publish(
        &self,
        passport: &Passport,
        payload: serde_json::Value,
    ) -> Result<(), DppError> {
        let mut tx = self.dal.begin().await?;
        // Same transaction as the passport write — the atomicity guarantee.
        update_passport_in_tx(&mut tx, passport).await?;
        sqlx::query(
            r#"INSERT INTO odal.registry_sync (passport_id, payload, status)
               VALUES ($1, $2, 'pending')
               ON CONFLICT (passport_id) DO NOTHING"#,
        )
        .bind(passport.id.0)
        .bind(&payload)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;
        tx.commit().await.map_err(db_err)?;
        Ok(())
    }

    async fn enqueue_status(
        &self,
        passport_id: PassportId,
        status: RegistrySyncStatus,
    ) -> Result<(), DppError> {
        // Upsert so a passport published before the outbox existed still gets a
        // row. Status-push to the registry has no port method yet; this
        // records the intent durably in the meantime.
        sqlx::query(
            r#"INSERT INTO odal.registry_sync (passport_id, status, updated_at)
               VALUES ($1, $2, now())
               ON CONFLICT (passport_id)
               DO UPDATE SET status = EXCLUDED.status, updated_at = now()"#,
        )
        .bind(passport_id.0)
        .bind(status.as_db())
        .execute(self.dal.pool())
        .await
        .map_err(db_err)?;
        Ok(())
    }

    async fn due(&self, limit: i64) -> Result<Vec<RegistrySyncRow>, DppError> {
        let rows = sqlx::query(
            r#"SELECT passport_id, status, registry_id, payload, message, attempts, next_attempt_at
               FROM odal.registry_sync
               WHERE status = 'pending' AND next_attempt_at <= now()
               ORDER BY next_attempt_at ASC
               LIMIT $1"#,
        )
        .bind(limit)
        .fetch_all(self.dal.pool())
        .await
        .map_err(db_err)?;
        Ok(rows.iter().map(Self::row_to_sync).collect())
    }

    async fn mark_registered(
        &self,
        passport_id: PassportId,
        registry_id: String,
    ) -> Result<(), DppError> {
        sqlx::query(
            r#"UPDATE odal.registry_sync SET
                 status = 'registered',
                 registry_id = $2,
                 registered_at = now(),
                 last_attempt_at = now(),
                 message = NULL,
                 updated_at = now()
               WHERE passport_id = $1"#,
        )
        .bind(passport_id.0)
        .bind(&registry_id)
        .execute(self.dal.pool())
        .await
        .map_err(db_err)?;
        Ok(())
    }

    async fn mark_rejected(
        &self,
        passport_id: PassportId,
        message: String,
    ) -> Result<(), DppError> {
        sqlx::query(
            r#"UPDATE odal.registry_sync SET
                 status = 'rejected',
                 message = $2,
                 last_attempt_at = now(),
                 updated_at = now()
               WHERE passport_id = $1"#,
        )
        .bind(passport_id.0)
        .bind(&message)
        .execute(self.dal.pool())
        .await
        .map_err(db_err)?;
        Ok(())
    }

    async fn mark_attempt_failed(
        &self,
        passport_id: PassportId,
        message: String,
    ) -> Result<(), DppError> {
        // Exponential backoff on the *new* attempt count, capped at 1h, with
        // 0.75–1.25× jitter to avoid thundering-herd retries. `attempts` in the
        // expression is the pre-increment value the row already holds.
        sqlx::query(
            r#"UPDATE odal.registry_sync SET
                 attempts = attempts + 1,
                 message = $2,
                 last_attempt_at = now(),
                 next_attempt_at = now()
                   + (LEAST(power(2, attempts + 1), 3600) * (0.75 + random() * 0.5))
                     * interval '1 second'
               WHERE passport_id = $1"#,
        )
        .bind(passport_id.0)
        .bind(&message)
        .execute(self.dal.pool())
        .await
        .map_err(db_err)?;
        Ok(())
    }

    async fn pending_for(
        &self,
        passport_id: PassportId,
    ) -> Result<Option<RegistrySyncRow>, DppError> {
        let row = sqlx::query(
            r#"SELECT passport_id, status, registry_id, payload, message, attempts, next_attempt_at
               FROM odal.registry_sync
               WHERE passport_id = $1"#,
        )
        .bind(passport_id.0)
        .fetch_optional(self.dal.pool())
        .await
        .map_err(db_err)?;
        Ok(row.as_ref().map(Self::row_to_sync))
    }

    async fn status_counts(&self, stall_threshold: i32) -> Result<RegistrySyncCounts, DppError> {
        let row = sqlx::query(
            r#"SELECT
                 count(*) FILTER (WHERE status = 'pending')                          AS pending,
                 count(*) FILTER (WHERE status = 'registered')                       AS registered,
                 count(*) FILTER (WHERE status = 'rejected')                         AS rejected,
                 count(*) FILTER (WHERE status IN ('suspended','deactivated'))       AS status_intents,
                 count(*) FILTER (WHERE status = 'pending' AND attempts >= $1)       AS stalled
               FROM odal.registry_sync"#,
        )
        .bind(stall_threshold)
        .fetch_one(self.dal.pool())
        .await
        .map_err(db_err)?;
        Ok(RegistrySyncCounts {
            pending: row.get::<i64, _>("pending"),
            registered: row.get::<i64, _>("registered"),
            rejected: row.get::<i64, _>("rejected"),
            status_intents: row.get::<i64, _>("status_intents"),
            stalled: row.get::<i64, _>("stalled"),
        })
    }
}
