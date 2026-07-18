//! `SnapshotOutbox` on PostgreSQL (`ops/pg/0023`).
//!
//! The durable reconcile queue behind the static continuity tier. Structurally
//! the same shape as `repo_webhook`/`repo_registry_sync` — enqueue, `due`, and
//! the three terminal/transient `mark_*` transitions with identical backoff —
//! with one deliberate difference: a row carries **no action and no body**, only
//! a `passport_id`. The drain derives put-or-remove from the passport's current
//! status, so replays and out-of-order retries converge instead of racing. See
//! `dpp_types::SnapshotOutbox` for why.
//!
//! Enqueue is an upsert on the unique `passport_id`: a second state change while
//! a reconcile is still queued re-arms the existing row rather than stacking a
//! new one, because one pending reconcile already subsumes any number of changes.

use async_trait::async_trait;
use sqlx::Row;
use uuid::Uuid;

use dpp_domain::{DppError, domain::passport::PassportId};
use dpp_types::{SnapshotOutbox, SnapshotOutboxCounts, SnapshotReconcileRow};

use super::{PgDal, db_err};

/// PostgreSQL implementation of [`SnapshotOutbox`].
pub struct PgSnapshotOutboxRepo {
    dal: PgDal,
}

impl PgSnapshotOutboxRepo {
    /// Construct a repo sharing the given pool handle.
    pub fn new(dal: PgDal) -> Self {
        Self { dal }
    }
}

#[async_trait]
impl SnapshotOutbox for PgSnapshotOutboxRepo {
    async fn enqueue(&self, passport_id: PassportId) -> Result<(), DppError> {
        // Re-arm on conflict: back to `pending`, due immediately, attempts reset.
        // Resetting attempts is intentional — a fresh state change deserves a
        // fresh retry budget, and an `exhausted` row must become drainable again
        // rather than stay stuck once the passport moves on.
        sqlx::query(
            r#"INSERT INTO odal.snapshot_outbox (passport_id)
               VALUES ($1)
               ON CONFLICT (passport_id) DO UPDATE SET
                 status = 'pending',
                 attempts = 0,
                 next_attempt_at = now(),
                 message = NULL,
                 reconciled_at = NULL,
                 updated_at = now()"#,
        )
        .bind(passport_id.0)
        .execute(self.dal.pool())
        .await
        .map_err(db_err)?;
        Ok(())
    }

    async fn enqueue_divergent(&self, limit: i64) -> Result<u64, DppError> {
        // One statement: select the divergent passports and upsert them through
        // the same re-arm path `enqueue` uses, so a swept row is indistinguishable
        // from a lifecycle-queued one and the drain needs no special case.
        //
        // `published_at IS NOT NULL` restricts the sweep to passports that have
        // been public at least once — a draft has nothing in the static tier to
        // repair, and without this every draft ever created would be swept in
        // forever on the "no outbox row" arm.
        //
        // `pending` rows are deliberately not matched: they are already queued
        // and the drain owns them. Re-arming them here would reset their
        // backoff every sweep and turn a failing row into a hot loop.
        let res = sqlx::query(
            r#"INSERT INTO odal.snapshot_outbox (passport_id)
               SELECT p.id
               FROM odal.passport p
               LEFT JOIN odal.snapshot_outbox s ON s.passport_id = p.id
               WHERE p.published_at IS NOT NULL
                 AND (
                       s.passport_id IS NULL
                    OR s.status = 'exhausted'
                    OR (s.status = 'reconciled' AND s.reconciled_at < p.updated_at)
                 )
               ORDER BY p.updated_at ASC
               LIMIT $1
               ON CONFLICT (passport_id) DO UPDATE SET
                 status = 'pending',
                 attempts = 0,
                 next_attempt_at = now(),
                 message = NULL,
                 reconciled_at = NULL,
                 updated_at = now()"#,
        )
        .bind(limit)
        .execute(self.dal.pool())
        .await
        .map_err(db_err)?;
        Ok(res.rows_affected())
    }

    async fn due(&self, limit: i64) -> Result<Vec<SnapshotReconcileRow>, DppError> {
        let rows = sqlx::query(
            r#"SELECT id, passport_id, attempts
               FROM odal.snapshot_outbox
               WHERE status = 'pending' AND next_attempt_at <= now()
               ORDER BY next_attempt_at ASC
               LIMIT $1"#,
        )
        .bind(limit)
        .fetch_all(self.dal.pool())
        .await
        .map_err(db_err)?;
        Ok(rows
            .iter()
            .map(|row| SnapshotReconcileRow {
                id: row.get::<Uuid, _>("id"),
                passport_id: PassportId(row.get::<Uuid, _>("passport_id")),
                attempts: row.get::<i32, _>("attempts"),
            })
            .collect())
    }

    async fn mark_reconciled(&self, id: Uuid) -> Result<(), DppError> {
        sqlx::query(
            r#"UPDATE odal.snapshot_outbox SET
                 status = 'reconciled',
                 reconciled_at = now(),
                 last_attempt_at = now(),
                 attempts = attempts + 1,
                 message = NULL,
                 updated_at = now()
               WHERE id = $1"#,
        )
        .bind(id)
        .execute(self.dal.pool())
        .await
        .map_err(db_err)?;
        Ok(())
    }

    async fn mark_attempt_failed(&self, id: Uuid, message: String) -> Result<(), DppError> {
        // Exponential backoff on the *new* attempt count, capped at 1h, with
        // 0.75–1.25× jitter — identical to the registry-sync and webhook
        // outboxes. `attempts` is the pre-increment value.
        sqlx::query(
            r#"UPDATE odal.snapshot_outbox SET
                 attempts = attempts + 1,
                 message = $2,
                 last_attempt_at = now(),
                 next_attempt_at = now()
                   + (LEAST(power(2, attempts + 1), 3600) * (0.75 + random() * 0.5))
                     * interval '1 second',
                 updated_at = now()
               WHERE id = $1"#,
        )
        .bind(id)
        .bind(&message)
        .execute(self.dal.pool())
        .await
        .map_err(db_err)?;
        Ok(())
    }

    async fn mark_exhausted(&self, id: Uuid, message: String) -> Result<(), DppError> {
        sqlx::query(
            r#"UPDATE odal.snapshot_outbox SET
                 status = 'exhausted',
                 message = $2,
                 last_attempt_at = now(),
                 attempts = attempts + 1,
                 updated_at = now()
               WHERE id = $1"#,
        )
        .bind(id)
        .bind(&message)
        .execute(self.dal.pool())
        .await
        .map_err(db_err)?;
        Ok(())
    }

    async fn status_counts(&self) -> Result<SnapshotOutboxCounts, DppError> {
        let row = sqlx::query(
            r#"SELECT
                 count(*) FILTER (WHERE status = 'pending')    AS pending,
                 count(*) FILTER (WHERE status = 'reconciled') AS reconciled,
                 count(*) FILTER (WHERE status = 'exhausted')  AS exhausted
               FROM odal.snapshot_outbox"#,
        )
        .fetch_one(self.dal.pool())
        .await
        .map_err(db_err)?;
        Ok(SnapshotOutboxCounts {
            pending: row.get::<i64, _>("pending"),
            reconciled: row.get::<i64, _>("reconciled"),
            exhausted: row.get::<i64, _>("exhausted"),
        })
    }
}
