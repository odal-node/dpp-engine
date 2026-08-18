//! `SealOutbox` on PostgreSQL (`ops/pg/0028`).
//!
//! Structurally the same shape as `repo_snapshot`/`repo_webhook` — enqueue,
//! `due`, and the terminal/transient `mark_*` transitions with identical backoff
//! — with two deliberate differences, both because each drained row costs money.
//!
//! **The key is `(passport_id, payload_hash)`, not `passport_id`.** The sibling
//! outboxes re-arm one row per passport because a later reconcile subsumes an
//! earlier one. Sealing does not work that way: a re-publish re-signs the
//! passport, so its digest changes, and the new signature genuinely needs its own
//! attestation. Re-arming would leave a re-published passport carrying a seal
//! over its *previous* signature.
//!
//! **`mark_sealed` writes the envelope and closes the row in one transaction.**
//! Separately, a crash between them would leave a `pending` row for a seal
//! already produced and already billed, and the next pass would buy it again.

use async_trait::async_trait;
use sqlx::Row;
use uuid::Uuid;

use dpp_domain::{DppError, domain::passport::PassportId, ports::seal::SealedEnvelope};
use dpp_types::{SealOutbox, SealOutboxCounts, SealRow};

use super::{PgDal, db_err, require_updated};

/// PostgreSQL implementation of [`SealOutbox`].
pub struct PgSealOutboxRepo {
    dal: PgDal,
}

impl PgSealOutboxRepo {
    /// Construct a repo sharing the given pool handle.
    pub fn new(dal: PgDal) -> Self {
        Self { dal }
    }
}

#[async_trait]
impl SealOutbox for PgSealOutboxRepo {
    async fn enqueue(&self, passport_id: PassportId, payload_hash: &str) -> Result<(), DppError> {
        // Re-arm `exhausted` rows only — everything else is left alone.
        //
        // The distinction is what separates a recovery path from double billing.
        // A `sealed` row has an artifact that was paid for, so re-queueing it
        // buys the same attestation twice; a `pending` row is already owned by
        // the drain, and re-arming would reset its backoff on every publish
        // retry and turn a failing row into a hot loop. But an `exhausted` row
        // has **no seal and nothing delivered to pay for** — it is a passport
        // that is published and permanently unsealed, and without this clause
        // nothing could ever seal it again short of re-publishing, which changes
        // the signature. A provider outage must not cost an operator their seal.
        //
        // Same shape as `registry_sync`'s re-queue of `rejected` rows.
        sqlx::query(
            r#"INSERT INTO odal.seal_outbox (passport_id, payload_hash)
               VALUES ($1, $2)
               ON CONFLICT (passport_id, payload_hash) DO UPDATE SET
                 status = 'pending',
                 attempts = 0,
                 next_attempt_at = now(),
                 message = NULL,
                 updated_at = now()
               WHERE odal.seal_outbox.status = 'exhausted'"#,
        )
        .bind(passport_id.0)
        .bind(payload_hash)
        .execute(self.dal.pool())
        .await
        .map_err(db_err)?;
        Ok(())
    }

    async fn enqueue_unsealed(&self, limit: i64, cooldown_secs: i64) -> Result<u64, DppError> {
        // Two steps rather than one statement, because the digest rule is
        // `dpp_types::seal::digest_for_jws` and must stay a single definition.
        // Computing SHA-256 in SQL instead would need pgcrypto and would create a
        // second implementation of what a seal covers — the exact drift that
        // would buy seals over digests nothing else recognises.
        //
        // The candidate query is `doc->'seal' IS NULL`: a published passport that
        // carries no seal at all. That covers the lost enqueue (no row) and the
        // exhausted row (re-armed by `enqueue`).
        //
        // Deliberately NOT covered: a passport whose seal is over a *superseded*
        // signature, which needs a digest comparison in SQL and therefore the
        // second implementation above. It requires a crash inside the
        // commit→enqueue window of a re-publish specifically; the seal it carries
        // is still a valid attestation of the signature it covers, and the `/seal`
        // route already tells a verifier how to detect the mismatch.
        let rows = sqlx::query(
            r#"SELECT p.id, p.doc->>'jwsSignature' AS jws
               FROM odal.passport p
               WHERE p.published_at IS NOT NULL
                 AND p.doc->'seal' IS NULL
                 AND p.doc->>'jwsSignature' IS NOT NULL
                 -- Already queued: the drain owns it, and re-arming would reset
                 -- its backoff every sweep and turn a failing row into a loop.
                 AND NOT EXISTS (
                   SELECT 1 FROM odal.seal_outbox q
                   WHERE q.passport_id = p.id AND q.status = 'pending'
                 )
                 -- Failed recently: let the provider recover before retrying, so
                 -- sweep and drain do not hammer an outage together.
                 AND NOT EXISTS (
                   SELECT 1 FROM odal.seal_outbox r
                   WHERE r.passport_id = p.id
                     AND r.status = 'exhausted'
                     AND r.last_attempt_at > now() - make_interval(secs => $2)
                 )
               ORDER BY p.published_at ASC
               LIMIT $1"#,
        )
        .bind(limit)
        .bind(cooldown_secs as f64)
        .fetch_all(self.dal.pool())
        .await
        .map_err(db_err)?;

        let mut queued = 0u64;
        for row in rows {
            let id = PassportId(row.get::<Uuid, _>("id"));
            let jws: String = row.get("jws");
            self.enqueue(id, &dpp_types::seal::digest_for_jws(&jws))
                .await?;
            queued += 1;
        }
        Ok(queued)
    }

    async fn due(&self, limit: i64) -> Result<Vec<SealRow>, DppError> {
        let rows = sqlx::query(
            r#"SELECT id, passport_id, payload_hash, attempts
               FROM odal.seal_outbox
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
            .map(|row| SealRow {
                id: row.get::<Uuid, _>("id"),
                passport_id: PassportId(row.get::<Uuid, _>("passport_id")),
                payload_hash: row.get::<String, _>("payload_hash"),
                attempts: row.get::<i32, _>("attempts"),
            })
            .collect())
    }

    async fn mark_sealed(&self, id: Uuid, envelope: &SealedEnvelope) -> Result<(), DppError> {
        let seal = serde_json::to_value(envelope)
            .map_err(|e| DppError::Serialisation(format!("seal envelope: {e}")))?;

        let mut tx = self.dal.begin().await?;

        // The seal is set on `doc` by key rather than through a full passport
        // round-trip: the drain holds no `Passport`, and re-serializing one read
        // moments earlier would clobber any concurrent change to a mutable field.
        // `jsonb_set` touches exactly `seal` and nothing else.
        //
        // The row's own `payload_hash` is the join condition, so a seal can only
        // ever land on the passport whose digest was actually sent.
        let res = sqlx::query(
            r#"UPDATE odal.passport p SET
                 doc = jsonb_set(p.doc, '{seal}', $2, true)
               FROM odal.seal_outbox s
               WHERE s.id = $1 AND p.id = s.passport_id"#,
        )
        .bind(id)
        .bind(&seal)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;
        if res.rows_affected() == 0 {
            return Err(DppError::NotFound(format!(
                "seal_outbox row {id} has no passport to seal"
            )));
        }

        let res = sqlx::query(
            r#"UPDATE odal.seal_outbox SET
                 status = 'sealed',
                 sealed_at = now(),
                 last_attempt_at = now(),
                 attempts = attempts + 1,
                 message = NULL,
                 updated_at = now()
               WHERE id = $1"#,
        )
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;
        require_updated(&res, "seal_outbox row", id)?;

        tx.commit().await.map_err(db_err)?;
        Ok(())
    }

    async fn sealed_digest(&self, passport_id: PassportId) -> Result<Option<String>, DppError> {
        // A re-published passport accumulates one `sealed` row per signature it
        // has carried, so "which seal is on the passport" is the newest of them.
        // `id` breaks a `sealed_at` tie: it is UUID v7, so ties order by
        // insertion, and `sealed_at` is `now()` — transaction start — which two
        // rows closed in the same transaction would share.
        let row = sqlx::query(
            r#"SELECT payload_hash FROM odal.seal_outbox
               WHERE passport_id = $1 AND status = 'sealed'
               ORDER BY sealed_at DESC, id DESC
               LIMIT 1"#,
        )
        .bind(passport_id.0)
        .fetch_optional(self.dal.pool())
        .await
        .map_err(db_err)?;

        Ok(row.map(|r| r.get::<String, _>("payload_hash")))
    }

    async fn mark_attempt_failed(&self, id: Uuid, message: String) -> Result<(), DppError> {
        // Exponential backoff on the *new* attempt count, capped at 1h, with
        // 0.75–1.25× jitter — identical to the registry-sync, webhook and
        // snapshot outboxes. `attempts` is the pre-increment value.
        let res = sqlx::query(
            r#"UPDATE odal.seal_outbox SET
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
        require_updated(&res, "seal_outbox row", id)
    }

    async fn mark_exhausted(&self, id: Uuid, message: String) -> Result<(), DppError> {
        let res = sqlx::query(
            r#"UPDATE odal.seal_outbox SET
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
        require_updated(&res, "seal_outbox row", id)
    }

    async fn status_counts(&self) -> Result<SealOutboxCounts, DppError> {
        let row = sqlx::query(
            r#"SELECT
                 count(*) FILTER (WHERE status = 'pending')   AS pending,
                 count(*) FILTER (WHERE status = 'sealed')    AS sealed,
                 count(*) FILTER (WHERE status = 'exhausted') AS exhausted
               FROM odal.seal_outbox"#,
        )
        .fetch_one(self.dal.pool())
        .await
        .map_err(db_err)?;
        Ok(SealOutboxCounts {
            pending: row.get::<i64, _>("pending"),
            sealed: row.get::<i64, _>("sealed"),
            exhausted: row.get::<i64, _>("exhausted"),
        })
    }

    async fn unsealed_published_count(&self) -> Result<i64, DppError> {
        // The same three conditions `enqueue_unsealed` selects on, and only
        // those. Its two `NOT EXISTS` guards hold back rows the drain already
        // owns or that failed recently — they shape *when to retry*, not whether
        // a passport is unsealed, and applying them here would report a queued
        // passport as sealed.
        //
        // No digest comparison, matching the sweep: a seal over a superseded
        // signature is still a valid attestation of the signature it covers, and
        // `/dpp/{id}/seal` reports that per passport as `coverage`.
        let row = sqlx::query(
            r#"SELECT count(*) AS unsealed
               FROM odal.passport p
               WHERE p.published_at IS NOT NULL
                 AND p.doc->'seal' IS NULL
                 AND p.doc->>'jwsSignature' IS NOT NULL"#,
        )
        .fetch_one(self.dal.pool())
        .await
        .map_err(db_err)?;
        Ok(row.get::<i64, _>("unsealed"))
    }
}
