//! [`IdempotencyStore`] on PostgreSQL.
//!
//! The whole mechanism turns on one statement: the claim in [`PgIdempotencyRepo::claim`]
//! is a single `INSERT … ON CONFLICT DO UPDATE … RETURNING`, so two simultaneous
//! first attempts cannot both be told they own the key. Splitting it into a
//! `SELECT` and an `INSERT` would leave exactly the race the feature exists to
//! close.

use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use dpp_common::idempotency::{
    Claim, IdempotencyError, IdempotencyStore, RequestKey, StoredResponse,
};
use sqlx::Row;

use super::PgDal;

/// PostgreSQL implementation of [`IdempotencyStore`] (migration 0036).
pub struct PgIdempotencyRepo {
    dal: PgDal,
}

impl PgIdempotencyRepo {
    /// Construct a repo sharing the given pool handle.
    pub fn new(dal: PgDal) -> Self {
        Self { dal }
    }
}

/// Map a sqlx failure into the port's error. The port carries no domain error
/// type deliberately — `dpp-common` has no domain dependency.
fn err(e: sqlx::Error) -> IdempotencyError {
    IdempotencyError::Unavailable(e.to_string())
}

/// Seconds as an interval, saturating rather than panicking on an absurd value.
fn as_interval(d: Duration) -> sqlx::postgres::types::PgInterval {
    sqlx::postgres::types::PgInterval {
        months: 0,
        days: 0,
        microseconds: i64::try_from(d.as_micros()).unwrap_or(i64::MAX),
    }
}

#[async_trait]
impl IdempotencyStore for PgIdempotencyRepo {
    async fn claim(
        &self,
        key: &RequestKey,
        fingerprint: &str,
        lease: Duration,
        retention: Duration,
    ) -> Result<Claim, IdempotencyError> {
        // One statement, and every branch of the decision is in it.
        //
        // The `ON CONFLICT DO UPDATE` fires only for a row that is *reclaimable*
        // — expired outright, or an `in_flight` claim whose lease has run out
        // (the crash case). When it fires, the row is reset to a fresh claim and
        // returned. When the `WHERE` refuses, `RETURNING` yields nothing and the
        // existing row is read back below to say which of the three remaining
        // answers applies.
        //
        // `xmax = 0` is the standard way to tell an insert from an update in a
        // single `RETURNING`: it is zero on a freshly inserted tuple.
        let inserted = sqlx::query(
            r#"INSERT INTO odal.idempotency_key
                 (principal, method, path, idem_key, fingerprint, state,
                  lease_expires_at, expires_at)
               VALUES ($1,$2,$3,$4,$5,'in_flight', now() + $6, now() + $7)
               ON CONFLICT (principal, method, path, idem_key) DO UPDATE
                 SET fingerprint      = EXCLUDED.fingerprint,
                     state            = 'in_flight',
                     response_status  = NULL,
                     response_body    = NULL,
                     content_type     = NULL,
                     completed_at     = NULL,
                     created_at       = now(),
                     lease_expires_at = EXCLUDED.lease_expires_at,
                     expires_at       = EXCLUDED.expires_at
                 WHERE odal.idempotency_key.expires_at <= now()
                    OR (odal.idempotency_key.state = 'in_flight'
                        AND odal.idempotency_key.lease_expires_at <= now())
               RETURNING (xmax = 0) AS fresh"#,
        )
        .bind(&key.principal)
        .bind(&key.method)
        .bind(&key.path)
        .bind(&key.key)
        .bind(fingerprint)
        .bind(as_interval(lease))
        .bind(as_interval(retention))
        .fetch_optional(self.dal.pool())
        .await
        .map_err(err)?;

        if inserted.is_some() {
            // Either a brand-new row, or a reclaimed one. Both are ours to run.
            return Ok(Claim::Claimed);
        }

        // The conflict target existed and was not reclaimable. Read what stands
        // there. A row that vanished between the two statements (swept in the
        // gap) is treated as a claim failure the caller may simply retry —
        // reporting `InFlight` is the conservative answer, never a duplicate.
        let Some(row) = sqlx::query(
            r#"SELECT fingerprint, state, response_status, response_body, content_type
               FROM odal.idempotency_key
               WHERE principal = $1 AND method = $2 AND path = $3 AND idem_key = $4"#,
        )
        .bind(&key.principal)
        .bind(&key.method)
        .bind(&key.path)
        .bind(&key.key)
        .fetch_optional(self.dal.pool())
        .await
        .map_err(err)?
        else {
            return Ok(Claim::InFlight);
        };

        // Checked before state: a caller that changed its body is wrong about
        // the request regardless of whether the first attempt has finished, and
        // "still running" would be a misleading thing to tell it.
        let stored_fingerprint: String = row.get("fingerprint");
        if stored_fingerprint != fingerprint {
            return Ok(Claim::FingerprintMismatch);
        }

        let state: String = row.get("state");
        if state != "completed" {
            return Ok(Claim::InFlight);
        }

        let status: Option<i16> = row.get("response_status");
        // The migration's CHECK makes a completed row without a status
        // unstorable, so this is belt-and-braces — but replaying a `200` with
        // an empty body because a column was NULL would be a silent lie, and
        // re-running is the safe direction.
        let Some(status) = status else {
            return Ok(Claim::InFlight);
        };

        Ok(Claim::Replay(StoredResponse {
            status: u16::try_from(status).unwrap_or(500),
            body: row
                .get::<Option<Vec<u8>>, _>("response_body")
                .unwrap_or_default(),
            content_type: row.get("content_type"),
        }))
    }

    async fn complete(
        &self,
        key: &RequestKey,
        response: &StoredResponse,
    ) -> Result<(), IdempotencyError> {
        sqlx::query(
            r#"UPDATE odal.idempotency_key
               SET state = 'completed',
                   response_status = $5,
                   response_body   = $6,
                   content_type    = $7,
                   completed_at    = now()
               WHERE principal = $1 AND method = $2 AND path = $3 AND idem_key = $4
                 AND state = 'in_flight'"#,
        )
        .bind(&key.principal)
        .bind(&key.method)
        .bind(&key.path)
        .bind(&key.key)
        .bind(i16::try_from(response.status).unwrap_or(500))
        .bind(&response.body)
        .bind(&response.content_type)
        .execute(self.dal.pool())
        .await
        .map_err(err)?;
        Ok(())
    }

    async fn release(&self, key: &RequestKey) -> Result<(), IdempotencyError> {
        // Deleted, not marked: an `in_flight` row left behind would hold the key
        // hostage for the rest of its lease, and the point of releasing is that
        // the caller may try again now.
        sqlx::query(
            r#"DELETE FROM odal.idempotency_key
               WHERE principal = $1 AND method = $2 AND path = $3 AND idem_key = $4
                 AND state = 'in_flight'"#,
        )
        .bind(&key.principal)
        .bind(&key.method)
        .bind(&key.path)
        .bind(&key.key)
        .execute(self.dal.pool())
        .await
        .map_err(err)?;
        Ok(())
    }

    async fn purge_expired(&self) -> Result<u64, IdempotencyError> {
        let result = sqlx::query("DELETE FROM odal.idempotency_key WHERE expires_at <= now()")
            .execute(self.dal.pool())
            .await
            .map_err(err)?;
        Ok(result.rows_affected())
    }
}

/// Exposed for the integration suite, which asserts the lease and retention
/// branches by moving a row's timestamps into the past rather than sleeping.
impl PgIdempotencyRepo {
    /// Backdate a key's lease and expiry, simulating the passage of time.
    ///
    /// # Errors
    /// [`IdempotencyError::Unavailable`] if the store cannot be reached.
    pub async fn backdate_for_test(
        &self,
        key: &RequestKey,
        lease_expires_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> Result<(), IdempotencyError> {
        sqlx::query(
            r#"UPDATE odal.idempotency_key
               SET lease_expires_at = $5, expires_at = $6
               WHERE principal = $1 AND method = $2 AND path = $3 AND idem_key = $4"#,
        )
        .bind(&key.principal)
        .bind(&key.method)
        .bind(&key.path)
        .bind(&key.key)
        .bind(lease_expires_at)
        .bind(expires_at)
        .execute(self.dal.pool())
        .await
        .map_err(err)?;
        Ok(())
    }
}
