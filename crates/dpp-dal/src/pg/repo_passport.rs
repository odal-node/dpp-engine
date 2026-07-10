//! `PassportRepository` on PostgreSQL — document-style.
//!
//! Single-tenant: one operator per node, no operator-isolation boundary and no
//! `operator_id` column on the passport.
//!
//! Design notes:
//! - `patch_fields` is a row-locked read-merge-write inside one transaction —
//!   real concurrent-write safety (no string-built SQL, no lowercasing quirks).

use async_trait::async_trait;
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

use dpp_domain::{
    domain::{
        error::DppError,
        passport::{Passport, PassportId},
        product_identity::ProductIdentity,
        status::PassportStatus,
    },
    ports::passport_repo::PassportRepository,
};

use super::{PgDal, db_err};

/// Apply a passport update (scalar columns + `doc`) inside a caller-supplied
/// transaction. Shared by [`PgPassportRepo::update`] and the transactional
/// outbox's `commit_publish`, so the publish-write and the outbox insert commit
/// atomically without duplicating this SQL. Errors `NotFound` if no row matched.
pub(crate) async fn update_passport_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    passport: &Passport,
) -> Result<(), DppError> {
    let doc = serde_json::to_value(passport)
        .map_err(|e| DppError::Internal(format!("serialize: {e}")))?;
    let res = sqlx::query(
        r#"UPDATE odal.passport SET
             sector           = $2->>'sector',
             status           = COALESCE($2->>'status', status),
             retention_locked = COALESCE(($2->>'retentionLocked')::boolean, retention_locked),
             schema_version   = COALESCE($2->>'schemaVersion', schema_version),
             published_at     = COALESCE(NULLIF($2->>'publishedAt','')::timestamptz, published_at),
             doc              = $2
           WHERE id = $1"#,
    )
    .bind(passport.id.0)
    .bind(&doc)
    .execute(&mut **tx)
    .await
    .map_err(db_err)?;
    if res.rows_affected() == 0 {
        return Err(DppError::NotFound("record not found after update".into()));
    }
    Ok(())
}

/// PostgreSQL implementation of [`PassportRepository`].
///
/// Each method serialises to/from the `doc JSONB` column. Scalar columns
/// (`sector`, `status`, `retention_locked`, …) are extracted from the JSON
/// and stored redundantly as real columns to support indexed queries.
pub struct PgPassportRepo {
    dal: PgDal,
}

impl PgPassportRepo {
    /// Construct a repo sharing the given pool handle.
    pub fn new(dal: PgDal) -> Self {
        Self { dal }
    }

    fn to_doc(passport: &Passport) -> Result<serde_json::Value, DppError> {
        serde_json::to_value(passport).map_err(|e| DppError::Internal(format!("serialize: {e}")))
    }

    fn from_doc(doc: serde_json::Value) -> Result<Passport, DppError> {
        serde_json::from_value(doc).map_err(|e| DppError::Internal(format!("deserialize: {e}")))
    }

    fn uuid_of(id: PassportId) -> Uuid {
        id.0
    }
}

#[async_trait]
impl PassportRepository for PgPassportRepo {
    /// Persist a new passport; scalar columns are populated from the JSON doc.
    async fn create(&self, passport: Passport) -> Result<Passport, DppError> {
        let doc = Self::to_doc(&passport)?;
        let mut tx = self.dal.begin().await?;
        sqlx::query(
            r#"INSERT INTO odal.passport
                 (id, sector, status, retention_locked, schema_version,
                  created_at, updated_at, published_at, doc)
               VALUES ($1,
                       $2->>'sector',
                       COALESCE($2->>'status','draft'),
                       COALESCE(($2->>'retentionLocked')::boolean, false),
                       COALESCE($2->>'schemaVersion','1.0.0'),
                       now(), now(),
                       NULLIF($2->>'publishedAt','')::timestamptz,
                       $2)"#,
        )
        .bind(Self::uuid_of(passport.id))
        .bind(&doc)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;
        tx.commit().await.map_err(db_err)?;
        Ok(passport)
    }

    /// Fetch by id regardless of status — for authenticated internal reads.
    async fn find_by_id(&self, id: PassportId) -> Result<Option<Passport>, DppError> {
        let mut tx = self.dal.begin().await?;
        let row = sqlx::query("SELECT doc FROM odal.passport WHERE id = $1")
            .bind(Self::uuid_of(id))
            .fetch_optional(&mut *tx)
            .await
            .map_err(db_err)?;
        tx.commit().await.map_err(db_err)?;
        row.map(|r| Self::from_doc(r.get::<serde_json::Value, _>("doc")))
            .transpose()
    }

    /// Fetch only `active` (published) passports — public resolver path.
    async fn find_published_by_id(&self, id: PassportId) -> Result<Option<Passport>, DppError> {
        // Public resolver path: only active (published) passports are served.
        let row = sqlx::query("SELECT doc FROM odal.passport WHERE id = $1 AND status = 'active'")
            .bind(Self::uuid_of(id))
            .fetch_optional(self.dal.pool())
            .await
            .map_err(db_err)?;
        row.map(|r| Self::from_doc(r.get::<serde_json::Value, _>("doc")))
            .transpose()
    }

    /// Find an active passport by GTIN via LIKE scan on `qrCodeUrl`.
    ///
    /// O(n) over active passports — acceptable for single-tenant MVP scale.
    async fn find_published_by_gtin(&self, gtin: &str) -> Result<Option<Passport>, DppError> {
        // Battery GS1 DL URL: https://id.odal-node.io/01/{gtin}/21/{serialId}
        let row = sqlx::query(
            "SELECT doc FROM odal.passport \
             WHERE status = 'active' \
               AND doc->>'qrCodeUrl' LIKE '%/01/' || $1 || '/%' \
             LIMIT 1",
        )
        .bind(gtin)
        .fetch_optional(self.dal.pool())
        .await
        .map_err(db_err)?;
        row.map(|r| Self::from_doc(r.get::<serde_json::Value, _>("doc")))
            .transpose()
    }

    /// Find a passport by exact compound identity (sector, GTIN, batch),
    /// across `Draft` and `Published` — backs the import delta-matcher.
    /// Indexed by `0019_passport_identity_index.sql`. GTIN is read from
    /// `doc->'sectorData'->>'gtin'`: present for every sector except
    /// `UnsoldGoods`/`Other`, which carry no GTIN field and so never match
    /// here — a discard-event report and an untyped catch-all, not a query bug.
    async fn find_by_identity(
        &self,
        identity: &ProductIdentity,
    ) -> Result<Option<Passport>, DppError> {
        let sector_str = serde_json::to_value(&identity.sector)
            .ok()
            .and_then(|v| v.as_str().map(str::to_owned))
            .ok_or_else(|| DppError::Internal("failed to serialise sector".into()))?;
        let row = sqlx::query(
            "SELECT doc FROM odal.passport \
             WHERE status IN ('draft','active') \
               AND sector = $1 \
               AND doc->'sectorData'->>'gtin' = $2 \
               AND doc->>'batchId' IS NOT DISTINCT FROM $3 \
             LIMIT 1",
        )
        .bind(&sector_str)
        .bind(&identity.gtin)
        .bind(identity.batch_id.as_deref())
        .fetch_optional(self.dal.pool())
        .await
        .map_err(db_err)?;
        row.map(|r| Self::from_doc(r.get::<serde_json::Value, _>("doc")))
            .transpose()
    }

    /// Fetch by id without a status filter; equivalent to `find_by_id`.
    async fn find_by_id_any_status(&self, id: PassportId) -> Result<Option<Passport>, DppError> {
        let mut tx = self.dal.begin().await?;
        let row = sqlx::query("SELECT doc FROM odal.passport WHERE id = $1")
            .bind(Self::uuid_of(id))
            .fetch_optional(&mut *tx)
            .await
            .map_err(db_err)?;
        tx.commit().await.map_err(db_err)?;
        row.map(|r| Self::from_doc(r.get::<serde_json::Value, _>("doc")))
            .transpose()
    }

    /// Replace the stored doc; errors if no row with the given id exists.
    async fn update(&self, passport: Passport) -> Result<Passport, DppError> {
        let mut tx = self.dal.begin().await?;
        update_passport_in_tx(&mut tx, &passport).await?;
        tx.commit().await.map_err(db_err)?;
        Ok(passport)
    }

    /// Merge a partial JSON delta into the stored doc under a row-level lock.
    ///
    /// Concurrent callers serialise on `FOR UPDATE` — no last-write-wins
    /// clobbering. Null values in `delta` remove the corresponding key.
    async fn patch_fields(
        &self,
        id: PassportId,
        delta: serde_json::Value,
    ) -> Result<Passport, DppError> {
        let mut tx = self.dal.begin().await?;
        // Row lock makes concurrent patches serialise instead of clobbering.
        let row = sqlx::query("SELECT doc FROM odal.passport WHERE id = $1 FOR UPDATE")
            .bind(Self::uuid_of(id))
            .fetch_optional(&mut *tx)
            .await
            .map_err(db_err)?;
        let Some(row) = row else {
            return Err(DppError::NotFound(id.to_string()));
        };
        let mut doc: serde_json::Value = row.get("doc");
        if let (serde_json::Value::Object(dm), serde_json::Value::Object(pm)) = (&delta, &mut doc) {
            for (k, v) in dm {
                if v.is_null() {
                    pm.remove(k);
                } else {
                    pm.insert(k.clone(), v.clone());
                }
            }
        }
        let passport = Self::from_doc(doc.clone())?;
        sqlx::query(
            r#"UPDATE odal.passport SET
                 status = COALESCE($2->>'status', status),
                 doc    = $2
               WHERE id = $1"#,
        )
        .bind(Self::uuid_of(id))
        .bind(&doc)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;
        tx.commit().await.map_err(db_err)?;
        Ok(passport)
    }

    /// Convenience wrapper: load, set status and `updated_at`, then call `update`.
    async fn update_status(
        &self,
        id: PassportId,
        status: PassportStatus,
    ) -> Result<Passport, DppError> {
        let Some(mut passport) = self.find_by_id(id).await? else {
            return Err(DppError::NotFound(id.to_string()));
        };
        passport.status = status;
        passport.updated_at = chrono::Utc::now();
        self.update(passport).await
    }

    /// List passports with optional status filter, full-text ILIKE search, and
    /// exact `facilityId` match (ADR-006: facility is a grouping/filter
    /// dimension, never an isolation boundary).
    async fn list(
        &self,
        status: Option<PassportStatus>,
        q: Option<&str>,
        facility_id: Option<&str>,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<Passport>, DppError> {
        let needle = q.map(str::trim).filter(|s| !s.is_empty());
        let mut tx = self.dal.begin().await?;
        let rows = sqlx::query(
            r#"SELECT doc FROM odal.passport
               WHERE ($1::text IS NULL OR status = $1)
                 AND ($2::text IS NULL
                      OR doc->>'productName'           ILIKE '%' || $2 || '%'
                      OR doc->>'batchId'               ILIKE '%' || $2 || '%'
                      OR doc->'manufacturer'->>'name'  ILIKE '%' || $2 || '%')
                 AND ($3::text IS NULL OR doc->'facility'->>'value' = $3)
               ORDER BY created_at DESC
               LIMIT $4 OFFSET $5"#,
        )
        .bind(status.map(|s| s.to_string()))
        .bind(needle)
        .bind(facility_id)
        .bind(i64::from(limit))
        .bind(i64::from(offset))
        .fetch_all(&mut *tx)
        .await
        .map_err(db_err)?;
        tx.commit().await.map_err(db_err)?;
        rows.into_iter()
            .map(|r| Self::from_doc(r.get::<serde_json::Value, _>("doc")))
            .collect()
    }

    /// Count passports with optional status and `facilityId` filters (the
    /// latter giving ADR-006's "per-facility counts" without a new endpoint).
    async fn count(
        &self,
        status: Option<PassportStatus>,
        facility_id: Option<&str>,
    ) -> Result<u64, DppError> {
        let mut tx = self.dal.begin().await?;
        let total: i64 = sqlx::query_scalar(
            r#"SELECT COUNT(*) FROM odal.passport
               WHERE ($1::text IS NULL OR status = $1)
                 AND ($2::text IS NULL OR doc->'facility'->>'value' = $2)"#,
        )
        .bind(status.map(|s| s.to_string()))
        .bind(facility_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(db_err)?;
        tx.commit().await.map_err(db_err)?;
        Ok(total.max(0) as u64)
    }
}
