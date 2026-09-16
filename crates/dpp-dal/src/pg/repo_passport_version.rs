//! Historical versions of a passport — EN 18221:2026 clause 4.2 archiving.
//!
//! 🚨 Not `PassportStatus::Archived`, which is a terminal lifecycle state. See
//! `ops/pg/0040_passport_version.sql` for why both wear the word.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::Row;

use dpp_domain::DppError;
use dpp_types::audit::{PassportVersion, PassportVersionStore};

use super::{PgDal, db_err};

/// PostgreSQL-backed archive of passport versions.
pub struct PgPassportVersionRepo {
    dal: PgDal,
}

impl PgPassportVersionRepo {
    /// Construct a repo sharing the given pool handle.
    pub fn new(dal: PgDal) -> Self {
        Self { dal }
    }
}

fn row_to_version(row: &sqlx::postgres::PgRow) -> Result<PassportVersion, DppError> {
    Ok(PassportVersion {
        id: row.try_get("id").map_err(db_err)?,
        passport_id: row
            .try_get::<uuid::Uuid, _>("passport_id")
            .map_err(db_err)?
            .to_string(),
        doc: row.try_get("doc").map_err(db_err)?,
        superseded_at: row.try_get("superseded_at").map_err(db_err)?,
    })
}

fn passport_uuid(passport_id: &str) -> Result<uuid::Uuid, DppError> {
    uuid::Uuid::parse_str(passport_id)
        .map_err(|e| DppError::Validation(format!("passport id is not a UUID: {e}").into()))
}

#[async_trait]
impl PassportVersionStore for PgPassportVersionRepo {
    async fn archive(
        &self,
        passport_id: &str,
        doc: &serde_json::Value,
        superseded_at: DateTime<Utc>,
    ) -> Result<(), DppError> {
        sqlx::query(
            "INSERT INTO odal.passport_version (id, passport_id, doc, superseded_at)
             VALUES ($1, $2, $3, $4)",
        )
        .bind(uuid::Uuid::now_v7())
        .bind(passport_uuid(passport_id)?)
        .bind(doc)
        .bind(superseded_at)
        .execute(self.dal.pool())
        .await
        .map_err(db_err)?;
        Ok(())
    }

    async fn versions(&self, passport_id: &str) -> Result<Vec<PassportVersion>, DppError> {
        let rows = sqlx::query(
            "SELECT id, passport_id, doc, superseded_at
               FROM odal.passport_version
              WHERE passport_id = $1
              ORDER BY superseded_at ASC, id ASC",
        )
        .bind(passport_uuid(passport_id)?)
        .fetch_all(self.dal.pool())
        .await
        .map_err(db_err)?;
        rows.iter().map(row_to_version).collect()
    }

    async fn version_at(
        &self,
        passport_id: &str,
        at: DateTime<Utc>,
    ) -> Result<Option<PassportVersion>, DppError> {
        // The earliest version that was still current at `at` — that is, the
        // first one to stop being current *after* it.
        //
        // `>` rather than `>=` deliberately. `superseded_at` is the instant the
        // replacement was applied, so at exactly that instant the new version is
        // the current one. Asking "as of the moment of a change" should answer
        // with what the change produced, not with what it replaced.
        let row = sqlx::query(
            "SELECT id, passport_id, doc, superseded_at
               FROM odal.passport_version
              WHERE passport_id = $1 AND superseded_at > $2
              ORDER BY superseded_at ASC, id ASC
              LIMIT 1",
        )
        .bind(passport_uuid(passport_id)?)
        .bind(at)
        .fetch_optional(self.dal.pool())
        .await
        .map_err(db_err)?;
        row.as_ref().map(row_to_version).transpose()
    }
}
