//! `DiscardRecordStore` on PostgreSQL (`ops/pg/0051`, `0052`).
//!
//! A record and the passports it names are written in one transaction. Nothing
//! is updated or deleted: the tables are append-only for the app role, so a
//! discard counted once stays counted.

use std::collections::HashMap;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::Row;
use uuid::Uuid;

use dpp_domain::{
    DppError, FieldError, ValidationErrors,
    unsold_goods::{DiscardRecord, EvidenceKind, FinancialYear},
};
use dpp_types::{DiscardRecordStore, StoredDiscardRecord};

use super::{PgDal, db_err};

/// PostgreSQL implementation of the discard-record store.
pub struct PgDiscardRecordRepo {
    dal: PgDal,
}

impl PgDiscardRecordRepo {
    /// Construct a repo sharing the given pool handle.
    pub fn new(dal: PgDal) -> Self {
        Self { dal }
    }

    /// The passports each of `ids` names, keyed by record.
    async fn passport_ids_of(&self, ids: &[Uuid]) -> Result<HashMap<Uuid, Vec<Uuid>>, DppError> {
        let rows = sqlx::query(
            "SELECT discard_record_id, passport_id
               FROM odal.discard_record_passport
              WHERE discard_record_id = ANY($1::uuid[])
              ORDER BY passport_id",
        )
        .bind(ids)
        .fetch_all(self.dal.pool())
        .await
        .map_err(db_err)?;
        let mut by_record: HashMap<Uuid, Vec<Uuid>> = HashMap::new();
        for row in &rows {
            by_record
                .entry(row.get::<Uuid, _>("discard_record_id"))
                .or_default()
                .push(row.get::<Uuid, _>("passport_id"));
        }
        Ok(by_record)
    }
}

/// The wire name of an evidence kind, which is what the link table stores.
fn kind_name(kind: EvidenceKind) -> Result<String, DppError> {
    match serde_json::to_value(kind).map_err(|e| DppError::Serialisation(e.to_string()))? {
        serde_json::Value::String(name) => Ok(name),
        other => Err(DppError::Serialisation(format!(
            "an evidence kind serialised as {other}, not as a name"
        ))),
    }
}

/// The evidence kind a stored name stands for.
fn kind_from_name(name: &str) -> Result<EvidenceKind, DppError> {
    serde_json::from_value(serde_json::Value::String(name.to_owned())).map_err(|e| {
        DppError::Internal(format!(
            "stored evidence kind `{name}` is not one core knows: {e}"
        ))
    })
}

/// Join a passport to the discard record that documents its destruction.
///
/// Called by the state-change commit, inside the transaction that writes the
/// destruction's status, so the join exists exactly when the destruction does.
/// A record id this node does not hold is refused by the foreign key, which fails
/// the whole change. Idempotent: a join already held is not written again.
pub(crate) async fn link_passport_in_tx<'e>(
    executor: impl sqlx::PgExecutor<'e>,
    record_id: Uuid,
    passport: dpp_domain::passport::PassportId,
) -> Result<(), DppError> {
    sqlx::query(
        "INSERT INTO odal.discard_record_passport (discard_record_id, passport_id)
         VALUES ($1, $2)
         ON CONFLICT DO NOTHING",
    )
    .bind(record_id)
    .bind(passport.0)
    .execute(executor)
    .await
    .map_err(db_err)?;
    Ok(())
}

fn row_to_record(row: &sqlx::postgres::PgRow) -> Result<StoredDiscardRecord, DppError> {
    let doc: serde_json::Value = row.get("record");
    let record: DiscardRecord = serde_json::from_value(doc)
        .map_err(|e| DppError::Internal(format!("stored discard record does not read: {e}")))?;
    Ok(StoredDiscardRecord {
        id: row.get::<Uuid, _>("id"),
        schema_version: row.get::<String, _>("schema_version"),
        record,
        passport_ids: Vec::new(),
        created_at: row.get::<DateTime<Utc>, _>("created_at"),
    })
}

#[async_trait]
impl DiscardRecordStore for PgDiscardRecordRepo {
    async fn create(
        &self,
        record: &DiscardRecord,
        schema_version: &str,
        passport_ids: &[Uuid],
    ) -> Result<StoredDiscardRecord, DppError> {
        let mut passports: Vec<Uuid> = passport_ids.to_vec();
        passports.sort_unstable();
        passports.dedup();
        let doc =
            serde_json::to_value(record).map_err(|e| DppError::Serialisation(e.to_string()))?;
        let id = Uuid::now_v7();

        let mut tx = self.dal.pool().begin().await.map_err(db_err)?;

        // Checked here rather than left to the foreign key, whose violation would
        // read as a database fault. Every passport it names is listed.
        if !passports.is_empty() {
            let held: Vec<Uuid> =
                sqlx::query("SELECT id FROM odal.passport WHERE id = ANY($1::uuid[])")
                    .bind(&passports)
                    .fetch_all(&mut *tx)
                    .await
                    .map_err(db_err)?
                    .iter()
                    .map(|row| row.get::<Uuid, _>("id"))
                    .collect();
            let missing: Vec<String> = passports
                .iter()
                .filter(|p| !held.contains(p))
                .map(ToString::to_string)
                .collect();
            if !missing.is_empty() {
                return Err(DppError::Validation(ValidationErrors {
                    errors: vec![FieldError {
                        field: "/passportIds".to_owned(),
                        message: format!(
                            "these passports are not held by this node: {}",
                            missing.join(", ")
                        ),
                    }],
                }));
            }
        }

        let created_at: DateTime<Utc> = sqlx::query(
            "INSERT INTO odal.discard_record (id, schema_version, discarded_on, record)
             VALUES ($1, $2, $3, $4)
             RETURNING created_at",
        )
        .bind(id)
        .bind(schema_version)
        .bind(record.discarded_on)
        .bind(doc)
        .fetch_one(&mut *tx)
        .await
        .map_err(db_err)?
        .get::<DateTime<Utc>, _>("created_at");

        for passport in &passports {
            sqlx::query(
                "INSERT INTO odal.discard_record_passport (discard_record_id, passport_id)
                 VALUES ($1, $2)",
            )
            .bind(id)
            .bind(*passport)
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;
        }

        tx.commit().await.map_err(db_err)?;
        Ok(StoredDiscardRecord {
            id,
            schema_version: schema_version.to_owned(),
            record: record.clone(),
            passport_ids: passports,
            created_at,
        })
    }

    async fn get(&self, id: Uuid) -> Result<Option<StoredDiscardRecord>, DppError> {
        let Some(row) = sqlx::query(
            "SELECT id, schema_version, record, created_at
               FROM odal.discard_record
              WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(self.dal.pool())
        .await
        .map_err(db_err)?
        else {
            return Ok(None);
        };
        let mut stored = row_to_record(&row)?;
        stored.passport_ids = self
            .passport_ids_of(&[id])
            .await?
            .remove(&id)
            .unwrap_or_default();
        Ok(Some(stored))
    }

    async fn list_for_year(
        &self,
        year: FinancialYear,
    ) -> Result<Vec<StoredDiscardRecord>, DppError> {
        let rows = sqlx::query(
            "SELECT id, schema_version, record, created_at
               FROM odal.discard_record
              WHERE discarded_on BETWEEN $1 AND $2
              ORDER BY discarded_on, id",
        )
        .bind(year.start)
        .bind(year.end)
        .fetch_all(self.dal.pool())
        .await
        .map_err(db_err)?;
        let mut records = rows
            .iter()
            .map(row_to_record)
            .collect::<Result<Vec<_>, _>>()?;
        let ids: Vec<Uuid> = records.iter().map(|r| r.id).collect();
        let mut passports = self.passport_ids_of(&ids).await?;
        for record in &mut records {
            record.passport_ids = passports.remove(&record.id).unwrap_or_default();
        }
        Ok(records)
    }

    async fn attach(
        &self,
        record_id: Uuid,
        kind: EvidenceKind,
        sha256: &str,
    ) -> Result<bool, DppError> {
        let result = sqlx::query(
            "INSERT INTO odal.discard_record_evidence (discard_record_id, evidence_sha256, kind)
             VALUES ($1, $2, $3)
             ON CONFLICT DO NOTHING",
        )
        .bind(record_id)
        .bind(sha256)
        .bind(kind_name(kind)?)
        .execute(self.dal.pool())
        .await
        .map_err(db_err)?;
        Ok(result.rows_affected() == 1)
    }

    async fn held_kinds(&self, record_id: Uuid) -> Result<Vec<EvidenceKind>, DppError> {
        let rows = sqlx::query(
            "SELECT DISTINCT kind
               FROM odal.discard_record_evidence
              WHERE discard_record_id = $1
              ORDER BY kind",
        )
        .bind(record_id)
        .fetch_all(self.dal.pool())
        .await
        .map_err(db_err)?;
        rows.iter()
            .map(|row| kind_from_name(&row.get::<String, _>("kind")))
            .collect()
    }
}
