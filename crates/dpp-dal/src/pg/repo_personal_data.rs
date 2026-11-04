//! `PersonalDataPort` on PostgreSQL (`ops/pg/0043`).
//!
//! The holder of the records a passport's `personalData` statement names. Core
//! states the contract (`dpp_domain::ports::personal_data`); this is the part
//! that is about where the records live.
//!
//! # Its own table, and nothing else's neighbour
//!
//! `odal.personal_data_record` is not a column of `odal.passport`, and no query
//! that builds a passport view, an archived version, a snapshot, an audit entry
//! or a back-up copy reads it. A record lodged with any of those could not be
//! erased with this one, which is the reason the store exists at all.
//!
//! # Erasure keeps the row
//!
//! Erasing is an `UPDATE` that drops `content` and stamps `erased_at`, not a
//! `DELETE`: the row is the tombstone, and the app role has no `DELETE` on this
//! table. The tombstone is not free of personal data — the passport identifier
//! can relate to whoever owns the item — so it is kept only as long as the
//! controller has a basis to keep it, and this table has no sweep that decides
//! when that is.
//!
//! The retry rule needs no lock beyond the row's own. Two concurrent erasures of
//! one record both run the `UPDATE`; the second waits for the first's commit,
//! re-reads the row, finds it erased, and matches nothing. It then reads the
//! receipt the first one wrote, so both callers are handed the same one.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::Row;
use uuid::Uuid;

use dpp_domain::DppError;
use dpp_domain::passport::PassportId;
use dpp_domain::personal_data::PersonalDataRecordId;
use dpp_domain::ports::personal_data::{
    ErasureReceipt, HeldRecord, PersonalDataPort, PersonalDataRecord,
};

use super::{PgDal, db_err};

/// PostgreSQL implementation of core's [`PersonalDataPort`].
pub struct PgPersonalDataRepo {
    dal: PgDal,
}

impl PgPersonalDataRepo {
    /// Construct a repo sharing the given pool handle.
    pub fn new(dal: PgDal) -> Self {
        Self { dal }
    }
}

/// An identifier this store minted is a UUID, so anything else was never minted
/// here: it names no record, and is answered the way an unknown UUID is.
fn parse(record: &PersonalDataRecordId) -> Option<Uuid> {
    Uuid::parse_str(record.as_str()).ok()
}

fn unknown(record: &PersonalDataRecordId) -> DppError {
    DppError::NotFound(format!("no personal data record {record} is held here"))
}

/// Every column a lookup needs, in one place so the three reads cannot select
/// different sets.
macro_rules! columns {
    () => {
        "id, passport_id, field, content, stored_at, erased_at"
    };
}

fn held_from(row: &sqlx::postgres::PgRow) -> Result<HeldRecord, DppError> {
    let id = PersonalDataRecordId::new(row.get::<Uuid, _>("id").to_string());
    let passport_id = PassportId(row.get::<Uuid, _>("passport_id"));
    let field = row.get::<String, _>("field");

    if let Some(erased_at) = row.get::<Option<DateTime<Utc>>, _>("erased_at") {
        return Ok(HeldRecord::Erased(ErasureReceipt {
            record: id,
            passport_id,
            field,
            erased_at,
        }));
    }
    // Present and without content is a state the table's CHECK refuses; saying
    // so beats reading it as an empty record.
    let Some(content) = row.get::<Option<serde_json::Value>, _>("content") else {
        return Err(DppError::Internal(format!(
            "personal data record {id} is neither erased nor holds content"
        )));
    };
    Ok(HeldRecord::Present(PersonalDataRecord {
        id,
        passport_id,
        field,
        content,
        stored_at: row.get::<DateTime<Utc>, _>("stored_at"),
    }))
}

fn receipt_from(row: &sqlx::postgres::PgRow) -> ErasureReceipt {
    ErasureReceipt {
        record: PersonalDataRecordId::new(row.get::<Uuid, _>("id").to_string()),
        passport_id: PassportId(row.get::<Uuid, _>("passport_id")),
        field: row.get::<String, _>("field"),
        erased_at: row.get::<DateTime<Utc>, _>("erased_at"),
    }
}

#[async_trait]
impl PersonalDataPort for PgPersonalDataRepo {
    async fn store(
        &self,
        passport_id: PassportId,
        field: &str,
        content: &serde_json::Value,
    ) -> Result<PersonalDataRecordId, DppError> {
        let id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO odal.personal_data_record (id, passport_id, field, content)
               VALUES ($1, $2, $3, $4)",
        )
        .bind(id)
        .bind(passport_id.0)
        .bind(field)
        .bind(content)
        .execute(self.dal.pool())
        .await
        .map_err(|e| match &e {
            // The passport is the thing a record hangs off. A node that has no
            // row for it has nothing to hold the record for.
            sqlx::Error::Database(db) if db.is_foreign_key_violation() => {
                DppError::NotFound(format!("no passport {} is held here", passport_id.0))
            }
            _ => db_err(e),
        })?;
        Ok(PersonalDataRecordId::new(id.to_string()))
    }

    async fn fetch(&self, record: &PersonalDataRecordId) -> Result<Option<HeldRecord>, DppError> {
        let Some(id) = parse(record) else {
            return Ok(None);
        };
        let row = sqlx::query(concat!(
            "SELECT ",
            columns!(),
            " FROM odal.personal_data_record WHERE id = $1"
        ))
        .bind(id)
        .fetch_optional(self.dal.pool())
        .await
        .map_err(db_err)?;
        row.as_ref().map(held_from).transpose()
    }

    async fn records_for(&self, passport_id: PassportId) -> Result<Vec<HeldRecord>, DppError> {
        // `id` breaks a tie between two records stored in the same instant; it
        // is a UUID v7, so it orders as they were minted.
        let rows = sqlx::query(concat!(
            "SELECT ",
            columns!(),
            " FROM odal.personal_data_record
               WHERE passport_id = $1
               ORDER BY stored_at, id"
        ))
        .bind(passport_id.0)
        .fetch_all(self.dal.pool())
        .await
        .map_err(db_err)?;
        rows.iter().map(held_from).collect()
    }

    async fn erase(&self, record: &PersonalDataRecordId) -> Result<ErasureReceipt, DppError> {
        let id = parse(record).ok_or_else(|| unknown(record))?;

        let erased = sqlx::query(
            "UPDATE odal.personal_data_record
                SET content = NULL, erased_at = now()
              WHERE id = $1 AND erased_at IS NULL
          RETURNING id, passport_id, field, erased_at",
        )
        .bind(id)
        .fetch_optional(self.dal.pool())
        .await
        .map_err(db_err)?;
        if let Some(row) = erased {
            return Ok(receipt_from(&row));
        }

        // Nothing was erased by this call: the record is either unknown or was
        // erased already, by an earlier call or by one that committed while this
        // one waited. The receipt is the first one's either way.
        let row = sqlx::query(
            "SELECT id, passport_id, field, erased_at
               FROM odal.personal_data_record
              WHERE id = $1 AND erased_at IS NOT NULL",
        )
        .bind(id)
        .fetch_optional(self.dal.pool())
        .await
        .map_err(db_err)?;
        row.as_ref()
            .map(receipt_from)
            .ok_or_else(|| unknown(record))
    }
}
