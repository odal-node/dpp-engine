//! `UnsoldGoodsStore` on PostgreSQL (`ops/pg/0008`, `0035`).
//!
//! One table, no outbox and no state machine: an Art. 24 disclosure line is
//! written once and read back. `operator_id`/`operator_name` are report
//! *content* — the operator the disclosure is about — and not a tenant key, so
//! neither is used to scope a query. The node is single-tenant; every row it
//! holds is its own operator's.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::Row;
use uuid::Uuid;

use dpp_domain::DppError;
use dpp_types::{CreateUnsoldGoodsEntry, UnsoldGoodsEntry, UnsoldGoodsStore};

use super::{PgDal, db_err};

/// PostgreSQL implementation of the unsold-goods disclosure store.
pub struct PgUnsoldGoodsRepo {
    dal: PgDal,
}

impl PgUnsoldGoodsRepo {
    /// Construct a repo sharing the given pool handle.
    pub fn new(dal: PgDal) -> Self {
        Self { dal }
    }

    fn row_to_entry(row: &sqlx::postgres::PgRow) -> UnsoldGoodsEntry {
        UnsoldGoodsEntry {
            id: row.get::<Uuid, _>("id"),
            reporting_period: row.get::<String, _>("reporting_period"),
            unit_count: row.get::<Option<i64>, _>("unit_count"),
            volume_kg: row.get::<f64, _>("volume_kg"),
            product_category: row.get::<String, _>("product_category"),
            reason: row.get::<String, _>("reason"),
            destination: row.get::<String, _>("destination"),
            destruction_justification: row.get::<Option<String>, _>("destruction_justification"),
            country_of_disposal: row.get::<String, _>("country_of_disposal"),
            operator_name: row.get::<Option<String>, _>("operator_name"),
            created_at: row.get::<DateTime<Utc>, _>("created_at"),
        }
    }
}

/// Every column the read model needs, in one place so the two queries cannot
/// select different sets and diverge on which fields come back populated.
///
/// A macro rather than a `const`, because sqlx 0.9 takes a statically-known
/// query string and rejects one built with `format!`. `concat!` splices this at
/// compile time, so both statements stay literals and the list is still written
/// once.
macro_rules! columns {
    () => {
        "id, reporting_period, unit_count, volume_kg, product_category, reason, \
         destination, destruction_justification, country_of_disposal, \
         operator_name, created_at"
    };
}

#[async_trait]
impl UnsoldGoodsStore for PgUnsoldGoodsRepo {
    async fn create(
        &self,
        entry: &CreateUnsoldGoodsEntry,
        operator_id: &str,
        operator_name: Option<&str>,
    ) -> Result<UnsoldGoodsEntry, DppError> {
        let row = sqlx::query(concat!(
            "INSERT INTO odal.unsold_goods_report
                 (operator_id, operator_name, reporting_period, unit_count, volume_kg,
                  product_category, reason, destination, destruction_justification,
                  country_of_disposal)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
               RETURNING ",
            columns!()
        ))
        .bind(operator_id)
        .bind(operator_name)
        .bind(&entry.reporting_period)
        .bind(entry.unit_count)
        .bind(entry.volume_kg)
        .bind(entry.product_category.as_str())
        .bind(entry.reason.as_str())
        .bind(entry.destination.as_str())
        .bind(entry.destruction_justification.as_deref())
        .bind(entry.country_of_disposal.to_uppercase())
        .fetch_one(self.dal.pool())
        .await
        .map_err(db_err)?;
        Ok(Self::row_to_entry(&row))
    }

    async fn list(
        &self,
        reporting_period: Option<&str>,
    ) -> Result<Vec<UnsoldGoodsEntry>, DppError> {
        // One statement with a null-guarded predicate rather than two query
        // strings: the filter is optional, and branching on it is how the two
        // column lists drift apart.
        let rows = sqlx::query(concat!(
            "SELECT ",
            columns!(),
            " FROM odal.unsold_goods_report
               WHERE ($1::text IS NULL OR reporting_period = $1)
               ORDER BY created_at DESC"
        ))
        .bind(reporting_period)
        .fetch_all(self.dal.pool())
        .await
        .map_err(db_err)?;
        Ok(rows.iter().map(Self::row_to_entry).collect())
    }
}
