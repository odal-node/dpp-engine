//! `UnsoldGoodsStore` on PostgreSQL (`ops/pg/0044`).
//!
//! One row per financial year, no outbox and no state machine. The report is
//! stored whole as `report`; the financial year is projected out of it because
//! it is the key, so recording a year again replaces its row.

use async_trait::async_trait;
use chrono::{DateTime, NaiveDate, Utc};
use sqlx::Row;

use dpp_domain::{DppError, UnsoldGoodsReport};
use dpp_types::{UnsoldGoodsDisclosure, UnsoldGoodsStore};

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

    fn row_to_disclosure(row: &sqlx::postgres::PgRow) -> Result<UnsoldGoodsDisclosure, DppError> {
        let report = serde_json::from_value(row.get::<serde_json::Value, _>("report"))
            .map_err(|e| DppError::Serialisation(format!("stored unsold-goods report: {e}")))?;
        Ok(UnsoldGoodsDisclosure {
            report,
            recorded_by: row.get("recorded_by"),
            created_at: row.get::<DateTime<Utc>, _>("created_at"),
            updated_at: row.get::<DateTime<Utc>, _>("updated_at"),
        })
    }
}

#[async_trait]
impl UnsoldGoodsStore for PgUnsoldGoodsRepo {
    async fn put(
        &self,
        report: &UnsoldGoodsReport,
        recorded_by: &str,
    ) -> Result<UnsoldGoodsDisclosure, DppError> {
        let doc = serde_json::to_value(report)
            .map_err(|e| DppError::Serialisation(format!("unsold-goods report: {e}")))?;
        let row = sqlx::query(
            r#"INSERT INTO odal.unsold_goods_disclosure
                 (financial_year_start, financial_year_end, report, recorded_by)
               VALUES ($1, $2, $3, $4)
               ON CONFLICT (financial_year_start) DO UPDATE SET
                 financial_year_end = EXCLUDED.financial_year_end,
                 report             = EXCLUDED.report,
                 recorded_by        = EXCLUDED.recorded_by,
                 updated_at         = now()
               RETURNING report, recorded_by, created_at, updated_at"#,
        )
        .bind(report.financial_year.start)
        .bind(report.financial_year.end)
        .bind(&doc)
        .bind(recorded_by)
        .fetch_one(self.dal.pool())
        .await
        .map_err(db_err)?;
        Self::row_to_disclosure(&row)
    }

    async fn get(&self, start: NaiveDate) -> Result<Option<UnsoldGoodsDisclosure>, DppError> {
        let row = sqlx::query(
            r#"SELECT report, recorded_by, created_at, updated_at
               FROM odal.unsold_goods_disclosure
               WHERE financial_year_start = $1"#,
        )
        .bind(start)
        .fetch_optional(self.dal.pool())
        .await
        .map_err(db_err)?;
        row.as_ref().map(Self::row_to_disclosure).transpose()
    }

    async fn list(&self) -> Result<Vec<UnsoldGoodsDisclosure>, DppError> {
        let rows = sqlx::query(
            r#"SELECT report, recorded_by, created_at, updated_at
               FROM odal.unsold_goods_disclosure
               ORDER BY financial_year_start DESC"#,
        )
        .fetch_all(self.dal.pool())
        .await
        .map_err(db_err)?;
        rows.iter().map(Self::row_to_disclosure).collect()
    }
}
