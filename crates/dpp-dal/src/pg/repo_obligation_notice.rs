//! PostgreSQL implementation of [`ObligationNoticeStore`] (`ops/pg/0050`).

use async_trait::async_trait;
use chrono::NaiveDate;
use sqlx::Row;
use uuid::Uuid;

use dpp_domain::DppError;
use dpp_types::obligation_notice::{basis_name, kind_name};
use dpp_types::{AnnouncedNotice, NoticeRecord, ObligationNoticeStore};

use super::repo_webhook::fan_out;
use super::{PgDal, db_err};

/// The ledger of announced notices, and the singleton day its pass starts from.
pub struct PgObligationNoticeRepo {
    dal: PgDal,
}

impl PgObligationNoticeRepo {
    /// Construct a repo sharing the given pool handle.
    pub fn new(dal: PgDal) -> Self {
        Self { dal }
    }
}

/// The lead time as the column stores it. Lead times are whole days from a
/// configuration that is read as `u32`, so this only refuses a value no
/// configuration can produce.
fn lead_column(lead: Option<u32>) -> Result<Option<i32>, DppError> {
    lead.map(|days| {
        i32::try_from(days)
            .map_err(|_| DppError::Internal(format!("lead time {days} exceeds the ledger")))
    })
    .transpose()
}

#[async_trait]
impl ObligationNoticeStore for PgObligationNoticeRepo {
    async fn ensure_active_since(&self, today: NaiveDate) -> Result<NaiveDate, DppError> {
        // `DO NOTHING`, not an update: the day is written by the first pass and
        // never moved. Two first passes racing on the primary key leave one row,
        // and both read that row back.
        sqlx::query(
            r#"INSERT INTO odal.obligation_notice_state (id, active_since)
               VALUES (1, $1)
               ON CONFLICT (id) DO NOTHING"#,
        )
        .bind(today)
        .execute(self.dal.pool())
        .await
        .map_err(db_err)?;
        let row = sqlx::query("SELECT active_since FROM odal.obligation_notice_state WHERE id = 1")
            .fetch_one(self.dal.pool())
            .await
            .map_err(db_err)?;
        Ok(row.get::<NaiveDate, _>("active_since"))
    }

    async fn announce(&self, notices: &[NoticeRecord]) -> Result<Vec<Uuid>, DppError> {
        // Taken in one order, so two instances recording overlapping sets wait on
        // each other's rows in the same sequence and cannot deadlock.
        let mut ordered: Vec<&NoticeRecord> = notices.iter().collect();
        ordered.sort_by_key(|notice| notice.notice_id);

        let mut tx = self.dal.pool().begin().await.map_err(db_err)?;
        let mut recorded = Vec::new();
        for notice in ordered {
            let inserted = sqlx::query(
                r#"INSERT INTO odal.obligation_notice
                     (notice_id, obligation_id, obligation_date, obligation_kind,
                      lead_days, notice_day, basis, body)
                   VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                   ON CONFLICT (notice_id) DO NOTHING"#,
            )
            .bind(notice.notice_id)
            .bind(&notice.obligation_id)
            .bind(notice.obligation_date)
            .bind(kind_name(notice.obligation_kind))
            .bind(lead_column(notice.lead_days)?)
            .bind(notice.notice_day)
            .bind(basis_name(notice.basis))
            .bind(&notice.body)
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;
            // Nothing inserted means the notice is already recorded, by an earlier
            // pass or by another instance. Only a notice this call recorded is
            // queued, so its deliveries are queued once.
            if inserted.rows_affected() == 1 {
                fan_out(&mut *tx, &notice.event_type, &notice.body).await?;
                recorded.push(notice.notice_id);
            }
        }
        tx.commit().await.map_err(db_err)?;
        Ok(recorded)
    }

    async fn announced(
        &self,
        from: NaiveDate,
        to: NaiveDate,
    ) -> Result<Vec<AnnouncedNotice>, DppError> {
        let rows = sqlx::query(
            r#"SELECT notice_id, obligation_id, obligation_date, lead_days, notice_day, announced_at
               FROM odal.obligation_notice
               WHERE obligation_date BETWEEN $1 AND $2
               ORDER BY obligation_date, obligation_id, notice_day"#,
        )
        .bind(from)
        .bind(to)
        .fetch_all(self.dal.pool())
        .await
        .map_err(db_err)?;
        rows.iter()
            .map(|row| {
                let lead: Option<i32> = row.get("lead_days");
                Ok(AnnouncedNotice {
                    notice_id: row.get("notice_id"),
                    obligation_id: row.get("obligation_id"),
                    obligation_date: row.get("obligation_date"),
                    lead_days: lead
                        .map(|d| {
                            u32::try_from(d).map_err(|_| {
                                DppError::Internal(format!("ledger lead time {d} is negative"))
                            })
                        })
                        .transpose()?,
                    notice_day: row.get("notice_day"),
                    announced_at: row.get("announced_at"),
                })
            })
            .collect()
    }
}
