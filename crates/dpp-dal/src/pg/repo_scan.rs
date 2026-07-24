//! `ScanTelemetryRepository` on PostgreSQL — upserted daily counters, keyed only
//! by `(passport, day, surface)`. No per-event rows and no scanner attributes
//! exist in the schema (`ops/pg/0025`); the DB `CHECK` also stops a QR render
//! being written as a scan.

use async_trait::async_trait;
use sqlx::Row;

use dpp_domain::{DppError, domain::passport::PassportId};
use dpp_types::scan::{
    DailyScanCount, OperatorScanStats, PassportScanStats, QrRenderIncrement, ScanIncrement,
    ScanPruneCounts, ScanTelemetryRepository,
};

use super::{PgDal, db_err};

/// PostgreSQL implementation of [`ScanTelemetryRepository`].
pub struct PgScanTelemetryRepo {
    dal: PgDal,
}

impl PgScanTelemetryRepo {
    /// Construct a repo sharing the given pool handle.
    pub fn new(dal: PgDal) -> Self {
        Self { dal }
    }
}

#[async_trait]
impl ScanTelemetryRepository for PgScanTelemetryRepo {
    async fn record_batch(
        &self,
        scans: &[ScanIncrement],
        qr_renders: &[QrRenderIncrement],
    ) -> Result<(), DppError> {
        if scans.is_empty() && qr_renders.is_empty() {
            return Ok(());
        }
        // One transaction over both tables so a flush lands atomically or not at
        // all — the resolver retains and retries the whole window on failure.
        let mut tx = self.dal.begin().await?;
        for s in scans {
            sqlx::query(
                r#"INSERT INTO odal.scan_telemetry (dpp_id, day, variant, count)
                   VALUES ($1, $2, $3, $4)
                   ON CONFLICT (dpp_id, day, variant)
                   DO UPDATE SET count = odal.scan_telemetry.count + EXCLUDED.count"#,
            )
            .bind(s.dpp_id.0)
            .bind(s.day)
            .bind(&s.variant)
            .bind(s.count)
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;
        }
        for q in qr_renders {
            sqlx::query(
                r#"INSERT INTO odal.qr_render (dpp_id, day, count)
                   VALUES ($1, $2, $3)
                   ON CONFLICT (dpp_id, day)
                   DO UPDATE SET count = odal.qr_render.count + EXCLUDED.count"#,
            )
            .bind(q.dpp_id.0)
            .bind(q.day)
            .bind(q.count)
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;
        }
        tx.commit().await.map_err(db_err)?;
        Ok(())
    }

    async fn passport_stats(
        &self,
        dpp_id: PassportId,
        window_days: i64,
    ) -> Result<PassportScanStats, DppError> {
        // `day >= today - (window_days - 1)` includes today, so window_days = 30
        // means "the last 30 calendar days".
        let totals = sqlx::query(
            r#"SELECT
                 COALESCE(SUM(count), 0)::bigint                                   AS total,
                 COALESCE(SUM(count) FILTER (WHERE variant = 'html'), 0)::bigint   AS html,
                 COALESCE(SUM(count) FILTER (WHERE variant = 'json'), 0)::bigint   AS json
               FROM odal.scan_telemetry
               WHERE dpp_id = $1 AND day >= CURRENT_DATE - ($2::int - 1)"#,
        )
        .bind(dpp_id.0)
        .bind(window_days)
        .fetch_one(self.dal.pool())
        .await
        .map_err(db_err)?;

        let daily_rows = sqlx::query(
            r#"SELECT day, SUM(count)::bigint AS count
               FROM odal.scan_telemetry
               WHERE dpp_id = $1 AND day >= CURRENT_DATE - ($2::int - 1)
               GROUP BY day
               ORDER BY day"#,
        )
        .bind(dpp_id.0)
        .bind(window_days)
        .fetch_all(self.dal.pool())
        .await
        .map_err(db_err)?;

        let qr_renders: i64 = sqlx::query_scalar(
            r#"SELECT COALESCE(SUM(count), 0)::bigint
               FROM odal.qr_render
               WHERE dpp_id = $1 AND day >= CURRENT_DATE - ($2::int - 1)"#,
        )
        .bind(dpp_id.0)
        .bind(window_days)
        .fetch_one(self.dal.pool())
        .await
        .map_err(db_err)?;

        Ok(PassportScanStats {
            window_days,
            total_scans: totals.get("total"),
            scans_html: totals.get("html"),
            scans_json: totals.get("json"),
            daily: daily_rows
                .into_iter()
                .map(|r| DailyScanCount {
                    day: r.get("day"),
                    count: r.get("count"),
                })
                .collect(),
            qr_renders,
        })
    }

    async fn operator_stats(&self, window_days: i64) -> Result<OperatorScanStats, DppError> {
        let row = sqlx::query(
            r#"SELECT
                 COALESCE(SUM(count), 0)::bigint      AS total,
                 COUNT(DISTINCT dpp_id)::bigint       AS distinct_passports
               FROM odal.scan_telemetry
               WHERE day >= CURRENT_DATE - ($1::int - 1)"#,
        )
        .bind(window_days)
        .fetch_one(self.dal.pool())
        .await
        .map_err(db_err)?;

        let total_qr: i64 = sqlx::query_scalar(
            r#"SELECT COALESCE(SUM(count), 0)::bigint
               FROM odal.qr_render
               WHERE day >= CURRENT_DATE - ($1::int - 1)"#,
        )
        .bind(window_days)
        .fetch_one(self.dal.pool())
        .await
        .map_err(db_err)?;

        Ok(OperatorScanStats {
            window_days,
            total_scans: row.get("total"),
            total_qr_renders: total_qr,
            distinct_passports_scanned: row.get("distinct_passports"),
        })
    }

    async fn prune(&self, horizon_days: i64) -> Result<ScanPruneCounts, DppError> {
        let mut tx = self.dal.begin().await?;
        let scans =
            sqlx::query("DELETE FROM odal.scan_telemetry WHERE day < CURRENT_DATE - ($1::int)")
                .bind(horizon_days)
                .execute(&mut *tx)
                .await
                .map_err(db_err)?
                .rows_affected();
        let qr_renders =
            sqlx::query("DELETE FROM odal.qr_render WHERE day < CURRENT_DATE - ($1::int)")
                .bind(horizon_days)
                .execute(&mut *tx)
                .await
                .map_err(db_err)?
                .rows_affected();
        tx.commit().await.map_err(db_err)?;
        Ok(ScanPruneCounts { scans, qr_renders })
    }
}
