//! `ScanTelemetryRepository` on PostgreSQL — upserted daily counters, keyed only
//! by `(passport, day, surface)`. No per-event rows and no scanner attributes
//! exist in the schema (`ops/pg/0025`); the DB `CHECK` also stops a QR render
//! being written as a scan.

use async_trait::async_trait;
use chrono::NaiveDate;
use sqlx::Row;

use dpp_domain::{DppError, passport::PassportId};
use dpp_types::scan::{
    DailyScanCount, OperatorScanStats, PassportScanStats, QrRenderIncrement, ScanIncrement,
    ScanPruneCounts, ScanTelemetryRepository,
};

use super::{PgDal, db_err};

/// Split increments into the parallel arrays `UNNEST` takes.
///
/// Separate from the query so the column order is stated once; a transposition
/// here would bind days as variants and fail loudly at the type cast rather
/// than writing plausible-looking wrong rows.
fn unzip_scans(
    scans: &[ScanIncrement],
) -> (Vec<uuid::Uuid>, Vec<NaiveDate>, Vec<String>, Vec<i64>) {
    let mut ids = Vec::with_capacity(scans.len());
    let mut days = Vec::with_capacity(scans.len());
    let mut variants = Vec::with_capacity(scans.len());
    let mut counts = Vec::with_capacity(scans.len());
    for s in scans {
        ids.push(s.dpp_id.0);
        days.push(s.day);
        variants.push(s.variant.clone());
        counts.push(s.count);
    }
    (ids, days, variants, counts)
}

/// The [`unzip_scans`] counterpart for QR renders, which carry no variant.
fn unzip_qr_renders(qr: &[QrRenderIncrement]) -> (Vec<uuid::Uuid>, Vec<NaiveDate>, Vec<i64>) {
    let mut ids = Vec::with_capacity(qr.len());
    let mut days = Vec::with_capacity(qr.len());
    let mut counts = Vec::with_capacity(qr.len());
    for q in qr {
        ids.push(q.dpp_id.0);
        days.push(q.day);
        counts.push(q.count);
    }
    (ids, days, counts)
}

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

        if !scans.is_empty() {
            let (ids, days, variants, counts) = unzip_scans(scans);
            sqlx::query(
                r#"INSERT INTO odal.scan_telemetry (dpp_id, day, variant, count)
                   SELECT dpp_id, day, variant, SUM(count)
                     FROM UNNEST($1::uuid[], $2::date[], $3::text[], $4::bigint[])
                          AS t(dpp_id, day, variant, count)
                    GROUP BY dpp_id, day, variant
                   ON CONFLICT (dpp_id, day, variant)
                   DO UPDATE SET count = odal.scan_telemetry.count + EXCLUDED.count"#,
            )
            .bind(&ids)
            .bind(&days)
            .bind(&variants)
            .bind(&counts)
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;
        }

        if !qr_renders.is_empty() {
            let (ids, days, counts) = unzip_qr_renders(qr_renders);
            sqlx::query(
                r#"INSERT INTO odal.qr_render (dpp_id, day, count)
                   SELECT dpp_id, day, SUM(count)
                     FROM UNNEST($1::uuid[], $2::date[], $3::bigint[])
                          AS t(dpp_id, day, count)
                    GROUP BY dpp_id, day
                   ON CONFLICT (dpp_id, day)
                   DO UPDATE SET count = odal.qr_render.count + EXCLUDED.count"#,
            )
            .bind(&ids)
            .bind(&days)
            .bind(&counts)
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
            // Liveness is not the database's to know — the handler overlays it
            // from what this process has actually received. See `scan_liveness`.
            ingesting: false,
            last_ingest_at: None,
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
            ingesting: false,
            last_ingest_at: None,
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
