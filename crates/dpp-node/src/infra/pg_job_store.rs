//! PostgreSQL-backed implementation of [`JobStore`].
//!
//! Status is flattened to a plain text column with the `Failed` reason stored
//! separately. Single-tenant: no operator scoping. `cleanup` is the one
//! sanctioned DELETE in the schema (import jobs are operational scratch data,
//! not regulatory records).

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use dpp_dal::pg::{PgDal, sqlx};
use dpp_integrator::{
    domain::batch_runner::BatchResult,
    domain::import_report::ImportReport,
    infra::job_store::{ImportJob, JobStatus, JobStore},
};
use sqlx::Row;

pub struct PgJobStore {
    dal: PgDal,
}

impl PgJobStore {
    pub fn new(dal: PgDal) -> Self {
        Self { dal }
    }

    fn split_status(status: &JobStatus) -> (&'static str, Option<String>) {
        match status {
            JobStatus::Queued => ("queued", None),
            JobStatus::Processing => ("processing", None),
            JobStatus::Completed => ("completed", None),
            JobStatus::Failed(reason) => ("failed", Some(reason.clone())),
        }
    }

    fn row_to_job(row: &sqlx::postgres::PgRow) -> Option<ImportJob> {
        let status = match row.get::<String, _>("status").as_str() {
            "queued" => JobStatus::Queued,
            "processing" => JobStatus::Processing,
            "completed" => JobStatus::Completed,
            "failed" => JobStatus::Failed(
                row.get::<Option<String>, _>("fail_reason")
                    .unwrap_or_else(|| "unknown".to_owned()),
            ),
            _ => return None,
        };
        let result: Option<BatchResult> = row
            .get::<Option<serde_json::Value>, _>("result")
            .and_then(|v| serde_json::from_value(v).ok());
        let report: Option<ImportReport> = row
            .get::<Option<serde_json::Value>, _>("report")
            .and_then(|v| serde_json::from_value(v).ok());
        Some(ImportJob {
            id: row.get("id"),
            status,
            total_rows: row.get::<i32, _>("total_rows").max(0) as usize,
            processed: row.get::<i32, _>("processed").max(0) as usize,
            result,
            report,
            parent_job_id: row.get::<Option<Uuid>, _>("parent_job_id"),
            created_at: row.get::<DateTime<Utc>, _>("created_at"),
        })
    }
}

#[async_trait]
impl JobStore for PgJobStore {
    async fn insert(&self, job: ImportJob) -> anyhow::Result<()> {
        let (status, fail_reason) = Self::split_status(&job.status);
        let result = job.result.as_ref().map(serde_json::to_value).transpose()?;
        let mut tx = self.dal.begin().await.map_err(|e| anyhow::anyhow!("{e}"))?;
        sqlx::query(
            r#"INSERT INTO odal.import_job
                 (id, status, fail_reason, total_rows, processed, result, created_at)
               VALUES ($1,$2,$3,$4,$5,$6,$7)"#,
        )
        .bind(job.id)
        .bind(status)
        .bind(fail_reason)
        .bind(job.total_rows as i32)
        .bind(job.processed as i32)
        .bind(result)
        .bind(job.created_at)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    async fn get(&self, id: Uuid) -> Option<ImportJob> {
        let mut tx = self.dal.begin().await.ok()?;
        let row = sqlx::query("SELECT * FROM odal.import_job WHERE id = $1")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await
            .ok()??;
        tx.commit().await.ok()?;
        Self::row_to_job(&row)
    }

    async fn set_status(&self, id: Uuid, status: JobStatus) -> anyhow::Result<()> {
        let (status_str, fail_reason) = Self::split_status(&status);
        let mut tx = self.dal.begin().await.map_err(|e| anyhow::anyhow!("{e}"))?;
        sqlx::query("UPDATE odal.import_job SET status = $2, fail_reason = $3 WHERE id = $1")
            .bind(id)
            .bind(status_str)
            .bind(fail_reason)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    async fn complete(&self, id: Uuid, result: BatchResult) -> anyhow::Result<()> {
        // On completion every row has been processed, so `processed` reflects the
        // job total — matching the InMemoryJobStore reference and the JobStore contract.
        let result_json = serde_json::to_value(&result)?;
        let mut tx = self.dal.begin().await.map_err(|e| anyhow::anyhow!("{e}"))?;
        sqlx::query(
            r#"UPDATE odal.import_job
               SET status = 'completed', processed = total_rows, result = $2
               WHERE id = $1"#,
        )
        .bind(id)
        .bind(result_json)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    async fn record_report(&self, id: Uuid, report: ImportReport) -> anyhow::Result<()> {
        let report_json = serde_json::to_value(&report)?;
        let mut tx = self.dal.begin().await.map_err(|e| anyhow::anyhow!("{e}"))?;
        sqlx::query("UPDATE odal.import_job SET report = $2 WHERE id = $1")
            .bind(id)
            .bind(report_json)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    async fn cleanup(&self, max_age: chrono::Duration) {
        let cutoff = Utc::now() - max_age;
        let Ok(mut tx) = self.dal.begin().await else {
            tracing::warn!("import job cleanup: could not open transaction");
            return;
        };
        match sqlx::query("DELETE FROM odal.import_job WHERE created_at < $1")
            .bind(cutoff)
            .execute(&mut *tx)
            .await
        {
            Ok(res) => {
                if tx.commit().await.is_ok() && res.rows_affected() > 0 {
                    tracing::info!(removed = res.rows_affected(), "import job cleanup");
                }
            }
            Err(e) => tracing::warn!(error = %e, "import job cleanup failed"),
        }
    }
}
