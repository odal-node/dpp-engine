//! Job store trait and implementations for tracking async import jobs.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::domain::batch_runner::BatchResult;
use crate::domain::import_report::ImportReport;

// ─── Job model ────────────────────────────────────────────────────────────────

/// Lifecycle status of an async import job.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum JobStatus {
    Queued,
    Processing,
    Completed,
    Failed(String),
}

/// An async import job tracked in the job store.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportJob {
    pub id: Uuid,
    pub status: JobStatus,
    /// Total number of data rows in the uploaded file.
    pub total_rows: usize,
    /// Number of rows processed so far.
    pub processed: usize,
    /// Final batch result — populated when status transitions to Completed.
    pub result: Option<BatchResult>,
    /// The row-addressed findings report — set for every job, dry-run or
    /// apply, via [`JobStore::record_report`]. Independent of `result`:
    /// `result` is apply-mode's created/errors bookkeeping, `report` is the
    /// per-row validation outcome both modes share.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report: Option<ImportReport>,
    /// The dry-run job this job re-runs as an apply, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_job_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
}

impl ImportJob {
    /// Create a new job in `Queued` status with zero progress.
    pub fn new(id: Uuid, total_rows: usize) -> Self {
        Self {
            id,
            status: JobStatus::Queued,
            total_rows,
            processed: 0,
            result: None,
            report: None,
            parent_job_id: None,
            created_at: Utc::now(),
        }
    }
}

// ─── Trait ────────────────────────────────────────────────────────────────────

/// Persistent store for async import jobs.
///
/// Implementations:
/// - `InMemoryJobStore` — development / tests (data lost on restart)
/// - `PgJobStore`       — production (in `dpp-node`, persisted to PostgreSQL)
#[async_trait]
pub trait JobStore: Send + Sync {
    /// Persist a new job. Returns `Err` if the job could not be stored — the
    /// caller MUST NOT report success (e.g. a `202` with a job id) on failure,
    /// or it promises a job that can never be polled.
    async fn insert(&self, job: ImportJob) -> anyhow::Result<()>;
    /// Retrieve a job by id. Returns `None` if the id is unknown.
    async fn get(&self, id: Uuid) -> Option<ImportJob>;
    /// Transition a job to a new status (e.g. `Queued` → `Processing`).
    async fn set_status(&self, id: Uuid, status: JobStatus) -> anyhow::Result<()>;
    /// Mark the job `Completed` and store the final batch result.
    async fn complete(&self, id: Uuid, result: BatchResult) -> anyhow::Result<()>;
    /// Attach the row-addressed findings report to a job. Independent of
    /// `complete`/`result` — set for dry-run jobs (which never call
    /// `complete`, since there is no `BatchResult` without a vault call) and
    /// apply jobs alike, as soon as validation finishes.
    async fn record_report(&self, id: Uuid, report: ImportReport) -> anyhow::Result<()>;
    /// Delete completed/failed jobs older than `max_age`.
    async fn cleanup(&self, max_age: chrono::Duration);
}

// ─── In-memory implementation ────────────────────────────────────────────────

/// Thread-safe in-memory store for import jobs.
///
/// Uses `std::sync::RwLock` (never held across `.await` points) so it can be
/// called from both sync and async contexts without blocking the Tokio runtime.
///
/// Suitable for development and tests. In production, use `PgJobStore`.
pub struct InMemoryJobStore {
    jobs: std::sync::RwLock<std::collections::HashMap<Uuid, ImportJob>>,
}

impl InMemoryJobStore {
    /// Create an empty in-memory job store.
    pub fn new() -> Self {
        Self {
            jobs: std::sync::RwLock::new(std::collections::HashMap::new()),
        }
    }
}

impl Default for InMemoryJobStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl JobStore for InMemoryJobStore {
    async fn insert(&self, job: ImportJob) -> anyhow::Result<()> {
        self.jobs
            .write()
            .expect("job store write lock poisoned")
            .insert(job.id, job);
        Ok(())
    }

    async fn get(&self, id: Uuid) -> Option<ImportJob> {
        self.jobs
            .read()
            .expect("job store read lock poisoned")
            .get(&id)
            .cloned()
    }

    async fn set_status(&self, id: Uuid, status: JobStatus) -> anyhow::Result<()> {
        if let Some(job) = self
            .jobs
            .write()
            .expect("job store write lock poisoned")
            .get_mut(&id)
        {
            job.status = status;
        }
        Ok(())
    }

    async fn complete(&self, id: Uuid, result: BatchResult) -> anyhow::Result<()> {
        if let Some(job) = self
            .jobs
            .write()
            .expect("job store write lock poisoned")
            .get_mut(&id)
        {
            job.processed = job.total_rows;
            job.result = Some(result);
            job.status = JobStatus::Completed;
        }
        Ok(())
    }

    async fn record_report(&self, id: Uuid, report: ImportReport) -> anyhow::Result<()> {
        if let Some(job) = self
            .jobs
            .write()
            .expect("job store write lock poisoned")
            .get_mut(&id)
        {
            job.report = Some(report);
        }
        Ok(())
    }

    async fn cleanup(&self, max_age: chrono::Duration) {
        let cutoff = Utc::now() - max_age;
        self.jobs
            .write()
            .expect("job store write lock poisoned")
            .retain(|_, job| {
                let is_terminal = matches!(job.status, JobStatus::Completed | JobStatus::Failed(_));
                !(is_terminal && job.created_at < cutoff)
            });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::batch_runner::{CreatedItem, RowError};

    fn sample_result() -> BatchResult {
        BatchResult {
            created: vec![CreatedItem {
                row: 1,
                passport_id: "pp-1".into(),
            }],
            updated: vec![],
            errors: vec![RowError {
                row: 2,
                field: "gtin".into(),
                message: "invalid".into(),
            }],
        }
    }

    #[tokio::test]
    async fn insert_then_get_round_trips() {
        let store = InMemoryJobStore::new();
        let id = Uuid::now_v7();
        store.insert(ImportJob::new(id, 42)).await.unwrap();

        let job = store.get(id).await.expect("job should exist");
        assert_eq!(job.id, id);
        assert_eq!(job.total_rows, 42);
        assert_eq!(job.processed, 0);
        assert!(matches!(job.status, JobStatus::Queued));
        assert!(job.result.is_none());
    }

    #[tokio::test]
    async fn get_unknown_id_returns_none() {
        let store = InMemoryJobStore::new();
        assert!(store.get(Uuid::now_v7()).await.is_none());
    }

    #[tokio::test]
    async fn set_status_transitions_existing_job() {
        let store = InMemoryJobStore::new();
        let id = Uuid::now_v7();
        store.insert(ImportJob::new(id, 10)).await.unwrap();

        store.set_status(id, JobStatus::Processing).await.unwrap();
        let job = store.get(id).await.unwrap();
        assert!(matches!(job.status, JobStatus::Processing));
    }

    #[tokio::test]
    async fn set_status_on_unknown_id_is_a_silent_noop() {
        let store = InMemoryJobStore::new();
        // Must not panic or error — the caller can't distinguish "unknown id"
        // from "already cleaned up" and shouldn't need to.
        store
            .set_status(Uuid::now_v7(), JobStatus::Processing)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn complete_records_result_and_marks_processed() {
        let store = InMemoryJobStore::new();
        let id = Uuid::now_v7();
        store.insert(ImportJob::new(id, 5)).await.unwrap();

        store.complete(id, sample_result()).await.unwrap();

        let job = store.get(id).await.unwrap();
        assert!(matches!(job.status, JobStatus::Completed));
        assert_eq!(job.processed, job.total_rows);
        let result = job.result.expect("result should be recorded");
        assert_eq!(result.created.len(), 1);
        assert_eq!(result.errors.len(), 1);
    }

    #[tokio::test]
    async fn cleanup_removes_old_terminal_jobs_but_keeps_recent_and_active_ones() {
        let store = InMemoryJobStore::new();

        let old_completed = Uuid::now_v7();
        store
            .insert(ImportJob::new(old_completed, 1))
            .await
            .unwrap();
        store
            .complete(old_completed, sample_result())
            .await
            .unwrap();
        // Backdate creation so it's older than the cleanup cutoff.
        {
            let mut jobs = store.jobs.write().unwrap();
            jobs.get_mut(&old_completed).unwrap().created_at =
                Utc::now() - chrono::Duration::days(2);
        }

        let recent_completed = Uuid::now_v7();
        store
            .insert(ImportJob::new(recent_completed, 1))
            .await
            .unwrap();
        store
            .complete(recent_completed, sample_result())
            .await
            .unwrap();

        let old_but_active = Uuid::now_v7();
        store
            .insert(ImportJob::new(old_but_active, 1))
            .await
            .unwrap();
        store
            .set_status(old_but_active, JobStatus::Processing)
            .await
            .unwrap();
        {
            let mut jobs = store.jobs.write().unwrap();
            jobs.get_mut(&old_but_active).unwrap().created_at =
                Utc::now() - chrono::Duration::days(2);
        }

        store.cleanup(chrono::Duration::hours(1)).await;

        assert!(
            store.get(old_completed).await.is_none(),
            "old + terminal must be swept"
        );
        assert!(
            store.get(recent_completed).await.is_some(),
            "recent must survive"
        );
        assert!(
            store.get(old_but_active).await.is_some(),
            "old but non-terminal (still processing) must survive"
        );
    }
}
