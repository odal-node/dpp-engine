//! Job store trait and implementations for tracking async import jobs.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::domain::batch_runner::BatchResult;

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
