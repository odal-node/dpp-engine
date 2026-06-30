//! Shared Axum application state for the integrator service.

use std::sync::Arc;

use crate::infra::{job_store::JobStore, vault_client::VaultHttpClient};

/// Shared application state injected into every Axum handler.
#[derive(Clone)]
pub struct AppState {
    /// HTTP client for the Vault service.
    pub vault_client: Arc<VaultHttpClient>,
    /// Persistent store for async import jobs.
    pub job_store: Arc<dyn JobStore>,
    /// Maximum concurrent vault requests during a batch run.
    pub batch_concurrency: usize,
}
