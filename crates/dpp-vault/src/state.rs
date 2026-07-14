//! Shared Axum application state for the vault service.

use std::sync::Arc;

use async_trait::async_trait;
use dpp_types::auth::AuthProvider;

use crate::domain::{
    api_key_service::ApiKeyService, operator_service::OperatorService,
    registry_identity_service::RegistryIdentityService, service::PassportService,
    webhook_service::WebhookService,
};

/// Database liveness probe — implemented in the composition root (main.rs)
/// and stored here so AppState doesn't pull a specific DB crate into the vault library.
#[async_trait]
pub trait DbPing: Send + Sync {
    /// Run a cheap liveness query against the database.
    ///
    /// # Errors
    ///
    /// Returns an error if the database is unreachable or the query fails.
    async fn ping(&self) -> anyhow::Result<()>;
}

/// Shared Axum application state — cloned cheaply per-request.
#[derive(Clone)]
pub struct AppState {
    /// Core domain service for passport lifecycle operations.
    pub service: Arc<PassportService>,
    /// Application service for operator branding and compliance configuration.
    pub operator_service: Arc<OperatorService>,
    /// Application service for API key creation, listing, and revocation.
    pub api_key_service: Arc<ApiKeyService>,
    /// Application service for facility (Annex III) + operator-identifier (Art. 13) management.
    pub registry_identity_service: Arc<RegistryIdentityService>,
    /// Application service for signed outbound webhook subscriptions.
    pub webhook_service: Arc<WebhookService>,
    /// Liveness probe for the backing database.
    pub db_ping: Arc<dyn DbPing>,
    /// Auth provider — CompositeAuthProvider (API key + local auth).
    pub auth_provider: Arc<dyn AuthProvider>,
    /// Origins allowed for CORS requests (empty = CORS disabled).
    pub cors_allowed_origins: Vec<String>,
}
