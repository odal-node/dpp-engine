//! Shared Axum application state for the vault service.

use std::sync::Arc;

use async_trait::async_trait;
use dpp_common::plugin_admin::PluginAdmin;
use dpp_types::auth::AuthProvider;
use dpp_types::scan::ScanTelemetryRepository;

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
    /// Bearer-scheme auth provider — API keys (and any future Bearer-scheme
    /// provider, e.g. OAuth). Only tried for `Authorization: Bearer`.
    pub auth_provider: Arc<dyn AuthProvider>,
    /// Network lookups for credential verification — issuer DID documents and
    /// revocation status lists. `None` when credentialed access is unconfigured,
    /// in which case the audience-scoped route serves the public view.
    pub credential_directory:
        Option<std::sync::Arc<dyn crate::middleware::credential::CredentialDirectory>>,
    /// Which issuers may attest which audience. `None` alongside
    /// `credential_directory`; the node reports the capability absent.
    pub trusted_issuers: Option<std::sync::Arc<dyn dpp_vc::TrustedIssuerRegistry>>,
    /// Basic-scheme auth provider — the local admin bootstrap credential.
    /// Only tried for `Authorization: Basic`; kept separate from
    /// `auth_provider` so a Bearer token can never authenticate as local
    /// admin, even if it happens to carry a valid `base64(user:pass)`
    /// payload. `None` when `ADMIN_USERNAME`/`ADMIN_PASSWORD` are not both set.
    pub local_auth_provider: Option<Arc<dyn AuthProvider>>,
    /// Aggregate scan-telemetry counters — resolution counts and QR-render
    /// counts. A bare port (like `db_ping`): the stats/ingest handlers call it
    /// directly, there is no orchestration to wrap in a service.
    pub scan_repo: Arc<dyn ScanTelemetryRepository>,
    /// Origins allowed for CORS requests (empty = CORS disabled).
    pub cors_allowed_origins: Vec<String>,
    /// Runtime plugin administration (the Wasm plugin host). `None` on
    /// deployments with no plugin host wired (e.g. the standalone vault binary).
    pub plugin_admin: Option<Arc<dyn PluginAdmin>>,
    /// The node's resolved trust posture — which trust ports are live, sandbox
    /// or ghost.
    ///
    /// Reported on the **authenticated** `/api/v1/node/state`, never on the
    /// public `/health`. The honesty property is worth keeping; who it is
    /// honest *to* is the question. Which ports are degraded, and how, is a
    /// targeting signal, and it sits alongside `/metrics` — also deliberately
    /// off the public router — as operational detail a caller should have to be
    /// entitled to read.
    ///
    /// `None` for the standalone vault binary, which has no composition root to
    /// resolve trust ports.
    pub trust: Option<Arc<dpp_types::trust::NodeTrustReport>>,
    /// Version of the Compliance Current ruleset this node validates against,
    /// reported alongside `trust`. A string rather than the ruleset type: that
    /// type belongs to the node binary, which depends on this crate.
    pub ruleset_version: Option<String>,
}
