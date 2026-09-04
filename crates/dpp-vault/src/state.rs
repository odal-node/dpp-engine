//! Shared Axum application state for the vault service.

use std::sync::Arc;

use async_trait::async_trait;
use dpp_common::plugin_admin::PluginAdmin;
use dpp_common::ruleset_admin::RulesetAdmin;
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

/// Minting an access credential with this node's own key.
///
/// A port for the same reason as [`DbPing`]: signing needs the key store, and
/// the key store belongs to the composition root. Two methods rather than one
/// because the credential's `issuer` and the key that signs it must be the same
/// identity — a handler builds the document from [`Self::issuer_did`] and then
/// hands it back to [`Self::sign`], so the two cannot be sourced separately.
///
/// # What a node may and may not attest
///
/// Only [`dpp_domain::Audience::LegitimateInterest`]. An operator naming its own
/// authorised repairer is making a claim it is uniquely placed to make — nobody
/// else knows who is in that network. An operator naming itself a market
/// surveillance authority is making a claim it has no standing to make at all,
/// and `dpp-vc` says so at the signing helper: a node signing its own access
/// credentials "has attested nothing to anyone". The audience split is what
/// makes both statements true at once, and the handler enforces it.
#[async_trait]
pub trait CredentialIssuer: Send + Sync {
    /// This node's own DID — the `issuer` value a credential it mints carries,
    /// and the document a verifier resolves to find the signing key.
    ///
    /// # Errors
    /// Propagates key-store failures from building the DID document.
    async fn issuer_did(&self) -> anyhow::Result<String>;

    /// Sign `credential` into compact VC-JWT form.
    ///
    /// # Errors
    /// Propagates key-store and signing failures.
    async fn sign(&self, credential: &dpp_vc::DppAccessCredential) -> anyhow::Result<String>;
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
    /// Minting access credentials with this node's own key. `None` on
    /// deployments with no key store in reach (the standalone vault binary),
    /// where the issuance route answers `501`.
    ///
    /// Independent of `trusted_issuers`: issuing is not the same act as
    /// trusting. A node can mint a credential that it will not itself honour
    /// (`CREDENTIAL_ISSUERS_SELF` unset), which is the ordinary case where the
    /// holder presents it to a *different* node in the same operator's fleet.
    pub credential_issuer: Option<Arc<dyn CredentialIssuer>>,
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
    /// ESPR Art. 24 unsold-goods disclosure lines. A bare port like `scan_repo`
    /// — a row is written once and read back, with no lifecycle to orchestrate.
    pub unsold_goods_repo: Arc<dyn dpp_types::UnsoldGoodsStore>,
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
    /// The node's signed Compliance Current channel: the version in force
    /// (reported alongside `trust`) and the reload the admin route triggers.
    ///
    /// A port rather than the node's concrete `ActiveRuleset`, which belongs to
    /// the node binary and depends on this crate — and a port rather than the
    /// `String` this used to be, because a version cloned once at boot stops
    /// being true the moment a swap can happen. `None` on deployments with no
    /// ruleset channel wired (e.g. the standalone vault binary).
    pub ruleset_admin: Option<Arc<dyn RulesetAdmin>>,
}
