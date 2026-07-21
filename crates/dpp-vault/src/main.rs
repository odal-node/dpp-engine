use std::sync::Arc;

use anyhow::Context;
use async_trait::async_trait;
use tokio::net::TcpListener;
use tracing_subscriber::{EnvFilter, fmt};

use dpp_common::{event::NoOpEventBus, event_codes};
use dpp_dal::pg::{
    PgApiKeyRepo, PgAuditRepo, PgDal, PgEvidenceDossierRepo, PgOperatorConfigRepo, PgPassportRepo,
    PgRegistryIdentityRepo, PgWebhookRepo,
};
use dpp_domain::{
    DppError, GhostArchive, GhostRegistrySync,
    compliance::passthrough_registry::PassthroughRegistry, ports::registry_sync::RegistrySyncPort,
};
use dpp_types::trust::{NodeProfile, NodeTrustReport, TrustMode, TrustPort};
use dpp_vault::{
    config::Config,
    domain::{
        self, api_key_service::ApiKeyService, operator_service::OperatorService,
        registry_identity_service::RegistryIdentityService, webhook_service::WebhookService,
    },
    infra::{
        auth::{
            api_key_provider::ApiKeyAuthProvider, composite_provider::CompositeAuthProvider,
            local_provider::LocalAuthProvider,
        },
        identity_client::IdentityHttpClient,
    },
    router,
    state::{AppState, DbPing},
};

struct PgPing(PgDal);

#[async_trait]
impl DbPing for PgPing {
    async fn ping(&self) -> anyhow::Result<()> {
        self.0
            .ping()
            .await
            .map_err(|e: DppError| anyhow::anyhow!("{e}"))
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();

    let cfg = Config::from_env().context("Failed to load configuration")?;

    fmt().with_env_filter(EnvFilter::new(&cfg.log_level)).init();

    tracing::info!(url = %cfg.database_url, "connecting to PostgreSQL");

    let dal = PgDal::connect(&cfg.database_url)
        .await
        .context("Failed to connect to PostgreSQL")?;

    let passport_repo = Arc::new(PgPassportRepo::new(dal.clone()));
    let audit_repo = Arc::new(PgAuditRepo::new(dal.clone()));
    let operator_repo = Arc::new(PgOperatorConfigRepo::new(dal.clone()));
    let api_key_repo = Arc::new(PgApiKeyRepo::new(dal.clone()));
    let registry_repo = Arc::new(PgRegistryIdentityRepo::new(dal.clone()));
    let evidence_repo = Arc::new(PgEvidenceDossierRepo::new(dal.clone()));
    let webhook_repo = Arc::new(PgWebhookRepo::new(dal.clone()));

    let identity = Arc::new(IdentityHttpClient::new(cfg.identity_service_url.clone()));
    let compliance = Arc::new(PassthroughRegistry::new());

    let event_bus: Arc<dyn dpp_common::event::EventBus> = Arc::new(NoOpEventBus);
    let registry_sync: Arc<dyn RegistrySyncPort> = Arc::new(GhostRegistrySync);

    // ── Ghost-honesty invariant ───────────────────────────────────────────────
    // Standalone dpp-vault always resolves registry_sync and archive to their
    // Ghost adapters (unlike the fused dpp-node binary, which picks a real
    // adapter when configured) — so a production profile must refuse to boot
    // here too, or this binary would silently run with placeholder trust.
    let trust = NodeTrustReport::new(
        NodeProfile::from_env(),
        vec![
            TrustPort {
                port: "registry_sync",
                mode: TrustMode::Ghost,
                required: true,
            },
            TrustPort {
                port: "archive",
                mode: TrustMode::Ghost,
                required: false,
            },
        ],
    );
    for p in &trust.ports {
        tracing::info!(
            port = p.port,
            mode = p.mode.as_str(),
            required = p.required,
            "trust mode"
        );
        metrics::gauge!("trust_mode", "port" => p.port).set(p.mode.gauge_value());
    }
    if let Err(msg) = trust.enforce_profile() {
        tracing::error!(code = event_codes::TRUST_GHOST_BOOT_REFUSED, %msg, "production profile refuses placeholder trust");
        anyhow::bail!(msg);
    }

    // The registry reader stamps the default facility (Annex III) + primary
    // operator identifier (Art. 13) onto new passports, read live so changes made
    // via the API/CLI apply without a node restart.
    let service = Arc::new(
        domain::service::PassportService::new(
            passport_repo,
            identity,
            compliance,
            audit_repo,
            event_bus,
            registry_sync,
            Arc::new(GhostArchive),
            String::new(),
        )
        .with_registry_reader(operator_repo.clone())
        .with_evidence_store(evidence_repo)
        .with_webhooks(webhook_repo.clone()),
    );
    let operator_service = Arc::new(OperatorService::new(operator_repo));
    let api_key_service = Arc::new(ApiKeyService::new(api_key_repo.clone()));
    let registry_identity_service = Arc::new(RegistryIdentityService::new(registry_repo));
    // Standalone vault has no dedicated SSRF opt-out setting; default to the safe
    // deny-private posture (self-hosters wanting internal receivers run the node).
    let webhook_service = Arc::new(WebhookService::new(
        webhook_repo.clone(),
        webhook_repo,
        false,
    ));

    // Auth: real API-key provider (+ optional local admin) — never a dev/unsigned
    // provider. Closes the standalone-vault auth-bypass (audit V0).
    let mut providers: Vec<Box<dyn dpp_types::auth::AuthProvider>> =
        vec![Box::new(ApiKeyAuthProvider::new(api_key_repo.clone()))];
    if let (Some(user), Some(pass)) = (&cfg.admin_username, &cfg.admin_password) {
        providers.push(Box::new(LocalAuthProvider::new(user.clone(), pass.clone())));
    }
    let auth_provider: Arc<dyn dpp_types::auth::AuthProvider> =
        Arc::new(CompositeAuthProvider::new(providers));

    let state = AppState {
        service,
        operator_service,
        api_key_service,
        registry_identity_service,
        webhook_service,
        db_ping: Arc::new(PgPing(dal)),
        auth_provider,
        cors_allowed_origins: cfg.cors_allowed_origins.clone(),
        // The standalone vault binary hosts no Wasm plugin engine; runtime
        // plugin install is available only on the fused node.
        plugin_admin: None,
    };

    let app = router::build(state);
    let addr = format!("0.0.0.0:{}", cfg.port);
    let listener = TcpListener::bind(&addr)
        .await
        .with_context(|| format!("Failed to bind to {addr}"))?;

    tracing::info!(addr, "dpp-vault listening");
    axum::serve(listener, app).await.context("Server error")?;

    Ok(())
}
