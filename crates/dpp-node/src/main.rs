//! Entry point for the `dpp-node` single-binary MVP.

mod plugins;

use dpp_node::{
    config::NodeConfig,
    infra::{
        nats_event_bus::NatsEventBus,
        s3_archive::{NoOpArchive, S3ArchiveAdapter, S3ArchiveConfig},
    },
    router,
};

use std::sync::Arc;

use anyhow::Context;
use axum::{Router, routing::get};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use tokio::net::TcpListener;

use dpp_common::{
    event::{EventBus, NoOpEventBus},
    event_codes,
};
use dpp_crypto::identity::LocalIdentityService;
use dpp_crypto::keystore::KeyStore;
use dpp_domain::ports::{
    archive::ArchivePort, compliance::ComplianceRegistry, passport_repo::PassportRepository,
    registry_sync::RegistrySyncPort,
};
use dpp_identity_service::state::AppState as IdentityState;
use dpp_integrator::{
    infra::{job_store::JobStore, vault_client::VaultHttpClient},
    state::AppState as IntegratorState,
};
use dpp_types::{
    api_key::ApiKeyRepository, audit::AuditRepository, operator::OperatorConfigRepository,
    registry_identity::RegistryIdentityRepository,
};
use dpp_vault::{
    domain::{
        api_key_service::ApiKeyService, operator_service::OperatorService,
        registry_identity_service::RegistryIdentityService, service::PassportService,
    },
    infra::auth::{
        api_key_provider::ApiKeyAuthProvider, composite_provider::CompositeAuthProvider,
        local_provider::LocalAuthProvider,
    },
    state::{AppState as VaultState, DbPing},
};

/// The issuer key id the node signs with and publishes at its did:web document.
const ISSUER_KEY_ID: &str = "root";

// ---------------------------------------------------------------------------
// DB-backend abstraction: cfg-gated init functions return the same struct.
// ---------------------------------------------------------------------------

struct DbComponents {
    passport_repo: Arc<dyn PassportRepository>,
    audit_repo: Arc<dyn AuditRepository>,
    operator_repo: Arc<dyn OperatorConfigRepository>,
    api_key_repo: Arc<dyn ApiKeyRepository>,
    registry_repo: Arc<dyn RegistryIdentityRepository>,
    job_store: Arc<dyn JobStore>,
    db_ping: Arc<dyn DbPing>,
}

async fn init_db(cfg: &NodeConfig) -> anyhow::Result<DbComponents> {
    use async_trait::async_trait;
    use dpp_dal::pg::{
        PgApiKeyRepo, PgAuditRepo, PgDal, PgOperatorConfigRepo, PgPassportRepo,
        PgRegistryIdentityRepo,
    };
    use dpp_domain::DppError;
    use dpp_node::infra::pg_job_store::PgJobStore;

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

    tracing::info!(url = %cfg.database_url, "connecting to PostgreSQL");

    // If a privileged migration URL is provided, run sqlx migrations before
    // the app pool opens. odal_app cannot run DDL; migrations need a superuser
    // or odal_migrate role. If absent, migrations must be pre-applied (ops).
    if let Some(ref migrate_url) = cfg.database_migrate_url {
        tracing::info!("running schema migrations via DATABASE_MIGRATE_URL");
        PgDal::migrate(migrate_url)
            .await
            .context("Failed to apply PostgreSQL migrations")?;
        tracing::info!("schema migrations applied");
    }

    // Retry up to 30 times to handle container startup ordering.
    let mut last_err: Option<anyhow::Error> = None;
    let mut dal_opt: Option<PgDal> = None;
    for attempt in 1..=30 {
        match PgDal::connect(&cfg.database_url).await {
            Ok(d) => {
                last_err = None;
                dal_opt = Some(d);
                break;
            }
            Err(e) => {
                tracing::warn!(attempt, error = %e, "PostgreSQL not ready yet, retrying");
                last_err = Some(anyhow::anyhow!("{e}"));
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
        }
    }
    if let Some(e) = last_err {
        return Err(e).context("Failed to connect to PostgreSQL after 30 attempts");
    }
    let dal = dal_opt.expect("dal set on success");
    tracing::info!(url = %cfg.database_url, "PostgreSQL connected");

    Ok(DbComponents {
        passport_repo: Arc::new(PgPassportRepo::new(dal.clone())),
        audit_repo: Arc::new(PgAuditRepo::new(dal.clone())),
        operator_repo: Arc::new(PgOperatorConfigRepo::new(dal.clone())),
        api_key_repo: Arc::new(PgApiKeyRepo::new(dal.clone())),
        registry_repo: Arc::new(PgRegistryIdentityRepo::new(dal.clone())),
        job_store: Arc::new(PgJobStore::new(dal.clone())),
        db_ping: Arc::new(PgPing(dal)),
    })
}

// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();

    let cfg = NodeConfig::from_env().context("Failed to load node configuration")?;

    dpp_common::telemetry::init(&cfg.log_level);

    let prometheus_handle = Arc::new(
        PrometheusBuilder::new()
            .install_recorder()
            .context("Failed to install Prometheus metrics recorder")?,
    );

    tracing::info!("booting dpp-node");

    // ── Database (backend selected at compile time) ────────────────────────
    let db = init_db(&cfg).await?;

    // ── Wasm plugin host ──────────────────────────────────────────────────────
    let plugin_host = plugins::boot(&cfg.plugins_dir).context("Failed to boot Wasm plugin host")?;
    tracing::info!(dir = %cfg.plugins_dir, "plugin host ready");

    // ── Event bus (NATS JetStream or NoOp) ────────────────────────────────────
    let event_bus: Arc<dyn EventBus> = match &cfg.nats_url {
        Some(url) => {
            let nats = NatsEventBus::connect(url, std::time::Duration::from_secs(7 * 24 * 3600))
                .await
                .context("Failed to connect to NATS JetStream")?;
            Arc::new(nats)
        }
        None => {
            tracing::info!("NATS_URL not set — using NoOp event bus");
            Arc::new(NoOpEventBus)
        }
    };

    // ── Identity (in-process signing) ─────────────────────────────────────────
    let key_store = Arc::new(
        KeyStore::open_and_migrate(&cfg.key_store_path, &cfg.key_store_passphrase)
            .map_err(|e| {
                tracing::error!(
                    code = event_codes::KEYSTORE_INTEGRITY_FAIL,
                    error = %e,
                    "key store failed to open — possible integrity failure"
                );
                e
            })
            .context("Failed to open key store")?,
    );
    if !key_store.has_key(ISSUER_KEY_ID) {
        key_store
            .generate_key(ISSUER_KEY_ID)
            .context("Failed to provision issuer signing key")?;
    }
    let identity_state = IdentityState {
        store: key_store.clone(),
        did_web_base_url: cfg.did_web_base_url.clone(),
    };
    let identity: Arc<dyn dpp_domain::ports::identity_port::IdentityPort> =
        Arc::new(LocalIdentityService::new(
            key_store.clone(),
            ISSUER_KEY_ID.to_owned(),
            cfg.did_web_base_url.clone(),
        ));

    // ── EU Registry sync (ESPR Art. 13) ──────────────────────────────────────
    // If EU_REGISTRY_CLIENT_ID + SECRET are set, use the live (sandbox) adapter.
    // Otherwise fall back to GhostRegistrySync so publish is never blocked before
    // the EU registry launches (~19 Jul 2026).
    let registry_sync: Arc<dyn RegistrySyncPort> = match (
        std::env::var("EU_REGISTRY_CLIENT_ID")
            .ok()
            .filter(|s| !s.is_empty()),
        std::env::var("EU_REGISTRY_CLIENT_SECRET")
            .ok()
            .filter(|s| !s.is_empty()),
    ) {
        (Some(id), Some(secret)) => {
            use dpp_node::infra::eu_registry_sync::{EuRegistrySync, EuRegistrySyncConfig};
            let reg_cfg = EuRegistrySyncConfig::sandbox(id, secret);
            let adapter = EuRegistrySync::new(reg_cfg)
                .context("Failed to build EU registry sync HTTP client")?;
            tracing::info!("EU registry sync: sandbox adapter active");
            Arc::new(adapter) as Arc<dyn RegistrySyncPort>
        }
        _ => {
            tracing::info!(
                "EU registry sync: ghost (pre-go-live) — set EU_REGISTRY_CLIENT_ID + EU_REGISTRY_CLIENT_SECRET to enable"
            );
            Arc::new(dpp_domain::GhostRegistrySync) as Arc<dyn RegistrySyncPort>
        }
    };

    // ── ESPR Art. 13 archive (S3/MinIO or NoOp) ──────────────────────────────
    let archive: Arc<dyn ArchivePort> = match S3ArchiveConfig::from_env() {
        Some(cfg) => {
            tracing::info!(bucket = %cfg.bucket, "ESPR archive: S3 adapter active");
            Arc::new(S3ArchiveAdapter::new(cfg)) as Arc<dyn ArchivePort>
        }
        None => {
            tracing::info!("ESPR archive: no-op — set ARCHIVE_S3_BUCKET to enable");
            Arc::new(NoOpArchive) as Arc<dyn ArchivePort>
        }
    };

    // ── Vault service state ────────────────────────────────────────────────────
    let operator_country = db
        .operator_repo
        .get(dpp_types::STANDALONE_OPERATOR_ID)
        .await
        .ok()
        .flatten()
        .map(|c| c.country)
        .unwrap_or_default();

    let compliance: Arc<dyn ComplianceRegistry> = plugin_host.clone();
    // The registry reader stamps the default facility (Annex III) + primary
    // operator identifier (Art. 13) onto new passports, read live so changes made
    // via the API/CLI apply without a node restart.
    let service = Arc::new(
        PassportService::new(
            db.passport_repo.clone(),
            identity,
            compliance,
            db.audit_repo.clone(),
            event_bus,
            registry_sync,
            archive,
            operator_country,
        )
        .with_registry_reader(db.operator_repo.clone()),
    );
    let operator_service = Arc::new(OperatorService::new(db.operator_repo.clone()));
    let api_key_service = Arc::new(ApiKeyService::new(db.api_key_repo.clone()));
    let registry_identity_service =
        Arc::new(RegistryIdentityService::new(db.registry_repo.clone()));

    // ── Auth provider (API key + optional local admin) ────────────────────────
    let mut providers: Vec<Box<dyn dpp_types::auth::AuthProvider>> =
        vec![Box::new(ApiKeyAuthProvider::new(db.api_key_repo.clone()))];
    if let (Some(user), Some(pass)) = (&cfg.admin_username, &cfg.admin_password) {
        providers.push(Box::new(LocalAuthProvider::new(user.clone(), pass.clone())));
    }
    let auth_provider: Arc<dyn dpp_types::auth::AuthProvider> =
        Arc::new(CompositeAuthProvider::new(providers));

    let vault_state = VaultState {
        service,
        operator_service,
        api_key_service,
        registry_identity_service,
        db_ping: db.db_ping.clone(),
        auth_provider,
        cors_allowed_origins: cfg.cors_allowed_origins.clone(),
    };

    // ── Integrator service state ────────────────────────────────────────────────
    let vault_url = format!("http://localhost:{}/vault", cfg.port);
    let vault_client = Arc::new(VaultHttpClient::new(&vault_url));
    let integrator_state = IntegratorState {
        vault_client,
        job_store: db.job_store.clone(),
        batch_concurrency: cfg.batch_concurrency,
    };

    // ── Background cleanup for expired import jobs (every 6 hours) ──────────
    {
        let store = db.job_store.clone();
        tokio::spawn(async move {
            let interval = tokio::time::Duration::from_secs(6 * 3600);
            let max_age = chrono::Duration::days(30);
            loop {
                tokio::time::sleep(interval).await;
                tracing::debug!("running import job cleanup");
                store.cleanup(max_age).await;
            }
        });
    }

    // ── Metrics: dedicated private listener (never the public API port) ────────
    // `/metrics` is deliberately NOT mounted on the public router — exposing
    // operational telemetry to anyone who can reach the API port is needless
    // recon (RT2-7). It is served on a separate, loopback-by-default listener.
    spawn_metrics_server(cfg.metrics_addr.clone(), prometheus_handle.clone());

    // ── Assemble router ───────────────────────────────────────────────────────
    let app = router::build(vault_state, identity_state, integrator_state);

    let addr = format!("0.0.0.0:{}", cfg.port);
    let listener = TcpListener::bind(&addr)
        .await
        .with_context(|| format!("Failed to bind to {addr}"))?;

    tracing::info!(addr = %addr, "dpp-node listening");
    axum::serve(listener, app).await.context("Server error")?;

    Ok(())
}

/// Spawn the Prometheus `/metrics` server on a dedicated private listener.
/// A bind/serve failure is logged but never takes the node down; `None` disables.
fn spawn_metrics_server(addr: Option<String>, handle: Arc<PrometheusHandle>) {
    match addr {
        Some(addr) => {
            tokio::spawn(async move {
                if let Err(e) = serve_metrics(&addr, handle).await {
                    tracing::error!(error = %e, "metrics server stopped");
                }
            });
        }
        None => tracing::info!("metrics endpoint disabled (METRICS_ADDR empty)"),
    }
}

async fn serve_metrics(addr: &str, handle: Arc<PrometheusHandle>) -> anyhow::Result<()> {
    let app = Router::new().route(
        "/metrics",
        get(move || {
            let h = handle.clone();
            async move { h.render() }
        }),
    );
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("metrics: failed to bind {addr}"))?;
    tracing::info!(addr, "metrics endpoint listening (private)");
    axum::serve(listener, app)
        .await
        .context("metrics server error")?;
    Ok(())
}
