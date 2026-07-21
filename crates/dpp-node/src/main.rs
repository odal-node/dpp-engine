//! Entry point for the `dpp-node` single-binary MVP.

mod boot;
mod plugins;

use dpp_node::{
    config::NodeConfig,
    infra::{
        nats_event_bus::NatsEventBus,
        s3_archive::{NoOpArchive, S3ArchiveAdapter, S3ArchiveConfig},
        s3_snapshot::{S3SnapshotConfig, S3SnapshotStore},
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
    archive::ArchivePort, compliance::ComplianceRegistry, registry_sync::RegistrySyncPort,
};
use dpp_identity_service::state::AppState as IdentityState;
use dpp_integrator::{infra::vault_client::VaultHttpClient, state::AppState as IntegratorState};
use dpp_types::trust::TrustMode;
use dpp_vault::{
    domain::{
        api_key_service::ApiKeyService, operator_service::OperatorService,
        registry_identity_service::RegistryIdentityService, service::PassportService,
        webhook_service::WebhookService,
    },
    infra::auth::{
        api_key_provider::ApiKeyAuthProvider, composite_provider::CompositeAuthProvider,
        local_provider::LocalAuthProvider,
    },
    state::AppState as VaultState,
};

/// The issuer key id the node signs with and publishes at its did:web document.
const ISSUER_KEY_ID: &str = "root";

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
    let db = boot::db::init_db(&cfg).await?;

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
    // Otherwise fall back to GhostRegistrySync so publish is never blocked for a
    // deployment that has not yet onboarded to the registry. (The registry became
    // operational on 20 Jul 2026 under IR (EU) 2026/1778; registration
    // obligations still follow each product's own delegated act.)
    let (registry_sync, registry_trust): (Arc<dyn RegistrySyncPort>, TrustMode) = match (
        std::env::var("EU_REGISTRY_CLIENT_ID")
            .ok()
            .filter(|s| !s.is_empty()),
        std::env::var("EU_REGISTRY_CLIENT_SECRET")
            .ok()
            .filter(|s| !s.is_empty()),
    ) {
        (Some(id), Some(secret)) => {
            use dpp_node::infra::registry::{EuRegistrySync, EuRegistrySyncConfig};
            let mut reg_cfg = EuRegistrySyncConfig::sandbox(id, secret);
            // Opt-in override: submit payloads that fail our local validation.
            // Off unless explicitly set, so the safe behaviour is the one you get
            // by doing nothing.
            reg_cfg.allow_invalid_payloads = std::env::var("EU_REGISTRY_ALLOW_INVALID_PAYLOADS")
                .is_ok_and(|v| v == "1" || v.eq_ignore_ascii_case("true"));
            if reg_cfg.allow_invalid_payloads {
                tracing::warn!(
                    "EU registry sync: EU_REGISTRY_ALLOW_INVALID_PAYLOADS is set — payloads \
                     that fail local validation will be submitted anyway. Intended for \
                     working around a false positive in our own rules; do not leave this \
                     set against the production registry."
                );
            }
            let adapter = EuRegistrySync::new(reg_cfg)
                .context("Failed to build EU registry sync HTTP client")?;
            tracing::info!("EU registry sync: sandbox adapter active");
            (Arc::new(adapter), TrustMode::Sandbox)
        }
        _ => {
            tracing::info!(
                "EU registry sync: ghost (pre-go-live) — set EU_REGISTRY_CLIENT_ID + EU_REGISTRY_CLIENT_SECRET to enable"
            );
            (Arc::new(dpp_domain::GhostRegistrySync), TrustMode::Ghost)
        }
    };

    // ── ESPR Art. 13 archive (S3/MinIO or NoOp) ──────────────────────────────
    let (archive, archive_trust): (Arc<dyn ArchivePort>, TrustMode) =
        match S3ArchiveConfig::from_env() {
            Some(cfg) => {
                tracing::info!(bucket = %cfg.bucket, "ESPR archive: S3 adapter active");
                (Arc::new(S3ArchiveAdapter::new(cfg)), TrustMode::Live)
            }
            None => {
                tracing::info!("ESPR archive: no-op — set ARCHIVE_S3_BUCKET to enable");
                (Arc::new(NoOpArchive), TrustMode::Ghost)
            }
        };

    let trust = boot::trust::build_and_enforce(registry_trust, archive_trust)?;

    // ── Compliance Current: signed ruleset channel ────────────────────────────
    // Load the pinned, signed bundle if a channel is configured; otherwise stay
    // on the in-repo baseline. A bad bundle never takes the node down — it stays
    // on the last-good ruleset (fail-closed) and raises an alarm metric.
    let active_ruleset = Arc::new(dpp_node::infra::ruleset::ActiveRuleset::baseline());
    match (
        std::env::var("RULESET_BUNDLE_PATH")
            .ok()
            .filter(|s| !s.is_empty()),
        std::env::var("RULESET_PUBLISHER_PUBKEY")
            .ok()
            .filter(|s| !s.is_empty()),
    ) {
        (Some(path), Some(pubkey)) => {
            let loaded = dpp_node::infra::ruleset::read_bundle_file(std::path::Path::new(&path))
                .and_then(|b| {
                    active_ruleset
                        .load_and_swap(&b, &pubkey)
                        .map_err(anyhow::Error::from)
                });
            match loaded {
                Ok(v) => tracing::info!(version = %v, "compliance-current ruleset loaded"),
                Err(e) => {
                    metrics::counter!("ruleset_load_failures_total").increment(1);
                    tracing::error!(
                        code = event_codes::RULESET_LOAD_FAILED,
                        error = %e,
                        "ruleset bundle failed to load — staying on baseline (fail-closed)"
                    );
                }
            }
        }
        _ => tracing::info!(
            "compliance-current ruleset: baseline — set RULESET_BUNDLE_PATH + RULESET_PUBLISHER_PUBKEY for a signed channel"
        ),
    }
    tracing::info!(version = %active_ruleset.version(), "active ruleset");

    // ── Vault service state ────────────────────────────────────────────────────
    let operator_country = match db
        .operator_repo
        .get(dpp_types::STANDALONE_OPERATOR_ID)
        .await
    {
        Ok(cfg) => cfg.map(|c| c.country).unwrap_or_default(),
        Err(e) => {
            // Don't silently bake an empty country into every registry payload
            // for the life of the process — a transient DB hiccup at boot must
            // be visible, like every other fallible boot step in this file.
            tracing::warn!(
                error = %e,
                "could not read operator config at boot — operator country left empty this run"
            );
            String::new()
        }
    };

    let compliance: Arc<dyn ComplianceRegistry> = plugin_host.clone();
    // Clone the registry-sync port for the outbox drain task before it is moved
    // into the service (the service persists it as a field but the drain owns
    // the actual registration calls now).
    let registry_sync_for_drain = registry_sync.clone();
    // The registry reader stamps the default facility (Annex III) + primary
    // operator identifier (Art. 13) onto new passports, read live so changes made
    // via the API/CLI apply without a node restart. The registry outbox makes the
    // passport-publish write and its EU-registry registration enqueue atomic.
    // Continuity snapshots: mirror published public views to a public bucket when
    // SNAPSHOT_S3_BUCKET is configured; otherwise the tier is disabled (no-op).
    let snapshot_store: Option<Arc<dyn dpp_types::snapshot::SnapshotStore>> =
        match S3SnapshotConfig::from_env() {
            Some(scfg) => {
                tracing::info!(bucket = %scfg.bucket, "continuity snapshots: S3 tier active");
                Some(Arc::new(S3SnapshotStore::new(scfg)))
            }
            None => {
                tracing::info!("continuity snapshots: disabled — set SNAPSHOT_S3_BUCKET to enable");
                None
            }
        };

    let mut passport_service = PassportService::new(
        db.passport_repo.clone(),
        identity,
        compliance,
        db.audit_repo.clone(),
        event_bus,
        registry_sync,
        archive,
        operator_country,
    )
    .with_registry_reader(db.operator_repo.clone())
    .with_registry_outbox(db.registry_outbox.clone())
    .with_transfer_store(db.transfer_store.clone())
    .with_evidence_store(db.evidence_store.clone())
    .with_webhooks(db.webhook_outbox.clone())
    .with_resolver_base_url(cfg.resolver_base_url.clone());
    // Only arm the reconcile outbox when there is somewhere to reconcile *to*.
    // Enqueuing rows no drain will ever consume would grow an unbounded backlog
    // of `pending` and make the gauge lie about the tier's health.
    if snapshot_store.is_some() {
        passport_service = passport_service.with_snapshot_outbox(db.snapshot_outbox.clone());
    }
    let service = Arc::new(passport_service);
    let operator_service = Arc::new(OperatorService::new(db.operator_repo.clone()));
    let api_key_service = Arc::new(ApiKeyService::new(db.api_key_repo.clone()));
    let registry_identity_service =
        Arc::new(RegistryIdentityService::new(db.registry_repo.clone()));
    let webhook_service = Arc::new(WebhookService::new(
        db.webhook_store.clone(),
        db.webhook_outbox.clone(),
        cfg.webhook_allow_private_targets,
    ));

    // ── Auth provider (API key + optional local admin) ────────────────────────
    let mut providers: Vec<Box<dyn dpp_types::auth::AuthProvider>> =
        vec![Box::new(ApiKeyAuthProvider::new(db.api_key_repo.clone()))];
    if let (Some(user), Some(pass)) = (&cfg.admin_username, &cfg.admin_password) {
        providers.push(Box::new(LocalAuthProvider::new(user.clone(), pass.clone())));
    }
    let auth_provider: Arc<dyn dpp_types::auth::AuthProvider> =
        Arc::new(CompositeAuthProvider::new(providers));

    // The concrete plugin host backs `POST /api/v1/plugins` (admin hot-install).
    let plugin_admin: Arc<dyn dpp_common::plugin_admin::PluginAdmin> = plugin_host.clone();
    let vault_state = VaultState {
        service,
        operator_service,
        api_key_service,
        registry_identity_service,
        webhook_service,
        db_ping: db.db_ping.clone(),
        auth_provider,
        cors_allowed_origins: cfg.cors_allowed_origins.clone(),
        plugin_admin: Some(plugin_admin),
    };

    // ── Integrator service state ────────────────────────────────────────────────
    let vault_url = format!("http://localhost:{}/vault", cfg.port);
    let vault_client = Arc::new(VaultHttpClient::new(&vault_url));
    let integrator_state = IntegratorState {
        vault_client,
        job_store: db.job_store.clone(),
        batch_concurrency: cfg.batch_concurrency,
    };

    // ── Background tasks: expired-import-job cleanup + registry outbox drain ──
    boot::tasks::spawn_job_cleanup(db.job_store.clone());
    boot::tasks::spawn_registry_drain(db.registry_outbox.clone(), registry_sync_for_drain).await;
    boot::tasks::spawn_webhook_drain(db.webhook_outbox.clone(), cfg.webhook_allow_private_targets)
        .await;
    // Continuity tier: only spawn when object storage is configured — without a
    // store there is nothing to reconcile against (and the vault never enqueues).
    if let Some(store) = snapshot_store {
        boot::tasks::spawn_snapshot_drain(
            db.snapshot_outbox.clone(),
            db.passport_repo.clone(),
            store,
            cfg.resolver_base_url.clone(),
        )
        .await;
        // Repair sweep: covers reconciles the event-driven path never queued.
        boot::tasks::spawn_snapshot_sweep(db.snapshot_outbox.clone());
    }

    // ── Metrics: dedicated private listener (never the public API port) ────────
    // `/metrics` is deliberately NOT mounted on the public router — exposing
    // operational telemetry to anyone who can reach the API port is needless
    // recon (RT2-7). It is served on a separate, loopback-by-default listener.
    spawn_metrics_server(cfg.metrics_addr.clone(), prometheus_handle.clone());

    // ── Assemble router ───────────────────────────────────────────────────────
    let app = router::build(
        vault_state,
        identity_state,
        integrator_state,
        trust,
        active_ruleset,
    );

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
