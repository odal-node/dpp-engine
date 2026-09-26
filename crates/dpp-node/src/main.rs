//! Entry point for the `dpp-node` single-binary MVP.

mod boot;
mod plugins;

use dpp_node::{config::NodeConfig, infra::nats_event_bus::NatsEventBus, router};

use std::sync::Arc;

use anyhow::Context;
use axum::{Router, routing::get};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use tokio::net::TcpListener;

use dpp_common::{
    event::{EventBus, NoOpEventBus},
    event_codes,
};
use dpp_crypto::keystore::KeyStore;
use dpp_domain::{
    ports::archive::ArchivePort, ports::compliance::ComplianceRegistry,
    ports::registry_sync::RegistrySyncPort,
};
use dpp_identity_service::state::AppState as IdentityState;
use dpp_integrator::{infra::vault_client::VaultHttpClient, state::AppState as IntegratorState};
use dpp_types::trust::{NodeProfile, TrustMode};
use dpp_vault::{
    domain::{
        api_key_service::ApiKeyService,
        operator_service::OperatorService,
        registry_identity_service::RegistryIdentityService,
        service::{OperatorIdentity, PassportService},
        webhook_service::WebhookService,
    },
    infra::auth::{
        api_key_provider::ApiKeyAuthProvider, composite_provider::CompositeAuthProvider,
        local_provider::LocalAuthProvider,
    },
    state::AppState as VaultState,
};
use dpp_vc::LocalIdentityService;

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

    // Read once and handed to both gates that depend on it — the plugin signing
    // policy below and the trust report — so the two cannot disagree about it.
    let profile = NodeProfile::from_env();

    // ── Wasm plugin host ──────────────────────────────────────────────────────
    let plugin_host =
        plugins::boot(&cfg.plugins_dir, profile).context("Failed to boot Wasm plugin host")?;
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
    let identity: Arc<dyn dpp_domain::ports::identity::IdentityPort> =
        Arc::new(LocalIdentityService::new(
            key_store.clone(),
            ISSUER_KEY_ID.to_owned(),
            cfg.did_web_base_url.clone(),
        ));

    // ── EU Registry sync (ESPR Art. 13) ──────────────────────────────────────
    // If EU_REGISTRY_CLIENT_ID + SECRET are set, use the live (sandbox) adapter.
    // Otherwise fall back to GhostRegistrySync so publish is never blocked for a
    // deployment that has not yet onboarded to the registry. (The registry became
    // operational on 20 Jul 2026; registration obligations still follow each
    // product's own delegated act.)
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
                "EU registry sync: ghost (not onboarded) — set EU_REGISTRY_CLIENT_ID + EU_REGISTRY_CLIENT_SECRET to enable"
            );
            (Arc::new(dpp_domain::GhostRegistrySync), TrustMode::Ghost)
        }
    };

    // ── ESPR Art. 13 archive (S3/MinIO or NoOp) ──────────────────────────────
    let (archive, archive_trust): (Arc<dyn ArchivePort>, TrustMode) =
        dpp_node::infra::s3_archive::from_env();

    // Credential issuers: who may attest which audience. Ghost when unconfigured,
    // so a node that cannot grant credentialed access says so rather than
    // denying every credential indistinguishably from a bad one.
    //
    // The operator DID is read back out of the node's own published DID document
    // rather than derived from the base URL a second time: that document's `id`
    // is the exact string a self-issued credential carries as its `issuer`, so
    // reading it is the only way self-trust cannot silently fail to match.
    let operator_did = identity
        .own_did_document()
        .await
        .ok()
        .and_then(|d| d["id"].as_str().map(ToOwned::to_owned));
    let (trusted_issuers, credential_trust) =
        dpp_node::infra::credential_issuers::from_env(operator_did.as_deref());
    let credentials_live = credential_trust != TrustMode::Ghost;

    // ── eIDAS qualified seal ─────────────────────────────────────────────────
    // Shared between the audit task that fills it and the route that reports it.
    let seal_audit = Arc::new(dpp_types::SealAuditLog::default());
    let seal_wiring = dpp_node::infra::seal::from_env()?;
    let sealing_live = seal_wiring.drains;

    let trust = boot::trust::build_and_enforce(
        profile,
        seal_wiring.trust,
        registry_trust,
        archive_trust,
        credential_trust,
        plugins::compliance_trust(&plugin_host),
    )?;

    // ── Compliance Current: signed ruleset channel ────────────────────────────
    // Load the pinned, signed bundle if a channel is configured; otherwise stay
    // on the in-repo baseline. A bad bundle never takes the node down — it stays
    // on the last-good ruleset (fail-closed) and raises an alarm metric.
    //
    // This is a `reload`, not a separate boot-time loader: the trigger the admin
    // route and the poller use is the same one boot uses, so it is exercised on
    // every start and cannot drift into a second copy of read-verify-swap.
    let ruleset_wiring = dpp_node::infra::ruleset::from_env();
    let active_ruleset = ruleset_wiring.active.clone();
    dpp_node::infra::ruleset::reload_and_report(&active_ruleset, true).await;
    tracing::info!(version = %active_ruleset.version(), "active ruleset");

    // ── Vault service state ────────────────────────────────────────────────────
    let operator = match db
        .operator_repo
        .get(dpp_types::STANDALONE_OPERATOR_ID)
        .await
    {
        Ok(cfg) => cfg
            .map(|c| OperatorIdentity {
                legal_name: c.legal_name,
                country: c.country,
            })
            .unwrap_or_default(),
        Err(e) => {
            // Don't silently bake an empty operator identity into every registry
            // payload for the life of the process — a transient DB hiccup at boot
            // must be visible, like every other fallible boot step in this file.
            tracing::warn!(
                error = %e,
                "could not read operator config at boot — operator identity left empty this run"
            );
            OperatorIdentity::default()
        }
    };
    // The registry requires a legal-entity name on the operator identifier, so
    // an empty one makes every registration this node builds invalid. Say so at
    // boot rather than letting each publish fail with the same message.
    if operator.legal_name.is_empty() {
        tracing::warn!(
            "operator legal name is not set — EU registry registrations will fail validation \
             until it is configured"
        );
    }

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
        dpp_node::infra::snapshot_store::from_env();

    let mut passport_service = PassportService::new(
        db.passport_repo.clone(),
        identity.clone(),
        compliance,
        db.audit_repo.clone(),
        event_bus,
        registry_sync,
        archive,
        operator,
        cfg.resolver_base_url.clone(),
    )
    .with_registry_reader(db.operator_repo.clone())
    .with_registry_outbox(db.registry_outbox.clone())
    .with_versions(db.version_store.clone())
    .with_successors(db.successors.clone())
    .with_transfer_store(db.transfer_store.clone())
    .with_transfer_outbox(db.transfer_outbox.clone())
    .with_evidence_store(db.evidence_store.clone())
    .with_webhooks(db.webhook_outbox.clone());
    if let Some(base) = cfg.snapshot_public_base_url.clone() {
        passport_service = passport_service.with_snapshot_public_base_url(base);
    }
    // Only arm the reconcile outbox when there is somewhere to reconcile *to*.
    // Enqueuing rows no drain will ever consume would grow an unbounded backlog
    // of `pending` and make the gauge lie about the tier's health.
    if snapshot_store.is_some() {
        passport_service = passport_service.with_snapshot_outbox(db.snapshot_outbox.clone());
    }
    // Only arm the seal outbox against a real QTSP. A ghost-backed adapter would
    // happily "seal" every row with a synthetic placeholder, filling the outbox
    // with rows that report success and passports carrying `placeholder: true`
    // seals — the ghost-as-real dishonesty the trust report exists to prevent.
    if sealing_live {
        passport_service = passport_service.with_seal_outbox(db.seal_outbox.clone());
    }
    // The inspector is wired unconditionally, and deliberately not under
    // `sealing_live` above. Reading a stored seal's certificate is not sealing:
    // a node whose provider was dropped, or one serving passports sealed before
    // a backend change, still holds seals whose origin a reader needs — and
    // those are precisely the ones least self-explanatory. Gating this would
    // withdraw the answer exactly where it is worth most.
    // The trusted lists are read here at boot, and **republished by the refresh
    // task** as each pass completes — see `spawn_trusted_list_refresh` below.
    //
    // 🚨 Read here rather than per request, and that part is a deliberate limit:
    // the inspector is called from read handlers, and one that could reach the
    // database — let alone the network — would put that work on the path of a
    // request somebody is waiting on.
    //
    // What a boot-time read alone could not do is reach a node that is already
    // running. The first pass starts a minute *after* boot, so on a fresh
    // deployment the set read here is always the empty one: the node answered
    // `consulted: 0` for every seal until somebody restarted it for an unrelated
    // reason, and nothing said so beyond a count nobody was looking at. The
    // inspector handle is therefore kept and handed to the refresh task, which
    // publishes into it.
    let (lists, unchecked) = match db.trusted_lists.load().await {
        Ok(cached) => dpp_seal::trustlist::from_cache(&cached),
        Err(e) => {
            // Not fatal. A node that cannot read its cache answers
            // `consulted: 0` — the verdict is about nothing and says so — which
            // is the same answer a node that has never refreshed gives.
            tracing::warn!(error = %e, "could not read the trusted-list cache; seal \
                 qualification verdicts will report that no list was consulted");
            (Vec::new(), Vec::new())
        }
    };
    tracing::info!(
        consulted = lists.len(),
        unchecked = unchecked.len(),
        "trusted lists loaded for seal qualification"
    );
    let seal_inspector = Arc::new(dpp_seal::CadesInspector::new());
    seal_inspector.publish(lists, unchecked);
    passport_service = passport_service.with_seal_inspector(seal_inspector.clone());
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

    // ── Auth providers (Bearer: API key; Basic: optional local admin) ─────────
    // Kept as two separate chains, not one composite, so the scheme a request
    // arrives under decides which provider(s) may even be tried.
    let providers: Vec<Box<dyn dpp_types::auth::AuthProvider>> =
        vec![Box::new(ApiKeyAuthProvider::new(db.api_key_repo.clone()))];
    let auth_provider: Arc<dyn dpp_types::auth::AuthProvider> =
        Arc::new(CompositeAuthProvider::new(providers));
    let local_auth_provider: Option<Arc<dyn dpp_types::auth::AuthProvider>> =
        match (&cfg.admin_username, &cfg.admin_password) {
            (Some(user), Some(pass)) => {
                Some(Arc::new(LocalAuthProvider::new(user.clone(), pass.clone())))
            }
            _ => None,
        };

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
        local_auth_provider,
        // Only wired when issuers are configured: with none, the audience-scoped
        // route serves the public view and the trust report says the capability
        // is absent.
        credential_directory: credentials_live.then(|| {
            let mut directory =
                dpp_vault::infra::credential_directory::HttpCredentialDirectory::new();
            // Operator-issued credentials resolve against the in-process
            // identity rather than the node's own public hostname.
            if let Some(did) = operator_did.clone() {
                directory = directory.with_local_issuer(did, identity.clone());
            }
            Arc::new(directory) as Arc<dyn dpp_vault::middleware::credential::CredentialDirectory>
        }),
        trusted_issuers: credentials_live
            .then(|| Arc::new(trusted_issuers) as Arc<dyn dpp_vc::TrustedIssuerRegistry>),
        // Unconditional, and deliberately not gated on `credentials_live`:
        // issuing is not the same act as trusting. An operator running two
        // nodes mints on one and honours on the other, and gating issuance on
        // this node also trusting itself would make that ordinary arrangement
        // impossible to set up.
        credential_issuer: Some(Arc::new(
            dpp_node::infra::credential_issuance::KeyStoreCredentialIssuer::new(
                key_store.clone(),
                ISSUER_KEY_ID.to_owned(),
                cfg.did_web_base_url.clone(),
            ),
        )),
        cors_allowed_origins: cfg.cors_allowed_origins.clone(),
        scan_repo: db.scan_repo.clone(),
        unsold_goods_repo: db.unsold_goods_repo.clone(),
        plugin_admin: Some(plugin_admin),
        // Reported on the authenticated `/vault/api/v1/node/state`, not on the
        // public `/health` — see `dpp_node::router::node_health`.
        trust: Some(trust.clone()),
        seal_audit: Some(seal_audit.clone()),
        // The port, not a version snapshot — `/node/state` reads the version in
        // force at the moment it is asked, and `POST /ruleset/reload` reaches
        // the same channel this booted from.
        ruleset_admin: Some(active_ruleset.clone()),
        idempotency: Some(db.idempotency.clone()),
    };

    // ── Integrator service state ────────────────────────────────────────────────
    let vault_url = format!("http://localhost:{}/vault", cfg.port);
    let vault_client = Arc::new(VaultHttpClient::new(&vault_url));
    let integrator_state = IntegratorState {
        vault_client,
        job_store: db.job_store.clone(),
        batch_concurrency: cfg.batch_concurrency,
        idempotency: Some(db.idempotency.clone()),
    };

    // ── Background tasks: expired-import-job cleanup + registry outbox drain ──
    boot::tasks::spawn_job_cleanup(db.job_store.clone());
    boot::tasks::spawn_idempotency_purge(db.idempotency.clone());
    boot::tasks::spawn_scan_prune(db.scan_repo.clone());
    boot::tasks::spawn_ruleset_poll(active_ruleset.clone(), ruleset_wiring.poll_interval);
    boot::tasks::spawn_registry_drain(
        db.registry_outbox.clone(),
        registry_sync_for_drain.clone(),
        Some(db.operator_repo.clone()),
    )
    .await;
    boot::tasks::spawn_transfer_drain(
        db.transfer_outbox.clone(),
        db.registry_outbox.clone(),
        registry_sync_for_drain,
    )
    .await;
    boot::tasks::spawn_webhook_drain(db.webhook_outbox.clone(), cfg.webhook_allow_private_targets)
        .await;
    // Qualified sealing: only spawn against a real QTSP. A ghost-backed drain
    // would stamp synthetic placeholder seals onto published passports and
    // report them sealed.
    if sealing_live {
        boot::tasks::spawn_seal_drain(
            db.seal_outbox.clone(),
            seal_wiring.port.clone(),
            seal_wiring.credential,
            seal_wiring.mode,
            seal_wiring.conformance_level,
        )
        .await;
        // The backstop for seals the event-driven path never queued, or that gave
        // up during an outage. Without it a published passport can stay unsealed
        // forever with nothing to notice.
        boot::tasks::spawn_seal_sweep(db.seal_outbox.clone());
    }
    // Read-only, and deliberately outside the `sealing_live` guard above: a node
    // that has stopped sealing still holds the seals it bought, and those are
    // exactly the ones nobody is watching any more.
    boot::tasks::spawn_seal_audit(
        db.seal_outbox.clone(),
        seal_audit.clone(),
        Some(db.seal_audit.clone()),
    )?;
    // Also outside `sealing_live`, and for a second reason on top of that one:
    // the lists answer questions about *other people's* certificates, so a node
    // that has never sealed anything still has verdicts to give about seals it
    // was sent. Off unless asked — see `trusted_list_refresh_enabled`.
    if dpp_node::infra::seal::trusted_list_refresh_enabled() {
        tracing::info!(
            "TRUSTED_LIST_REFRESH=on — this node will fetch and verify the EU Trusted Lists \
             daily, beginning shortly after boot"
        );
        boot::tasks::spawn_trusted_list_refresh(db.trusted_lists.clone(), seal_inspector.clone());
    } else {
        tracing::debug!(
            "trusted list refresh is off — seal qualification verdicts will report that no \
             list was consulted. Set TRUSTED_LIST_REFRESH=on to change that"
        );
    }
    // Continuity tier: only spawn when object storage is configured — without a
    // store there is nothing to reconcile against (and the vault never enqueues).
    if let Some(store) = snapshot_store {
        boot::tasks::spawn_snapshot_drain(
            db.snapshot_outbox.clone(),
            db.passport_repo.clone(),
            store,
            identity.clone(),
            cfg.resolver_base_url.clone(),
        )
        .await;
        // Repair sweep: covers reconciles the event-driven path never queued.
        boot::tasks::spawn_snapshot_sweep(db.snapshot_outbox.clone());
        // Refresh pass: re-signs published snapshots before the bound they
        // carry runs out. Without it every snapshot expires and the tier goes
        // dark one validity window after boot.
        boot::tasks::spawn_snapshot_refresh(db.snapshot_outbox.clone()).await;
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
