//! Postgres connection + retry loop, and the concrete repo set the rest of
//! boot wires into the vault/integrator services.

use std::sync::Arc;

use anyhow::Context;
use async_trait::async_trait;

use dpp_dal::pg::{
    PgApiKeyRepo, PgAuditRepo, PgDal, PgEvidenceDossierRepo, PgIdempotencyRepo,
    PgOperatorConfigRepo, PgPassportRepo, PgRegistryIdentityRepo, PgRegistrySyncRepo,
    PgRegistryTransferRepo, PgScanTelemetryRepo, PgSealOutboxRepo, PgSnapshotOutboxRepo,
    PgTransferRepo, PgWebhookRepo,
};
use dpp_domain::{DppError, ports::passport_repo::PassportRepository};
use dpp_integrator::infra::job_store::JobStore;
use dpp_node::{config::NodeConfig, infra::pg_job_store::PgJobStore};
use dpp_types::{
    api_key::ApiKeyRepository, audit::AuditRepository, evidence::EvidenceDossierRepository,
    operator::OperatorConfigRepository, registry_identity::RegistryIdentityRepository,
    registry_sync::RegistrySyncOutbox, registry_transfer::RegistryTransferOutbox,
    scan::ScanTelemetryRepository, seal::SealOutbox, snapshot::SnapshotOutbox,
    transfer::TransferStore, webhook::WebhookOutbox, webhook::WebhookSubscriptionStore,
};
use dpp_vault::{infra::request_stamped_audit::RequestStampedAudit, state::DbPing};

pub struct DbComponents {
    /// Already wrapped in the archiving decorator — see the constructor.
    pub passport_repo: Arc<dyn PassportRepository>,
    /// Archived passport versions, for the route that reads them back.
    pub version_store: Arc<dyn dpp_types::audit::PassportVersionStore>,
    /// Finds the passport that replaced a superseded one, so a printed carrier
    /// keeps landing on the current record.
    pub successors: Arc<dyn dpp_types::successor::SuccessorLookup>,
    /// The trusted lists this node has verified, kept across restarts.
    ///
    /// Persisted rather than held in memory because a pass over the Union is
    /// roughly 40 MB of XML and an XAdES check per document: in memory every
    /// restart pays that again, and for the length of a whole refresh the node
    /// reports "nothing consulted" — indistinguishable from a node whose refresh
    /// is broken.
    pub trusted_lists: Arc<dyn dpp_types::trust::TrustedListStore>,
    pub audit_repo: Arc<dyn AuditRepository>,
    pub operator_repo: Arc<dyn OperatorConfigRepository>,
    pub api_key_repo: Arc<dyn ApiKeyRepository>,
    pub registry_repo: Arc<dyn RegistryIdentityRepository>,
    pub registry_outbox: Arc<dyn RegistrySyncOutbox>,
    pub transfer_store: Arc<dyn TransferStore>,
    pub transfer_outbox: Arc<dyn RegistryTransferOutbox>,
    pub evidence_store: Arc<dyn EvidenceDossierRepository>,
    pub webhook_outbox: Arc<dyn WebhookOutbox>,
    pub webhook_store: Arc<dyn WebhookSubscriptionStore>,
    pub snapshot_outbox: Arc<dyn SnapshotOutbox>,
    pub seal_outbox: Arc<dyn SealOutbox>,
    pub seal_audit: Arc<dyn dpp_types::SealAuditStore>,
    pub scan_repo: Arc<dyn ScanTelemetryRepository>,
    pub unsold_goods_repo: Arc<dyn dpp_types::UnsoldGoodsStore>,
    pub job_store: Arc<dyn JobStore>,
    pub db_ping: Arc<dyn DbPing>,
    pub idempotency: Arc<dyn dpp_common::idempotency::IdempotencyStore>,
}

pub async fn init_db(cfg: &NodeConfig) -> anyhow::Result<DbComponents> {
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

    // The URL carries the app role's password inline: log where the database
    // is, never how to log in to it.
    let db_target = dpp_common::config::redact_url_credentials(&cfg.database_url);
    tracing::info!(url = %db_target, "connecting to PostgreSQL");

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
    tracing::info!(url = %db_target, "PostgreSQL connected");

    let version_store: Arc<dyn dpp_types::audit::PassportVersionStore> =
        Arc::new(dpp_dal::pg::PgPassportVersionRepo::new(dal.clone()));

    Ok(DbComponents {
        // Wrapped, not bare, and the wrapping is the point: EN 18221 clause 4.2
        // says **all** changes are archived, and a rule of that shape cannot be
        // left to each write path to remember. Every change to passport content
        // reaches the database through here, so archiving is something a write
        // path cannot avoid rather than something it opts into.
        //
        // "Content", because one write does not: `mark_sealed` sets `doc->seal`
        // by key and is correctly outside the archive. The set of direct writers
        // is gated — see `dpp-dal/tests/passport_writers_are_known.rs`.
        passport_repo: Arc::new(dpp_dal::pg::ArchivingPassportRepo::new(
            PgPassportRepo::new(dal.clone()),
            version_store.clone(),
        )),
        version_store,
        successors: Arc::new(dpp_dal::pg::PgSuccessorRepo::new(dal.clone())),
        trusted_lists: Arc::new(dpp_dal::pg::PgTrustedListRepo::new(dal.clone())),
        // Wrapped, not bare: the decorator is what stamps `request_id` onto
        // every audit entry. See `dpp_vault::infra::request_stamped_audit`.
        audit_repo: Arc::new(RequestStampedAudit::new(Arc::new(PgAuditRepo::new(
            dal.clone(),
        )))),
        operator_repo: Arc::new(PgOperatorConfigRepo::new(dal.clone())),
        api_key_repo: Arc::new(PgApiKeyRepo::new(dal.clone())),
        registry_repo: Arc::new(PgRegistryIdentityRepo::new(dal.clone())),
        registry_outbox: Arc::new(PgRegistrySyncRepo::new(dal.clone())),
        transfer_store: Arc::new(PgTransferRepo::new(dal.clone())),
        transfer_outbox: Arc::new(PgRegistryTransferRepo::new(dal.clone())),
        evidence_store: Arc::new(PgEvidenceDossierRepo::new(dal.clone())),
        webhook_outbox: Arc::new(PgWebhookRepo::new(dal.clone())),
        webhook_store: Arc::new(PgWebhookRepo::new(dal.clone())),
        snapshot_outbox: Arc::new(PgSnapshotOutboxRepo::new(dal.clone())),
        seal_outbox: Arc::new(PgSealOutboxRepo::new(dal.clone())),
        seal_audit: Arc::new(dpp_dal::pg::PgSealAuditRepo::new(dal.clone())),
        scan_repo: Arc::new(PgScanTelemetryRepo::new(dal.clone())),
        unsold_goods_repo: Arc::new(dpp_dal::pg::PgUnsoldGoodsRepo::new(dal.clone())),
        job_store: Arc::new(PgJobStore::new(dal.clone())),
        idempotency: Arc::new(PgIdempotencyRepo::new(dal.clone())),
        db_ping: Arc::new(PgPing(dal)),
    })
}

#[cfg(test)]
mod tests {
    //! `init_db` needs a live Postgres to get past its connect loop, but it logs
    //! the database it is about to use *before* that, and it bails ahead of the
    //! loop when `DATABASE_MIGRATE_URL` will not parse — so the line can be read
    //! back here with no database and without waiting out 30 retries.
    use std::io;
    use std::sync::Mutex;

    use tracing_subscriber::fmt::MakeWriter;

    use super::*;

    /// A log sink the test can read back.
    #[derive(Clone, Default)]
    struct Captured(Arc<Mutex<Vec<u8>>>);

    impl io::Write for Captured {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl MakeWriter<'_> for Captured {
        type Writer = Self;

        fn make_writer(&self) -> Self {
            self.clone()
        }
    }

    fn config(database_url: &str, database_migrate_url: &str) -> NodeConfig {
        NodeConfig {
            database_url: database_url.into(),
            database_migrate_url: Some(database_migrate_url.into()),
            key_store_path: "/tmp/ks.json".into(),
            key_store_passphrase: "passphrase-must-not-leak".into(),
            did_web_base_url: "https://node.example.com".into(),
            cors_allowed_origins: Vec::new(),
            admin_username: None,
            admin_password: None,
            batch_concurrency: 20,
            nats_url: None,
            port: 8001,
            log_level: "info".into(),
            plugins_dir: "./plugins".into(),
            metrics_addr: None,
            webhook_allow_private_targets: false,
            resolver_base_url: "https://dpp.example.com".into(),
            snapshot_public_base_url: None,
        }
    }

    /// Both URLs carry their password inline, so a log field that prints one as
    /// configured puts the app role's password into whatever aggregates the
    /// node's logs — on every boot, at INFO. Asserts on the **secret values**,
    /// like `NodeConfig`'s `Debug` test does, and on the host surviving, so the
    /// redaction cannot have emptied the line of what makes it useful.
    #[tokio::test]
    async fn the_connection_log_line_never_contains_the_password() {
        let logs = Captured::default();
        let _subscriber = tracing::subscriber::set_default(
            tracing_subscriber::fmt()
                .with_writer(logs.clone())
                .with_ansi(false)
                .finish(),
        );

        // The migrate URL is unparseable (port) on purpose: that is what ends
        // `init_db` before the retry loop. It also carries a password, so the
        // test would catch it being logged too.
        let cfg = config(
            "postgres://odal_app:pg-pass-must-not-leak@db.internal:5432/odal",
            "postgres://postgres:migrate-pass-must-not-leak@db.internal:notaport/odal",
        );
        assert!(
            init_db(&cfg).await.is_err(),
            "the unparseable migrate URL should have ended boot"
        );

        let logged = String::from_utf8(logs.0.lock().unwrap().clone()).expect("log is utf-8");
        assert!(logged.contains("connecting to PostgreSQL"), "{logged}");
        assert!(logged.contains("db.internal:5432/odal"), "{logged}");
        for secret in ["pg-pass-must-not-leak", "migrate-pass-must-not-leak"] {
            assert!(!logged.contains(secret), "boot logged {secret}: {logged}");
        }
    }
}
