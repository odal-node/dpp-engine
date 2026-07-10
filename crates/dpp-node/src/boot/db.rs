//! Postgres connection + retry loop, and the concrete repo set the rest of
//! boot wires into the vault/integrator services.

use std::sync::Arc;

use anyhow::Context;
use async_trait::async_trait;

use dpp_dal::pg::{
    PgApiKeyRepo, PgAuditRepo, PgDal, PgEvidenceDossierRepo, PgOperatorConfigRepo, PgPassportRepo,
    PgRegistryIdentityRepo, PgRegistrySyncRepo, PgTransferRepo,
};
use dpp_domain::{DppError, ports::passport_repo::PassportRepository};
use dpp_integrator::infra::job_store::JobStore;
use dpp_node::{config::NodeConfig, infra::pg_job_store::PgJobStore};
use dpp_types::{
    api_key::ApiKeyRepository, audit::AuditRepository, evidence::EvidenceDossierRepository,
    operator::OperatorConfigRepository, registry_identity::RegistryIdentityRepository,
    registry_sync::RegistrySyncOutbox, transfer::TransferStore,
};
use dpp_vault::state::DbPing;

pub struct DbComponents {
    pub passport_repo: Arc<dyn PassportRepository>,
    pub audit_repo: Arc<dyn AuditRepository>,
    pub operator_repo: Arc<dyn OperatorConfigRepository>,
    pub api_key_repo: Arc<dyn ApiKeyRepository>,
    pub registry_repo: Arc<dyn RegistryIdentityRepository>,
    pub registry_outbox: Arc<dyn RegistrySyncOutbox>,
    pub transfer_store: Arc<dyn TransferStore>,
    pub evidence_store: Arc<dyn EvidenceDossierRepository>,
    pub job_store: Arc<dyn JobStore>,
    pub db_ping: Arc<dyn DbPing>,
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
        registry_outbox: Arc::new(PgRegistrySyncRepo::new(dal.clone())),
        transfer_store: Arc::new(PgTransferRepo::new(dal.clone())),
        evidence_store: Arc::new(PgEvidenceDossierRepo::new(dal.clone())),
        job_store: Arc::new(PgJobStore::new(dal.clone())),
        db_ping: Arc::new(PgPing(dal)),
    })
}
