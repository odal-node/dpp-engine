//! Entry point for the standalone `dpp-integrator` service.

use std::sync::Arc;

use anyhow::Context;
use tokio::net::TcpListener;

use dpp_integrator::{
    config::Config,
    infra::{job_store::InMemoryJobStore, vault_client::VaultHttpClient},
    router,
    state::AppState,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();

    let cfg = Config::from_env().context("Failed to load configuration")?;

    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(&cfg.log_level))
        .init();

    let vault_client = Arc::new(VaultHttpClient::new(&cfg.vault_service_url));
    let job_store = Arc::new(InMemoryJobStore::new());

    let state = AppState {
        vault_client,
        job_store,
        batch_concurrency: cfg.batch_concurrency,
    };

    let app = router::build(state);
    let addr = format!("0.0.0.0:{}", cfg.port);
    let listener = TcpListener::bind(&addr)
        .await
        .with_context(|| format!("Failed to bind to {addr}"))?;
    tracing::info!(addr, "dpp-integrator listening");
    axum::serve(listener, app).await.context("Server error")?;
    Ok(())
}
