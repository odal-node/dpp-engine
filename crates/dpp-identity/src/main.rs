//! Entrypoint for the dpp-identity service.

use std::sync::Arc;

use anyhow::Context;
use tokio::net::TcpListener;

use dpp_crypto::keystore::KeyStore;
use dpp_identity_service::{config::Config, router, state::AppState};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();

    let cfg = Config::from_env().context("Failed to load configuration")?;

    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(&cfg.log_level))
        .init();

    tracing::info!(path = %cfg.key_store_path, "opening key store");

    let store = KeyStore::open_and_migrate(&cfg.key_store_path, &cfg.key_store_passphrase)
        .context("Failed to open key store")?;

    let state = AppState {
        store: Arc::new(store),
        did_web_base_url: cfg.did_web_base_url.clone(),
    };

    let app = router::build(state);
    let addr = format!("0.0.0.0:{}", cfg.port);
    let listener = TcpListener::bind(&addr)
        .await
        .with_context(|| format!("Failed to bind to {addr}"))?;

    tracing::info!(addr, "dpp-identity listening");
    axum::serve(listener, app).await.context("Server error")?;

    Ok(())
}
