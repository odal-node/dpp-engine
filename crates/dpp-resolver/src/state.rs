//! Shared Axum application state for the resolver.

use std::sync::Arc;

use crate::infra::cache::Cache;

/// Shared Axum application state for the resolver.
#[derive(Clone)]
pub struct AppState {
    /// Vault base URL — resolver calls the vault's public GET endpoint to fetch DPPs.
    pub vault_base_url: String,
    /// URL of the operator's did:web document (the signer's public key). Every
    /// passport's JWS is verified against this single operator DID in the
    /// single-tenant deployment. Empty disables verification (dev/test only).
    pub operator_did_url: String,
    /// Redis-backed response cache (tier-aware key per DPP id).
    pub cache: Arc<Cache>,
    /// HTTP client for outbound requests to the vault and the operator DID endpoint.
    pub http: reqwest::Client,
}
