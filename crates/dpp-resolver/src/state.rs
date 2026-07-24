//! Shared Axum application state for the resolver.

use std::sync::Arc;

use crate::infra::cache::Cache;
use crate::infra::scan_counter::ScanCounter;

/// Shared Axum application state for the resolver.
#[derive(Clone)]
pub struct AppState {
    /// Vault base URL — resolver calls the vault's public GET endpoint to fetch DPPs.
    pub vault_base_url: String,
    /// URL of the operator's did:web document (the signer's public key). Every
    /// passport's JWS is verified against this single operator DID in the
    /// single-tenant deployment. Empty disables verification (dev/test only).
    pub operator_did_url: String,
    /// This resolver's own public GS1 Digital Link host (e.g.
    /// `https://id.odal-node.io`, or a self-hoster's own domain). Hardcoded
    /// rather than derived from mutable passport data — see
    /// `handlers::resolve_by_gtin` for why trusting `qrCodeUrl` here would
    /// reopen an open-redirect surface.
    pub resolver_base_url: String,
    /// Redis-backed response cache (tier-aware key per DPP id).
    pub cache: Arc<Cache>,
    /// HTTP client for outbound requests to the vault and the operator DID endpoint.
    pub http: reqwest::Client,
    /// In-memory scan/QR-render accumulator, flushed to the node's internal
    /// ingest endpoint. `None` when telemetry is not configured (no
    /// `SCAN_INGEST_URL`) — the default for dev and tests, where the resolver
    /// counts nothing and behaves exactly as before.
    pub scan_counter: Option<Arc<ScanCounter>>,
}
