//! Shared Axum application state for the identity service.

use std::sync::Arc;

use dpp_crypto::keystore::KeyStore;

/// Shared Axum application state — cloned cheaply per-request.
#[derive(Clone)]
pub struct AppState {
    /// The AES-256-GCM encrypted Ed25519 key store — holds all operator signing keys.
    pub store: Arc<KeyStore>,
    /// Base URL used when constructing `did:web` DID document identifiers,
    /// e.g. `https://identity.odal-node.io`.
    pub did_web_base_url: String,
}
