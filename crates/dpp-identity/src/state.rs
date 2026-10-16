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

impl AppState {
    /// The absolute DID URL of the verification method that names `operator_id`'s
    /// current key: this service's DID, `#`, and the key's thumbprint URI.
    ///
    /// It is the identifier [`dpp_vc::did_builder::build_did_document`] gives the
    /// key, so it is both the `kid` a token signed with the key carries and the
    /// `id` of its method. A thumbprint is derived from the public key alone, so
    /// the name does not change when the key is rotated out.
    ///
    /// # Errors
    ///
    /// When the operator has no key, or its recorded public key is unreadable.
    pub(crate) fn verification_method_url(&self, operator_id: &str) -> anyhow::Result<String> {
        let key = self
            .store
            .public_key(operator_id)
            .ok_or_else(|| anyhow::anyhow!("no key found for {operator_id}"))?;
        Ok(format!(
            "{}#{}",
            dpp_vc::did_builder::did_for(&self.did_web_base_url),
            key.thumbprint_uri()?
        ))
    }
}
