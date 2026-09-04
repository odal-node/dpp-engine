//! Signing access credentials with the node's own key.
//!
//! The composition-root half of `dpp_vault::state::CredentialIssuer`. It exists
//! here rather than in the vault for the same reason `DbPing` does: the key
//! store is the binary's, and the vault library must not reach for it.
//!
//! Both methods route through `dpp-vc` rather than assembling anything —
//! `build_did_document` for the identity and `sign_access_credential` for the
//! signature — so the credential is signed by exactly the key the node's
//! published DID document offers a verifier, and the `kid` in the JWS header
//! resolves in that document. The alternative, restating either half here,
//! would let the two drift apart in the one way that is invisible until an
//! external verifier rejects a credential this node considers valid.

use std::sync::Arc;

use async_trait::async_trait;
use dpp_crypto::keystore::KeyStore;
use dpp_vault::state::CredentialIssuer;
use dpp_vc::credential::sign_access_credential;
use dpp_vc::{DppAccessCredential, build_did_document};

/// Issues credentials from the node's key store.
pub struct KeyStoreCredentialIssuer {
    store: Arc<KeyStore>,
    key_id: String,
    base_url: String,
}

impl KeyStoreCredentialIssuer {
    /// Build from the same store, key and base URL the identity service uses.
    ///
    /// Taking all three rather than an `IdentityPort` is deliberate: the port
    /// signs *passports* — it takes a `PassportId` and returns a
    /// `SignedCredential` — and a credential is neither. Widening the port to
    /// carry an unrelated signing act would put a passport-shaped hole in it.
    #[must_use]
    pub fn new(store: Arc<KeyStore>, key_id: String, base_url: String) -> Self {
        Self {
            store,
            key_id,
            base_url,
        }
    }
}

#[async_trait]
impl CredentialIssuer for KeyStoreCredentialIssuer {
    async fn issuer_did(&self) -> anyhow::Result<String> {
        let doc = build_did_document(&self.store, &self.base_url, &self.key_id)?;
        doc["id"]
            .as_str()
            .map(ToOwned::to_owned)
            .ok_or_else(|| anyhow::anyhow!("this node's DID document carries no `id`"))
    }

    async fn sign(&self, credential: &DppAccessCredential) -> anyhow::Result<String> {
        sign_access_credential(credential, &self.store, &self.key_id)
    }
}
