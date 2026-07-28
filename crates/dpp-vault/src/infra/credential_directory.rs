//! HTTP adapter for the network half of credential verification.
//!
//! Two lookups, one adapter: the issuer's `did:web` document (for the signing
//! key) and the credential's status list (for revocation). They are together
//! because they share a client, a timeout policy and a fail-closed rule, and
//! splitting them would mean two caches to keep honest.
//!
//! # Fail-closed, in both directions
//!
//! Every failure — unreachable, non-2xx, malformed, undecodable — returns
//! `None`. For the DID document that means no key and so no verification; for
//! the status list, core treats `None` as **revoked** whenever the credential
//! declares a status. A credential cannot grant access while the network needed
//! to check it is unavailable.
//!
//! # Caching
//!
//! DID documents are cached for [`DID_TTL`]: they change only on issuer key
//! rotation, a rare and deliberate event, so a short TTL trades a bounded
//! propagation delay for not refetching on every read.
//!
//! Status lists are **not** cached. Revocation is the check whose whole purpose
//! is to be current, and a cached "not revoked" is exactly the answer an
//! attacker wants. `dpp-resolver`'s DID cache additionally serialises concurrent
//! misses per URL; that refinement is not replicated here because credentialed
//! reads are not the public traffic path — revisit if that stops being true.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use dpp_crypto::{DppAccessCredential, StatusList};
use reqwest::Client;

use crate::middleware::credential::CredentialDirectory;

/// How long a fetched issuer DID document is trusted before refetching.
pub const DID_TTL: Duration = Duration::from_secs(300);

/// Per-request timeout for both lookups.
const TIMEOUT: Duration = Duration::from_secs(5);

/// HTTP-backed [`CredentialDirectory`].
pub struct HttpCredentialDirectory {
    http: Client,
    did_cache: Mutex<HashMap<String, (Instant, serde_json::Value)>>,
}

impl HttpCredentialDirectory {
    #[must_use]
    pub fn new(http: Client) -> Self {
        Self {
            http,
            did_cache: Mutex::new(HashMap::new()),
        }
    }

    /// `did:web:example.com` → `https://example.com/.well-known/did.json`,
    /// `did:web:example.com:a:b` → `https://example.com/a/b/did.json`, per the
    /// did:web method. Anything that is not a `did:web` is unresolvable here.
    fn did_web_url(did: &str) -> Option<String> {
        let rest = did.strip_prefix("did:web:")?;
        let mut parts = rest.split(':');
        let host = parts.next().filter(|h| !h.is_empty())?;
        // Percent-decoding of the host's optional `%3A` port separator.
        let host = host.replace("%3A", ":");
        let path: Vec<&str> = parts.collect();
        Some(if path.is_empty() {
            format!("https://{host}/.well-known/did.json")
        } else {
            format!("https://{host}/{}/did.json", path.join("/"))
        })
    }

    fn cached(&self, did: &str) -> Option<serde_json::Value> {
        let cache = self.did_cache.lock().ok()?;
        let (at, doc) = cache.get(did)?;
        (at.elapsed() < DID_TTL).then(|| doc.clone())
    }

    fn store(&self, did: &str, doc: &serde_json::Value) {
        if let Ok(mut cache) = self.did_cache.lock() {
            cache.insert(did.to_owned(), (Instant::now(), doc.clone()));
        }
    }
}

#[async_trait::async_trait]
impl CredentialDirectory for HttpCredentialDirectory {
    async fn did_document(&self, issuer_did: &str) -> Option<serde_json::Value> {
        if let Some(doc) = self.cached(issuer_did) {
            return Some(doc);
        }
        let url = Self::did_web_url(issuer_did)?;
        let resp = self.http.get(&url).timeout(TIMEOUT).send().await.ok()?;
        if !resp.status().is_success() {
            tracing::debug!(
                status = %resp.status(),
                issuer_did,
                "issuer DID fetch returned non-2xx; credential cannot be verified"
            );
            return None;
        }
        let doc: serde_json::Value = resp.json().await.ok()?;
        self.store(issuer_did, &doc);
        Some(doc)
    }

    async fn status_list(&self, credential: &DppAccessCredential) -> Option<StatusList> {
        super::status_list::fetch_status_list_for(&self.http, credential).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn did_web_maps_to_the_well_known_document() {
        assert_eq!(
            HttpCredentialDirectory::did_web_url("did:web:issuer.example").as_deref(),
            Some("https://issuer.example/.well-known/did.json")
        );
    }

    #[test]
    fn a_pathful_did_web_maps_to_that_path() {
        assert_eq!(
            HttpCredentialDirectory::did_web_url("did:web:issuer.example:org:keys").as_deref(),
            Some("https://issuer.example/org/keys/did.json")
        );
    }

    #[test]
    fn a_port_in_the_did_is_decoded() {
        assert_eq!(
            HttpCredentialDirectory::did_web_url("did:web:localhost%3A8080").as_deref(),
            Some("https://localhost:8080/.well-known/did.json")
        );
    }

    /// Only `did:web` is resolvable by this adapter. A `did:key` or an
    /// unrecognised method must yield no URL rather than being coerced into
    /// one — an unresolvable issuer fails closed upstream.
    #[test]
    fn other_did_methods_are_unresolvable() {
        for did in ["did:key:z6Mk", "did:example:123", "not-a-did", "did:web:"] {
            assert!(
                HttpCredentialDirectory::did_web_url(did).is_none(),
                "{did} must not resolve"
            );
        }
    }
}
