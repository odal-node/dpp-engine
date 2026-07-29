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
//! # The issuer DID is chosen by an unauthenticated caller
//!
//! `credential.issuer` is read out of an **unverified** payload on a route that
//! needs no API key, so the fetch target here is attacker-controlled — the only
//! outbound request in this workspace of which that is true. Three consequences,
//! all enforced below:
//!
//! - Every fetch passes [`dpp_common::url_guard::assert_public_target`], which
//!   requires `https` and re-resolves the host to refuse loopback, private,
//!   link-local and cloud-metadata addresses. There is deliberately **no**
//!   `allow_private` opt-out: the webhook guard has one because the operator
//!   chooses that target, and this one is chosen by a stranger.
//! - Redirects are **not followed**. Guarding only the first hop would let a
//!   public host redirect into the internal network.
//! - Response bodies are capped at [`MAX_BODY`], so an anonymous request cannot
//!   make the node buffer an unbounded document.
//!
//! # The operator's own DID never goes over the network
//!
//! When the issuer is this node's own DID — the operator-issued credentials the
//! trust model leans on — the document is read from the in-process identity
//! port. That is the same document the node publishes, so it is strictly more
//! current than a fetched copy, and it removes both a production round-trip and
//! the node's dependence on its own public hostname being reachable from inside
//! its network. It is also why no private-network opt-out is needed: the one
//! legitimate loopback case is not a fetch at all.
//!
//! # Caching
//!
//! DID documents are cached for [`DID_TTL`]: they change only on issuer key
//! rotation, a rare and deliberate event, so a short TTL trades a bounded
//! propagation delay for not refetching on every read. The cache is capped at
//! [`MAX_CACHED_DIDS`] entries — it is keyed by a caller-supplied string, so an
//! unbounded map would be a memory-growth lever for anyone who can host DID
//! documents.
//!
//! Status lists are **not** cached. Revocation is the check whose whole purpose
//! is to be current, and a cached "not revoked" is exactly the answer an
//! attacker wants. `dpp-resolver`'s DID cache additionally serialises concurrent
//! misses per URL; that refinement is not replicated here because credentialed
//! reads are not the public traffic path — revisit if that stops being true.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use dpp_crypto::{DppAccessCredential, StatusList};
use dpp_domain::ports::identity_port::IdentityPort;
use futures::StreamExt;
use reqwest::Client;

use crate::middleware::credential::CredentialDirectory;

/// How long a fetched issuer DID document is trusted before refetching.
pub const DID_TTL: Duration = Duration::from_secs(300);

/// Per-request timeout for both lookups.
const TIMEOUT: Duration = Duration::from_secs(5);

/// Largest DID document this node will buffer from an untrusted issuer.
const MAX_BODY: usize = 256 * 1024;

/// Cap on cached issuer documents; the oldest entry is evicted at the cap.
const MAX_CACHED_DIDS: usize = 512;

/// HTTP-backed [`CredentialDirectory`].
pub struct HttpCredentialDirectory {
    http: Client,
    /// This node's own DID and a live handle to its document, so a credential
    /// the operator issued to itself resolves in-process rather than over the
    /// network. `None` leaves every issuer on the guarded network path.
    local_issuer: Option<(String, Arc<dyn IdentityPort>)>,
    did_cache: Mutex<HashMap<String, (Instant, serde_json::Value)>>,
}

impl HttpCredentialDirectory {
    /// Build a directory that resolves every issuer over the guarded network
    /// path.
    ///
    /// The client is built here rather than accepted from the caller so the
    /// redirect and timeout policy cannot be weakened by sharing a general
    /// purpose client with laxer settings.
    #[must_use]
    pub fn new() -> Self {
        Self {
            http: Self::hardened_client(),
            local_issuer: None,
            did_cache: Mutex::new(HashMap::new()),
        }
    }

    /// Resolve `did` — this node's own DID — from `identity` instead of the
    /// network. See the module docs.
    #[must_use]
    pub fn with_local_issuer(mut self, did: String, identity: Arc<dyn IdentityPort>) -> Self {
        self.local_issuer = Some((did, identity));
        self
    }

    /// A client that never follows redirects: the guard checks the host it is
    /// given, so a followed redirect would escape it.
    fn hardened_client() -> Client {
        Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(TIMEOUT)
            .build()
            .unwrap_or_else(|_| Client::new())
    }

    /// Read at most [`MAX_BODY`] bytes, then parse. Refuses rather than
    /// truncates: a truncated DID document would fail to parse anyway, and an
    /// explicit refusal is the honest log line.
    async fn read_capped_json(resp: reqwest::Response) -> Option<serde_json::Value> {
        let mut buf: Vec<u8> = Vec::new();
        let mut stream = resp.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.ok()?;
            if buf.len() + chunk.len() > MAX_BODY {
                tracing::debug!(limit = MAX_BODY, "issuer document exceeded the size cap");
                return None;
            }
            buf.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&buf).ok()
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
            // Keyed by a caller-supplied string, so it needs a ceiling. At the
            // cap drop the oldest entry: the map is a latency optimisation, and
            // evicting a live issuer only costs one refetch.
            if cache.len() >= MAX_CACHED_DIDS
                && let Some(oldest) = cache
                    .iter()
                    .min_by_key(|(_, (at, _))| *at)
                    .map(|(k, _)| k.clone())
            {
                cache.remove(&oldest);
            }
            cache.insert(did.to_owned(), (Instant::now(), doc.clone()));
        }
    }
}

impl Default for HttpCredentialDirectory {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl CredentialDirectory for HttpCredentialDirectory {
    async fn did_document(&self, issuer_did: &str) -> Option<serde_json::Value> {
        // The operator's own DID resolves in-process — never a network fetch,
        // and never subject to the guard, because there is no outbound request.
        if let Some((did, identity)) = &self.local_issuer
            && did == issuer_did
        {
            return identity.own_did_document().await.ok();
        }

        if let Some(doc) = self.cached(issuer_did) {
            return Some(doc);
        }
        let url = Self::did_web_url(issuer_did)?;

        // The target came from an unverified payload on an unauthenticated
        // route. Guard it before the request, not after.
        if let Err(reason) = dpp_common::url_guard::assert_public_target(&url).await {
            tracing::debug!(
                issuer_did,
                reason,
                "refusing issuer DID fetch: target is not a public https host"
            );
            return None;
        }

        let resp = self.http.get(&url).send().await.ok()?;
        if !resp.status().is_success() {
            tracing::debug!(
                status = %resp.status(),
                issuer_did,
                "issuer DID fetch returned non-2xx; credential cannot be verified"
            );
            return None;
        }
        let doc = Self::read_capped_json(resp).await?;
        self.store(issuer_did, &doc);
        Some(doc)
    }

    async fn status_list(&self, credential: &DppAccessCredential) -> Option<StatusList> {
        // Weaker exposure than the DID fetch — by this point the credential's
        // signature has verified against a trusted issuer, so the URL is
        // issuer-chosen rather than stranger-chosen. Guarded anyway: a trusted
        // issuer is still not this operator, and `None` here fails closed to
        // "revoked", so the guard cannot turn a denial into a grant.
        if let Some(url) = credential
            .credential_status
            .as_ref()
            .and_then(|s| s.status_list_credential.as_ref())
            && let Err(reason) = dpp_common::url_guard::assert_public_target(url).await
        {
            tracing::debug!(
                url = url.as_str(),
                reason,
                "refusing status list fetch: target is not a public https host \
                 (credential treated as revoked)"
            );
            return None;
        }
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

    /// URL derivation is deliberately separate from the guard: `did:web` *can*
    /// name an internal host, and the point is that deriving the URL succeeds
    /// while fetching it is refused. Both halves asserted together so neither
    /// can be removed on the assumption the other covers it.
    #[tokio::test]
    async fn an_internal_issuer_derives_a_url_but_is_never_fetched() {
        for did in [
            "did:web:localhost%3A8080",
            "did:web:127.0.0.1",
            "did:web:169.254.169.254",
        ] {
            assert!(
                HttpCredentialDirectory::did_web_url(did).is_some(),
                "{did} still derives a URL"
            );
            assert!(
                HttpCredentialDirectory::new()
                    .did_document(did)
                    .await
                    .is_none(),
                "{did} must never be fetched — SSRF from an unauthenticated route"
            );
        }
    }

    /// The operator's own DID is answered from the in-process identity port, so
    /// it works without any network at all — including for a loopback
    /// `DID_WEB_BASE_URL`, which the guard would otherwise (correctly) refuse.
    #[tokio::test]
    async fn the_operators_own_did_resolves_without_the_network() {
        struct LocalIdentity;

        #[async_trait::async_trait]
        impl IdentityPort for LocalIdentity {
            async fn sign_passport(
                &self,
                _id: dpp_domain::PassportId,
                _payload: &serde_json::Value,
            ) -> Result<dpp_domain::SignedCredential, dpp_domain::DppError> {
                unreachable!("not exercised by this test")
            }
            async fn verify_signature(
                &self,
                _jws: &str,
                _payload: &serde_json::Value,
            ) -> Result<bool, dpp_domain::DppError> {
                unreachable!("not exercised by this test")
            }
            async fn own_did_document(&self) -> Result<serde_json::Value, dpp_domain::DppError> {
                Ok(serde_json::json!({ "id": "did:web:localhost%3A8001" }))
            }
        }

        let did = "did:web:localhost%3A8001";
        let directory = HttpCredentialDirectory::new()
            .with_local_issuer(did.to_owned(), Arc::new(LocalIdentity));

        let doc = directory.did_document(did).await.expect("resolved locally");
        assert_eq!(doc["id"], did);

        // A *different* loopback issuer is still refused: the short-circuit is
        // bound to this node's own DID, not to loopback in general.
        assert!(
            directory
                .did_document("did:web:localhost%3A9999")
                .await
                .is_none()
        );
    }
}
