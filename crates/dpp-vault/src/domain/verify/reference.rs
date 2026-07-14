//! Single-hop verification of a cross-operator passport reference
//! (`PassportRef`): fetch the cited passport and prove its signed public view is
//! byte-identical to what the pin commits to. Fails closed on every ambiguity —
//! a fetch failure or a mismatch is never reported as verified.
//!
//! This establishes **integrity** via the hash pin: any change to the
//! referenced passport's signed public view (or to the signature itself)
//! changes the hash and is caught here. Proving that the pinned signature is
//! cryptographically valid *under the issuer's DID* is a separate check — it
//! needs cross-operator issuer-DID discovery and DID-document resolution, which
//! belongs with the recursive verify-tree that builds on this primitive, not in
//! this single-hop check.

use dpp_common::url_guard::validate_public_https_url;
use dpp_domain::domain::passport::PassportRef;
use serde::Serialize;
use sha2::{Digest, Sha256};

/// The outcome of verifying one [`PassportRef`] against its live target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefVerification {
    /// The target was fetched and its public JWS matched the pin.
    Verified,
    /// Verification could not be completed, or the target failed the pin check.
    Unverifiable(RefUnverifiable),
}

/// Why a [`PassportRef`] could not be verified. Every variant is fail-closed.
///
/// The first three arise on a single-hop [`verify_ref`]; the last three only
/// arise inside the recursive [`super::verify_tree`] walk, which shares this
/// vocabulary so a per-node report reads uniformly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum RefUnverifiable {
    /// The target URI could not be fetched (guard, transport, or non-2xx status).
    Unreachable,
    /// The target carries no `publicJwsSignature` — it is not a published passport.
    NotPublished,
    /// The target's public JWS does not hash to the pinned value (tamper / rot).
    HashMismatch,
    /// A ref reappeared during the walk — the component graph closed a cycle
    /// that could not be caught at insertion time (a cross-operator edge).
    Cycle,
    /// The walk went deeper than the allowed BOM depth.
    DepthExceeded,
    /// The walk reached the cap on total nodes fetched for one request.
    NodeCapExceeded,
    /// A node's `componentRefs` held an entry that is not a well-formed
    /// reference — surfaced rather than silently skipped.
    MalformedRef,
}

/// Lowercase hex SHA-256 of a compact JWS string — the pin format minted at
/// citation time and stored in a ref's `publicJwsHash`. Shared with the
/// recursive [`super::verify_tree`] walk.
pub(crate) fn public_jws_hash(jws: &str) -> String {
    hex::encode(Sha256::digest(jws.as_bytes()))
}

/// Verify a single cross-operator passport reference against its live target.
///
/// `fetch` returns the JSON at a URL or `Err(())` for any failure; production
/// wires an SSRF-guarded HTTPS GET, tests wire a fixture map. Fails closed at
/// every branch — a failure is never a pass.
pub async fn verify_ref<F, Fut>(reference: &PassportRef, fetch: F) -> RefVerification
where
    F: Fn(String) -> Fut,
    Fut: std::future::Future<Output = Result<serde_json::Value, ()>>,
{
    let parent = match fetch(reference.uri.clone()).await {
        Ok(v) => v,
        Err(()) => return RefVerification::Unverifiable(RefUnverifiable::Unreachable),
    };
    let jws = match parent.get("publicJwsSignature").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return RefVerification::Unverifiable(RefUnverifiable::NotPublished),
    };
    if public_jws_hash(jws) == reference.public_jws_hash {
        RefVerification::Verified
    } else {
        RefVerification::Unverifiable(RefUnverifiable::HashMismatch)
    }
}

/// Production fetch for [`verify_ref`]: an SSRF-guarded HTTPS GET returning JSON.
/// Any guard, transport, non-2xx, or decode failure collapses to `Err(())` — the
/// caller treats every failure as unverifiable, never a pass.
pub async fn fetch_public_json(url: String) -> Result<serde_json::Value, ()> {
    let url = validate_public_https_url(&url).map_err(|_| ())?;
    let resp = reqwest::get(&url).await.map_err(|_| ())?;
    if !resp.status().is_success() {
        return Err(());
    }
    resp.json().await.map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn published(jws: &str) -> serde_json::Value {
        serde_json::json!({ "publicJwsSignature": jws })
    }

    /// A fixture fetcher: serves the JSON mapped to a URL, `Err(())` otherwise.
    fn map_fetcher(
        map: HashMap<String, serde_json::Value>,
    ) -> impl Fn(String) -> std::future::Ready<Result<serde_json::Value, ()>> {
        move |url: String| std::future::ready(map.get(&url).cloned().ok_or(()))
    }

    #[test]
    fn hash_is_lowercase_hex_sha256_of_the_jws() {
        // Known SHA-256 of the empty string.
        assert_eq!(
            public_jws_hash(""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[tokio::test]
    async fn verified_when_pin_matches_fetched_signature() {
        let jws = "eyJhbGciOiJFZERTQSJ9.eyJhIjoxfQ.sig";
        let uri = "https://id.odal-node.io/dpp/parent".to_string();
        let reference = PassportRef {
            uri: uri.clone(),
            public_jws_hash: public_jws_hash(jws),
        };
        let fetch = map_fetcher(HashMap::from([(uri, published(jws))]));
        assert_eq!(
            verify_ref(&reference, fetch).await,
            RefVerification::Verified
        );
    }

    #[tokio::test]
    async fn hash_mismatch_when_signature_tampered() {
        let uri = "https://id.odal-node.io/dpp/parent".to_string();
        let reference = PassportRef {
            uri: uri.clone(),
            public_jws_hash: public_jws_hash("the-cited-signature"),
        };
        // The live target now serves a different signature than was pinned.
        let fetch = map_fetcher(HashMap::from([(uri, published("a-tampered-signature"))]));
        assert_eq!(
            verify_ref(&reference, fetch).await,
            RefVerification::Unverifiable(RefUnverifiable::HashMismatch)
        );
    }

    #[tokio::test]
    async fn not_published_when_target_has_no_public_jws() {
        let uri = "https://id.odal-node.io/dpp/draft".to_string();
        let reference = PassportRef {
            uri: uri.clone(),
            public_jws_hash: String::new(),
        };
        let fetch = map_fetcher(HashMap::from([(uri, serde_json::json!({ "id": "x" }))]));
        assert_eq!(
            verify_ref(&reference, fetch).await,
            RefVerification::Unverifiable(RefUnverifiable::NotPublished)
        );
    }

    #[tokio::test]
    async fn unreachable_when_fetch_fails() {
        let reference = PassportRef {
            uri: "https://gone.example/dpp/x".into(),
            public_jws_hash: String::new(),
        };
        let fetch = map_fetcher(HashMap::new()); // nothing mapped → Err(())
        assert_eq!(
            verify_ref(&reference, fetch).await,
            RefVerification::Unverifiable(RefUnverifiable::Unreachable)
        );
    }
}
