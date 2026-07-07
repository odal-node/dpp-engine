//! Compliance Current — signed, versioned ruleset bundles.
//!
//! ADR-002's moat made literal: rulesets ship as versioned bundles whose
//! manifest is signed (compact EdDSA JWS) by an **offline publisher key**,
//! distinct from any operator key. The node pins the publisher public key,
//! verifies **fail-closed**, and can hot-swap the active bundle without a
//! restart. "Provably more current than a fork" becomes a wire artifact a
//! customer or auditor can verify, not a consulting promise.
//!
//! The bundle format and fail-closed verification (signature + content-hash
//! checks) live in `dpp_rules::bundle` (Apache-2.0) — see that module's docs
//! for the wire shape and why verification takes an injected [`JwsVerify`]
//! rather than depending on a JWS crate directly. This file supplies the
//! concrete verifier ([`DppCryptoVerifier`]), signing (needs a private key
//! store), reading bundle files from disk, and the hot-swappable runtime
//! state — all engine concerns that stay here.

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

use chrono::{DateTime, Utc};
use dpp_crypto::jws;
use dpp_crypto::keystore::KeyStore;
use dpp_rules::bundle::JwsVerify;
pub use dpp_rules::bundle::{
    RulesetError, RulesetManifest, SignedBundle, VerifiedRuleset, content_hash, verify_bundle,
};

/// Wires `dpp_rules::bundle`'s injected EdDSA check to `dpp-crypto`'s JWS
/// verifier — the one production implementation of [`JwsVerify`].
struct DppCryptoVerifier;

impl JwsVerify for DppCryptoVerifier {
    fn verify_eddsa(&self, jws: &str, public_key_b64: &str) -> Result<bool, RulesetError> {
        jws::verify_jws(jws, public_key_b64).map_err(|e| RulesetError::Malformed(e.to_string()))
    }
}

/// Build and sign a bundle from content + metadata (publisher tooling).
///
/// # Errors
/// Propagates JWS signing errors from the key store.
#[allow(clippy::too_many_arguments)]
pub fn sign_bundle(
    store: &KeyStore,
    key_id: &str,
    bundle_version: impl Into<String>,
    effective_date: DateTime<Utc>,
    act_citations: Vec<String>,
    schema_versions: BTreeMap<String, String>,
    content: serde_json::Value,
) -> anyhow::Result<SignedBundle> {
    let manifest = RulesetManifest {
        bundle_version: bundle_version.into(),
        effective_date,
        act_citations,
        schema_versions,
        content_sha256: content_hash(&content),
    };
    let manifest_value = serde_json::to_value(&manifest)?;
    let manifest_jws = jws::sign(store, key_id, &manifest_value)?;
    Ok(SignedBundle {
        manifest_jws,
        content,
    })
}

/// Read a `SignedBundle` from a JSON file (the configured channel drop).
///
/// # Errors
/// IO or JSON errors reading/parsing the bundle file.
pub fn read_bundle_file(path: &std::path::Path) -> anyhow::Result<SignedBundle> {
    let bytes = std::fs::read(path)?;
    Ok(serde_json::from_slice(&bytes)?)
}

/// The node's active ruleset — atomically swappable so a verified hot update
/// takes effect without a restart. The baseline (no configured channel) is the
/// in-repo Apache ruleset, versioned `"baseline"`.
pub struct ActiveRuleset {
    current: RwLock<Arc<VerifiedRuleset>>,
}

impl ActiveRuleset {
    /// The free-tier baseline — no signed channel configured.
    #[must_use]
    pub fn baseline() -> Self {
        let content = serde_json::json!({});
        let manifest = RulesetManifest {
            bundle_version: "baseline".into(),
            effective_date: Utc::now(),
            act_citations: vec![],
            schema_versions: BTreeMap::new(),
            content_sha256: content_hash(&content),
        };
        Self {
            current: RwLock::new(Arc::new(VerifiedRuleset { manifest, content })),
        }
    }

    /// The current verified ruleset (cheap Arc clone).
    #[must_use]
    pub fn get(&self) -> Arc<VerifiedRuleset> {
        self.current.read().expect("ruleset lock poisoned").clone()
    }

    /// The active bundle version.
    #[must_use]
    pub fn version(&self) -> String {
        self.current
            .read()
            .expect("ruleset lock poisoned")
            .manifest
            .bundle_version
            .clone()
    }

    /// Verify a bundle against the pinned publisher key and, only if it passes,
    /// atomically swap it in. On failure the active ruleset is unchanged
    /// (fail-closed) and the error is returned for the caller to alarm on.
    ///
    /// # Errors
    /// [`RulesetError`] when the bundle does not verify — the swap does not happen.
    pub fn load_and_swap(
        &self,
        bundle: &SignedBundle,
        publisher_pubkey_b64: &str,
    ) -> Result<String, RulesetError> {
        let verified = verify_bundle(bundle, publisher_pubkey_b64, &DppCryptoVerifier)?;
        let version = verified.manifest.bundle_version.clone();
        *self.current.write().expect("ruleset lock poisoned") = Arc::new(verified);
        Ok(version)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    /// A throwaway publisher key store; returns the store, key id, and the
    /// base64url public key a node would pin.
    fn publisher() -> (KeyStore, String, String) {
        let path = std::env::temp_dir().join(format!("ruleset-pub-{}.enc", uuid::Uuid::now_v7()));
        let store = KeyStore::open_and_migrate(&path, "test-passphrase").expect("open keystore");
        let entry = store.generate_key("publisher").expect("generate key");
        let pubkey_b64 =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(entry.verifying_key.as_bytes());
        (store, "publisher".to_owned(), pubkey_b64)
    }

    fn bundle(store: &KeyStore, key_id: &str, version: &str, threshold: i64) -> SignedBundle {
        sign_bundle(
            store,
            key_id,
            version,
            Utc::now(),
            vec!["ESPR Art. 25".into()],
            BTreeMap::from([("textile".to_owned(), "2.0.0".to_owned())]),
            serde_json::json!({ "textileFibreThreshold": threshold }),
        )
        .expect("sign bundle")
    }

    #[test]
    fn signed_bundle_verifies_and_carries_version() {
        let (store, kid, pubkey) = publisher();
        let b = bundle(&store, &kid, "2026-Q3.1", 5);
        let v = verify_bundle(&b, &pubkey, &DppCryptoVerifier).expect("must verify");
        assert_eq!(v.version(), "2026-Q3.1");
        assert_eq!(v.content["textileFibreThreshold"], 5);
    }

    #[test]
    fn tampered_signature_is_refused() {
        let (store, kid, pubkey) = publisher();
        let mut b = bundle(&store, &kid, "2026-Q3.1", 5);
        // Flip the second-to-last char of the JWS signature segment. The very
        // last base64url char of a 64-byte Ed25519 signature carries only 2
        // significant bits (the rest is zero-padding most decoders discard),
        // so flipping it can decode to the same signature bytes — an
        // intermittent no-op tamper. The second-to-last char sits in a full
        // 6-bit group and is always fully significant, so flipping it
        // deterministically produces a different signature.
        let mut chars: Vec<char> = b.manifest_jws.chars().collect();
        let idx = chars.len() - 2;
        chars[idx] = if chars[idx] == 'A' { 'B' } else { 'A' };
        b.manifest_jws = chars.into_iter().collect();
        assert!(matches!(
            verify_bundle(&b, &pubkey, &DppCryptoVerifier),
            Err(RulesetError::BadSignature)
        ));
    }

    #[test]
    fn tampered_content_is_refused() {
        let (store, kid, pubkey) = publisher();
        let mut b = bundle(&store, &kid, "2026-Q3.1", 5);
        // Change the content without re-signing the manifest.
        b.content = serde_json::json!({ "textileFibreThreshold": 999 });
        assert!(matches!(
            verify_bundle(&b, &pubkey, &DppCryptoVerifier),
            Err(RulesetError::ContentHashMismatch)
        ));
    }

    #[test]
    fn wrong_publisher_key_is_refused() {
        let (store, kid, _pubkey) = publisher();
        let (_other_store, _oid, other_pubkey) = publisher();
        let b = bundle(&store, &kid, "2026-Q3.1", 5);
        assert!(matches!(
            verify_bundle(&b, &other_pubkey, &DppCryptoVerifier),
            Err(RulesetError::BadSignature)
        ));
    }

    #[test]
    fn active_ruleset_hot_swaps_a_verified_bundle() {
        let (store, kid, pubkey) = publisher();
        let active = ActiveRuleset::baseline();
        assert_eq!(active.version(), "baseline");

        let v2 = bundle(&store, &kid, "2026-Q3.2", 7);
        let new_version = active.load_and_swap(&v2, &pubkey).expect("swap");
        assert_eq!(new_version, "2026-Q3.2");
        assert_eq!(active.version(), "2026-Q3.2");
        assert_eq!(active.get().content["textileFibreThreshold"], 7);

        // A bad bundle leaves the active ruleset unchanged (fail-closed).
        let (bad_store, bad_kid, _) = publisher();
        let forged = bundle(&bad_store, &bad_kid, "evil", 0);
        assert!(active.load_and_swap(&forged, &pubkey).is_err());
        assert_eq!(active.version(), "2026-Q3.2");
    }
}
