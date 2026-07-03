//! Compliance Current — signed, versioned ruleset bundles (N-2).
//!
//! ADR-002's moat made literal: rulesets ship as versioned bundles whose
//! manifest is signed (compact EdDSA JWS) by an **offline publisher key**,
//! distinct from any operator key. The node pins the publisher public key,
//! verifies **fail-closed**, and can hot-swap the active bundle without a
//! restart. "Provably more current than a fork" becomes a wire artifact a
//! customer or auditor can verify, not a consulting promise.
//!
//! ## Bundle format (open)
//!
//! A bundle is `{ manifestJws, content }`:
//! - `manifestJws` — a compact EdDSA JWS whose payload is the [`RulesetManifest`]
//!   (bundle version, effective date, EU-act citations, sector schema versions,
//!   and the SHA-256 of `content`), signed by the publisher key.
//! - `content` — the ruleset payload the manifest commits to (thresholds,
//!   tables, schema references).
//!
//! Verification is two independent checks: **authenticity** (the JWS verifies
//! under the pinned publisher key) and **integrity** (`content` hashes to the
//! value in the signed manifest). Reusing `dpp-crypto`'s JWS means no new crypto
//! and no bespoke signature format. The reference loader lives engine-side for
//! now; it is a candidate to promote into Apache `dpp-rules` at the next core
//! release (the format above is the open contract either way).

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

use chrono::{DateTime, Utc};
use dpp_crypto::jws;
use dpp_crypto::keystore::KeyStore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Signed description of a ruleset bundle — the JWS payload.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RulesetManifest {
    /// Channel bundle version, e.g. `"2026-Q3.1"`.
    pub bundle_version: String,
    /// When this bundle's rules take effect.
    pub effective_date: DateTime<Utc>,
    /// EU-act citations this bundle encodes (audit trail for the change).
    #[serde(default)]
    pub act_citations: Vec<String>,
    /// Sector → schema version this bundle references (never forks schemas).
    #[serde(default)]
    pub schema_versions: BTreeMap<String, String>,
    /// Hex SHA-256 over the JCS-canonicalised `content`.
    pub content_sha256: String,
}

/// A signed bundle on the wire.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedBundle {
    /// Compact EdDSA JWS over the manifest, signed by the publisher key.
    pub manifest_jws: String,
    /// The ruleset payload the manifest commits to.
    pub content: serde_json::Value,
}

/// A bundle that passed both signature and hash checks. Only constructible via
/// [`verify_bundle`], so holding one is proof it verified.
#[derive(Debug, Clone)]
pub struct VerifiedRuleset {
    /// The verified manifest.
    pub manifest: RulesetManifest,
    /// The verified content.
    pub content: serde_json::Value,
}

impl VerifiedRuleset {
    /// The active bundle version (surfaced on `/health`, stamped into provenance).
    #[must_use]
    pub fn version(&self) -> &str {
        &self.manifest.bundle_version
    }
}

/// Why a bundle was refused. Verification is fail-closed — any of these keeps
/// the node on its current ruleset.
#[derive(Debug, thiserror::Error)]
pub enum RulesetError {
    /// The manifest JWS did not verify under the pinned publisher key.
    #[error("bundle signature invalid or not signed by the pinned publisher key")]
    BadSignature,
    /// `content` does not hash to the value in the signed manifest.
    #[error("bundle content hash mismatch — content does not match the signed manifest")]
    ContentHashMismatch,
    /// The bundle was structurally malformed.
    #[error("malformed bundle: {0}")]
    Malformed(String),
}

/// Canonical SHA-256 (hex) of a content value (RFC 8785 / JCS bytes).
fn content_hash(content: &serde_json::Value) -> String {
    let bytes = serde_jcs::to_vec(content).expect("JCS canonicalisation is infallible");
    hex::encode(Sha256::digest(&bytes))
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

/// Verify a bundle against the pinned publisher public key (base64url). Both the
/// signature (authenticity) and the content hash (integrity) must pass.
///
/// # Errors
/// [`RulesetError`] — fail-closed on a bad signature, hash mismatch, or malformed input.
pub fn verify_bundle(
    bundle: &SignedBundle,
    publisher_pubkey_b64: &str,
) -> Result<VerifiedRuleset, RulesetError> {
    // (1) Authenticity: the manifest JWS verifies under the pinned key.
    let ok = jws::verify_jws(&bundle.manifest_jws, publisher_pubkey_b64)
        .map_err(|e| RulesetError::Malformed(e.to_string()))?;
    if !ok {
        return Err(RulesetError::BadSignature);
    }
    // (2) The manifest is now trusted — extract it from the JWS payload.
    let manifest: RulesetManifest = decode_jws_payload(&bundle.manifest_jws)?;
    // (3) Integrity: content must hash to what the signed manifest commits to.
    if content_hash(&bundle.content) != manifest.content_sha256 {
        return Err(RulesetError::ContentHashMismatch);
    }
    Ok(VerifiedRuleset {
        manifest,
        content: bundle.content.clone(),
    })
}

/// Decode the payload segment of a compact JWS into `T` (used only after the
/// signature verified, so the bytes are trusted).
fn decode_jws_payload<T: for<'de> Deserialize<'de>>(jws: &str) -> Result<T, RulesetError> {
    use base64::Engine;
    let payload_b64 = jws
        .split('.')
        .nth(1)
        .ok_or_else(|| RulesetError::Malformed("JWS has no payload segment".into()))?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|e| RulesetError::Malformed(format!("payload base64: {e}")))?;
    serde_json::from_slice(&bytes).map_err(|e| RulesetError::Malformed(format!("payload json: {e}")))
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
        let verified = verify_bundle(bundle, publisher_pubkey_b64)?;
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
        let pubkey_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(entry.verifying_key.as_bytes());
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
        let v = verify_bundle(&b, &pubkey).expect("must verify");
        assert_eq!(v.version(), "2026-Q3.1");
        assert_eq!(v.content["textileFibreThreshold"], 5);
    }

    #[test]
    fn tampered_signature_is_refused() {
        let (store, kid, pubkey) = publisher();
        let mut b = bundle(&store, &kid, "2026-Q3.1", 5);
        // Flip the last char of the JWS signature segment to a guaranteed-different one.
        let last = b.manifest_jws.pop().expect("non-empty jws");
        b.manifest_jws.push(if last == 'A' { 'B' } else { 'A' });
        assert!(matches!(
            verify_bundle(&b, &pubkey),
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
            verify_bundle(&b, &pubkey),
            Err(RulesetError::ContentHashMismatch)
        ));
    }

    #[test]
    fn wrong_publisher_key_is_refused() {
        let (store, kid, _pubkey) = publisher();
        let (_other_store, _oid, other_pubkey) = publisher();
        let b = bundle(&store, &kid, "2026-Q3.1", 5);
        assert!(matches!(
            verify_bundle(&b, &other_pubkey),
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
