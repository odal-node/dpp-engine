//! Compliance Current — signed, versioned ruleset bundles.
//!
//! Rulesets ship as versioned bundles whose
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
//! concrete verifier (`DppCryptoVerifier`), signing (needs a private key
//! store), reading bundle files from disk, and the hot-swappable runtime
//! state — all engine concerns that stay here.

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

use chrono::{DateTime, Utc};
use dpp_crypto::jws;
use dpp_crypto::keystore::KeyStore;
use dpp_rules::bundle::JwsVerify;
pub use dpp_rules::bundle::{
    AcceptancePolicy, RulesetAcceptance, RulesetError, RulesetManifest, RulesetProvenance,
    SignedBundle, content_hash, verify_bundle,
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
        content_sha256: content_hash(&content)?,
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
    current: RwLock<Arc<RulesetAcceptance>>,
}

impl ActiveRuleset {
    /// The free-tier baseline — no signed channel configured.
    ///
    /// Built through `unverified_baseline` because that is what it is: no bytes
    /// arrived, so there was no signature to check. The provenance it carries is
    /// what [`Self::load_and_swap`] reads to decide whether this ruleset may
    /// refuse an incoming one as superseded.
    #[must_use]
    pub fn baseline() -> Self {
        let content = serde_json::json!({});
        let manifest = RulesetManifest {
            bundle_version: "baseline".into(),
            effective_date: Utc::now(),
            act_citations: vec![],
            schema_versions: BTreeMap::new(),
            content_sha256: content_hash(&content)
                .expect("baseline content is a static empty object; hashing cannot fail"),
        };
        Self {
            current: RwLock::new(Arc::new(RulesetAcceptance::unverified_baseline(
                manifest, content,
            ))),
        }
    }

    /// The ruleset currently in effect (cheap Arc clone).
    #[must_use]
    pub fn get(&self) -> Arc<RulesetAcceptance> {
        self.current.read().expect("ruleset lock poisoned").clone()
    }

    /// The active bundle version.
    #[must_use]
    pub fn version(&self) -> String {
        self.current
            .read()
            .expect("ruleset lock poisoned")
            .manifest()
            .bundle_version
            .clone()
    }

    /// Verify a bundle against the pinned publisher key and the ruleset already
    /// in effect and, only if it passes, atomically swap it in. On failure the
    /// active ruleset is unchanged (fail-closed) and the error is returned for
    /// the caller to alarm on.
    ///
    /// # What `in_force` is, and when it is `None`
    ///
    /// A signature says a bundle is authentic, never that it is *current*, so
    /// verification also refuses one older than what is already running. The
    /// ruleset in effect is what that comparison is made against — but only
    /// when something was actually published.
    ///
    /// A [`RulesetProvenance::LocalBaseline`] is not that. No bytes arrived and
    /// nobody signed it; it is the floor a node stands on until a channel is
    /// configured. Letting it act as `in_force` would be an outright bug here,
    /// because [`Self::baseline`] stamps `effective_date` with the *process
    /// start time* — so a node booted today would refuse every bundle published
    /// before today as a rollback, which is every bundle that exists.
    ///
    /// # Errors
    /// [`RulesetError`] when the bundle does not verify, is not yet effective,
    /// or is superseded — the swap does not happen in any of those cases.
    pub fn load_and_swap(
        &self,
        bundle: &SignedBundle,
        publisher_pubkey_b64: &str,
    ) -> Result<String, RulesetError> {
        let in_effect = self.get();
        let policy = AcceptancePolicy {
            now: Utc::now(),
            in_force: match in_effect.provenance() {
                RulesetProvenance::Verified => Some(in_effect.manifest()),
                RulesetProvenance::LocalBaseline => None,
            },
        };
        let accepted = verify_bundle(bundle, publisher_pubkey_b64, &DppCryptoVerifier, &policy)?;
        let version = accepted.manifest().bundle_version.clone();
        *self.current.write().expect("ruleset lock poisoned") = Arc::new(accepted);
        Ok(version)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    /// A throwaway publisher key store; returns the store, key id, the
    /// base64url public key a node would pin, and the directory holding it.
    ///
    /// The `TempDir` is returned rather than dropped because it owns the
    /// directory the keystore writes into. `tempfile` creates that directory
    /// with restrictive permissions and removes it on drop; `env::temp_dir()`
    /// did neither, and left an Ed25519 private key behind on every run.
    fn publisher() -> (KeyStore, String, String, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("temp dir");
        let store = KeyStore::open_and_migrate(dir.path().join("publisher.enc"), "test-passphrase")
            .expect("open keystore");
        let entry = store.generate_key("publisher").expect("generate key");
        let pubkey_b64 =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(entry.verifying_key.as_bytes());
        (store, "publisher".to_owned(), pubkey_b64, dir)
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

    /// Same as [`bundle`] but with the effective date chosen, for the
    /// applicability and currency cases.
    fn bundle_at(
        store: &KeyStore,
        key_id: &str,
        version: &str,
        threshold: i64,
        effective: DateTime<Utc>,
    ) -> SignedBundle {
        sign_bundle(
            store,
            key_id,
            version,
            effective,
            vec!["ESPR Art. 25".into()],
            BTreeMap::from([("textile".to_owned(), "2.0.0".to_owned())]),
            serde_json::json!({ "textileFibreThreshold": threshold }),
        )
        .expect("sign bundle")
    }

    /// Nothing in force, clock at now: the policy for tests that are about
    /// authenticity and integrity rather than timing. Cases that are about
    /// timing build their own.
    fn accepts_any() -> AcceptancePolicy<'static> {
        AcceptancePolicy {
            now: Utc::now(),
            in_force: None,
        }
    }

    #[test]
    fn signed_bundle_verifies_and_carries_version() {
        let (store, kid, pubkey, _dir) = publisher();
        let b = bundle(&store, &kid, "2026-Q3.1", 5);
        let v =
            verify_bundle(&b, &pubkey, &DppCryptoVerifier, &accepts_any()).expect("must verify");
        assert_eq!(v.version(), "2026-Q3.1");
        assert_eq!(v.content()["textileFibreThreshold"], 5);
    }

    #[test]
    fn tampered_signature_is_refused() {
        let (store, kid, pubkey, _dir) = publisher();
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
            verify_bundle(&b, &pubkey, &DppCryptoVerifier, &accepts_any()),
            Err(RulesetError::BadSignature)
        ));
    }

    #[test]
    fn tampered_content_is_refused() {
        let (store, kid, pubkey, _dir) = publisher();
        let mut b = bundle(&store, &kid, "2026-Q3.1", 5);
        // Change the content without re-signing the manifest.
        b.content = serde_json::json!({ "textileFibreThreshold": 999 });
        assert!(matches!(
            verify_bundle(&b, &pubkey, &DppCryptoVerifier, &accepts_any()),
            Err(RulesetError::ContentHashMismatch)
        ));
    }

    #[test]
    fn wrong_publisher_key_is_refused() {
        let (store, kid, _pubkey, _dir) = publisher();
        let (_other_store, _oid, other_pubkey, _dir) = publisher();
        let b = bundle(&store, &kid, "2026-Q3.1", 5);
        assert!(matches!(
            verify_bundle(&b, &other_pubkey, &DppCryptoVerifier, &accepts_any()),
            Err(RulesetError::BadSignature)
        ));
    }

    #[test]
    fn active_ruleset_hot_swaps_a_verified_bundle() {
        let (store, kid, pubkey, _dir) = publisher();
        let active = ActiveRuleset::baseline();
        assert_eq!(active.version(), "baseline");

        let v2 = bundle(&store, &kid, "2026-Q3.2", 7);
        let new_version = active.load_and_swap(&v2, &pubkey).expect("swap");
        assert_eq!(new_version, "2026-Q3.2");
        assert_eq!(active.version(), "2026-Q3.2");
        assert_eq!(active.get().content()["textileFibreThreshold"], 7);

        // A bad bundle leaves the active ruleset unchanged (fail-closed).
        let (bad_store, bad_kid, _, _dir) = publisher();
        let forged = bundle(&bad_store, &bad_kid, "evil", 0);
        assert!(active.load_and_swap(&forged, &pubkey).is_err());
        assert_eq!(active.version(), "2026-Q3.2");
    }

    // ── Applicability and currency, as this node wires them ──────────────────

    #[test]
    fn a_baseline_node_accepts_a_bundle_published_before_boot() {
        // The baseline stamps `effective_date` with the process start time. If
        // it were passed as `in_force`, every bundle published before this node
        // booted — which is every bundle that exists — would be refused as a
        // rollback. A node that has never seen a signed ruleset has nothing in
        // force to be rolled back from.
        let (store, kid, pubkey, _dir) = publisher();
        let active = ActiveRuleset::baseline();

        let published_last_week = bundle_at(
            &store,
            &kid,
            "2026-Q3.1",
            5,
            Utc::now() - chrono::Duration::days(7),
        );
        assert_eq!(
            active
                .load_and_swap(&published_last_week, &pubkey)
                .expect("a baseline must not refuse a real bundle as superseded"),
            "2026-Q3.1"
        );
    }

    #[test]
    fn an_older_bundle_cannot_displace_a_verified_one() {
        let (store, kid, pubkey, _dir) = publisher();
        let active = ActiveRuleset::baseline();

        let current = bundle_at(
            &store,
            &kid,
            "2026-Q3.2",
            7,
            Utc::now() - chrono::Duration::days(2),
        );
        active.load_and_swap(&current, &pubkey).expect("swap");

        // Authentic, signed by the right publisher, and older. Anyone able to
        // serve bytes could otherwise pin this node to superseded rules.
        let older = bundle_at(
            &store,
            &kid,
            "2026-Q3.1",
            5,
            Utc::now() - chrono::Duration::days(9),
        );
        assert!(matches!(
            active.load_and_swap(&older, &pubkey),
            Err(RulesetError::Superseded { .. })
        ));
        assert_eq!(active.version(), "2026-Q3.2", "the swap must not happen");
        assert_eq!(active.get().content()["textileFibreThreshold"], 7);
    }

    #[test]
    fn a_bundle_that_is_not_yet_effective_is_refused() {
        // Refused as NotYetEffective rather than Superseded: the first tells a
        // caller to hold the bytes and re-offer them, the second to discard.
        let (store, kid, pubkey, _dir) = publisher();
        let active = ActiveRuleset::baseline();

        let next_year = bundle_at(
            &store,
            &kid,
            "2027-Q1.1",
            9,
            Utc::now() + chrono::Duration::days(365),
        );
        assert!(matches!(
            active.load_and_swap(&next_year, &pubkey),
            Err(RulesetError::NotYetEffective { .. })
        ));
        assert_eq!(active.version(), "baseline");
    }
}
