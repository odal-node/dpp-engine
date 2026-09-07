//! Compliance Current — signed, versioned ruleset bundles.
//!
//! Rulesets ship as versioned bundles whose
//! manifest is signed (compact EdDSA JWS) by an **offline publisher key**,
//! distinct from any operator key. The node pins the publisher public key,
//! verifies **fail-closed**, and hot-swaps the active bundle without a restart.
//! "Provably more current than a fork" becomes a wire artifact a customer or
//! auditor can verify, not a consulting promise.
//!
//! The bundle format and fail-closed verification (signature + content-hash
//! checks) live in `dpp_rules::bundle` (Apache-2.0) — see that module's docs
//! for the wire shape and why verification takes an injected [`JwsVerify`]
//! rather than depending on a JWS crate directly. This file supplies the
//! concrete verifier (`DppCryptoVerifier`), signing (needs a private key
//! store), the channel a bundle arrives over, and the hot-swappable runtime
//! state — all engine concerns that stay here.
//!
//! # What actually triggers a swap
//!
//! Two things, and naming them is the point: an **admin call** to
//! `POST /vault/api/v1/ruleset/reload`, and a **poller** on the configured
//! channel (`RULESET_POLL_INTERVAL_SECS`, default 5 minutes, `0` disables).
//! Both land on [`ActiveRuleset::reload`], which is also what boot calls — so
//! the boot path is the reload path, exercised on every start, rather than a
//! second copy of read-verify-swap that can drift from it.
//!
//! For most of this module's life neither trigger existed. The type was built
//! to swap, the doc said it swapped, and the only caller was a boot-time load —
//! so adopting a new ruleset meant a restart, which is what the doc promised an
//! operator would not need. That gap is what [`RulesetSource`] and `reload`
//! close.
//!
//! # What a swap changes today, and what it does not
//!
//! A signed version string, and nothing else. [`ActiveRuleset::get`] has one
//! production caller — the currency check inside this module — and
//! [`RulesetAcceptance::content`] has none at all: every other caller of either
//! is a test in this file. The rules that actually run are `dpp-calc`'s
//! compiled-in registry, which no bundle reaches.
//!
//! So the authenticity, integrity, currency and rollback guarantees below are
//! real and worth having — a node can prove which ruleset version it is on, and
//! refuse a forged or stale one — but adopting a bundle does not change how a
//! passport is evaluated. Feeding the channel's content into validation is a
//! separate and much larger piece of work.
//!
//! This is stated here rather than left to be inferred from green tests,
//! because everything around it reads as though the rules themselves were being
//! swapped, and the sentence at the top of this file — "provably more current
//! than a fork" — is a claim about the *version*, not yet about the rules.
//!
//! # Why a source seam rather than a file read
//!
//! A local file is the channel today and is explicitly the placeholder: the
//! distribution design has bundles arriving over an HTTP feed or an OCI pull,
//! with the local path standing in until one exists. Putting that behind
//! [`RulesetSource`] means the swap path — verification, currency, atomic
//! install, fail-closed rollback — is written once and does not move when the
//! transport does. A source is allowed to answer "nothing changed" so a
//! conditional GET can be cheap; it is never allowed to decide whether a bundle
//! is *acceptable*, which stays entirely in `dpp_rules::bundle`.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use dpp_common::event_codes;
use dpp_common::ruleset_admin::{RulesetAdmin, RulesetReload, RulesetReloadError};
use dpp_crypto::jws;
use dpp_crypto::keystore::KeyStore;
use dpp_rules::bundle::JwsVerify;
pub use dpp_rules::bundle::{
    AcceptancePolicy, RulesetAcceptance, RulesetError, RulesetManifest, RulesetProvenance,
    SignedBundle, content_hash, verify_bundle,
};

/// How often the poller re-reads the channel when `RULESET_POLL_INTERVAL_SECS`
/// is unset. Five minutes: a regulatory ruleset changes on the order of
/// quarters, so this is about bounding how long a node can be behind a
/// correction, not about latency.
const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(300);

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

// ── The channel a bundle arrives over ────────────────────────────────────────

/// Where signed bundles come from. The transport half of the channel; the
/// trust half is [`verify_bundle`] and never moves.
#[async_trait]
pub trait RulesetSource: Send + Sync {
    /// A short, non-secret description for logs — a path, a feed URL, a
    /// registry reference.
    fn describe(&self) -> String;

    /// Fetch whatever bundle the channel currently offers.
    ///
    /// `Ok(None)` means the source knows nothing has changed since its last
    /// successful fetch — a conditional GET answered `304`, say. A source that
    /// cannot cheaply tell returns `Ok(Some(_))` every time and lets
    /// [`ActiveRuleset::reload`] decide, which compares the *signed* manifest
    /// rather than a transport-level heuristic and is therefore exact.
    ///
    /// # Errors
    /// Anything that stopped bytes arriving. Never used to report that a bundle
    /// is unacceptable — that judgement is not a source's to make.
    async fn fetch(&self) -> anyhow::Result<Option<SignedBundle>>;
}

/// A bundle dropped on the local filesystem — the channel as it ships today.
pub struct FileRulesetSource {
    path: PathBuf,
}

impl FileRulesetSource {
    /// A source reading the bundle JSON at `path` on every fetch.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

#[async_trait]
impl RulesetSource for FileRulesetSource {
    fn describe(&self) -> String {
        self.path.display().to_string()
    }

    /// Always re-reads and always answers `Some`.
    ///
    /// It could stat the file and skip an unchanged mtime, and that would be
    /// both cheaper and wrong: an mtime is a claim about the filesystem, not
    /// about the bundle, and it is equally capable of missing a rewrite that
    /// preserved it and reporting a change for a bare `touch`. Re-reading a few
    /// kilobytes and letting the signed `content_sha256` settle it costs an
    /// Ed25519 verify per poll and cannot be fooled.
    async fn fetch(&self) -> anyhow::Result<Option<SignedBundle>> {
        let path = self.path.clone();
        // Off the async worker: the bundle is small, but the path can be a
        // network mount, and a stalled read must not take the reactor with it.
        tokio::task::spawn_blocking(move || read_bundle_file(&path))
            .await?
            .map(Some)
    }
}

/// A configured channel: where bundles come from, and the key they must be
/// signed by. Both or neither — a source with no pinned key would be a channel
/// that accepts anything, which is the one thing this design refuses.
struct Channel {
    source: Box<dyn RulesetSource>,
    publisher_pubkey: String,
}

/// The node's active ruleset — atomically swappable so a verified hot update
/// takes effect without a restart. The baseline (no configured channel) is the
/// in-repo Apache ruleset, versioned `"baseline"`.
pub struct ActiveRuleset {
    current: RwLock<Arc<RulesetAcceptance>>,
    /// Serialises swaps against each other — never against readers.
    ///
    /// Currency is checked against whatever is in force and then installed, and
    /// those two steps have to be one step: without this, two reloads racing
    /// could both pass the check against the same in-force manifest and the
    /// *older* one could land last, which is precisely the rollback
    /// [`RulesetError::Superseded`] exists to refuse. A dedicated mutex rather
    /// than holding `current`'s write lock across verification, because
    /// verification must never block a request reading the ruleset.
    swap: Mutex<()>,
    channel: Option<Channel>,
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
            swap: Mutex::new(()),
            channel: None,
        }
    }

    /// A baseline node with a signed channel wired: bundles arrive from
    /// `source` and must verify under `publisher_pubkey_b64`.
    #[must_use]
    pub fn with_channel(
        mut self,
        source: Box<dyn RulesetSource>,
        publisher_pubkey_b64: impl Into<String>,
    ) -> Self {
        self.channel = Some(Channel {
            source,
            publisher_pubkey: publisher_pubkey_b64.into(),
        });
        self
    }

    /// Whether a signed channel is configured at all.
    #[must_use]
    pub fn has_channel(&self) -> bool {
        self.channel.is_some()
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
        Ok(self
            .verify_and_install(bundle, publisher_pubkey_b64)?
            .ruleset_version)
    }

    /// [`Self::load_and_swap`], keeping the answer to whether anything actually
    /// changed. Verification and installation happen under [`Self::swap`] so
    /// the currency check and the install cannot be interleaved by a second
    /// swap.
    fn verify_and_install(
        &self,
        bundle: &SignedBundle,
        publisher_pubkey_b64: &str,
    ) -> Result<RulesetReload, RulesetError> {
        let _swapping = self.swap.lock().expect("ruleset swap lock poisoned");

        let in_effect = self.get();
        let policy = AcceptancePolicy {
            now: Utc::now(),
            in_force: match in_effect.provenance() {
                RulesetProvenance::Verified => Some(in_effect.manifest()),
                RulesetProvenance::LocalBaseline => None,
            },
        };
        let accepted = verify_bundle(bundle, publisher_pubkey_b64, &DppCryptoVerifier, &policy)?;

        // "Changed" is decided on the *signed* manifest: a republish at the same
        // effective date is accepted as a correction, so version alone would
        // report no change for one that carries different rules, and the hash
        // alone would report none for a re-version of identical content.
        let changed = in_effect.manifest().content_sha256 != accepted.manifest().content_sha256
            || in_effect.version() != accepted.version();
        let ruleset_version = accepted.version().to_owned();

        *self.current.write().expect("ruleset lock poisoned") = Arc::new(accepted);
        Ok(RulesetReload {
            ruleset_version,
            changed,
        })
    }
}

#[async_trait]
impl RulesetAdmin for ActiveRuleset {
    fn active_version(&self) -> String {
        self.version()
    }

    async fn reload(&self) -> Result<RulesetReload, RulesetReloadError> {
        let Some(channel) = self.channel.as_ref() else {
            return Err(RulesetReloadError::NotConfigured);
        };

        let fetched = channel
            .source
            .fetch()
            .await
            .map_err(|e| RulesetReloadError::Unavailable(e.to_string()))?;

        // The source says nothing arrived that it has not already served. Report
        // what is in force rather than inventing a swap.
        let Some(bundle) = fetched else {
            return Ok(RulesetReload {
                ruleset_version: self.version(),
                changed: false,
            });
        };

        self.verify_and_install(&bundle, &channel.publisher_pubkey)
            .map_err(reload_error)
    }
}

/// Map a verification refusal onto the port's error, keeping the two timing
/// refusals distinct from the authenticity ones — they tell an operator
/// opposite things (hold and re-offer vs. discard).
fn reload_error(e: RulesetError) -> RulesetReloadError {
    match e {
        RulesetError::NotYetEffective { .. } => RulesetReloadError::NotYetEffective(e.to_string()),
        RulesetError::Superseded { .. } => RulesetReloadError::Superseded(e.to_string()),
        other => RulesetReloadError::Rejected(other.to_string()),
    }
}

// ── Wiring ───────────────────────────────────────────────────────────────────

/// The ruleset channel as the composition root wires it.
pub struct RulesetWiring {
    /// The live ruleset, shared with the router and the poller.
    pub active: Arc<ActiveRuleset>,
    /// How often to re-read the channel. `None` when no channel is configured,
    /// or when the operator disabled polling with `RULESET_POLL_INTERVAL_SECS=0`.
    pub poll_interval: Option<Duration>,
}

/// Build the ruleset channel from the environment.
///
/// `RULESET_BUNDLE_PATH` + `RULESET_PUBLISHER_PUBKEY` configure a signed
/// channel; either alone configures nothing, because a source without a pinned
/// key is a channel that would accept anything. With neither the node stays on
/// its compiled-in baseline and [`RulesetAdmin::reload`] answers
/// [`RulesetReloadError::NotConfigured`].
///
/// `RULESET_POLL_INTERVAL_SECS` sets the poll cadence (default 300, `0`
/// disables polling and leaves the admin route as the only trigger).
#[must_use]
pub fn from_env() -> RulesetWiring {
    let path = std::env::var("RULESET_BUNDLE_PATH")
        .ok()
        .filter(|s| !s.is_empty());
    let pubkey = std::env::var("RULESET_PUBLISHER_PUBKEY")
        .ok()
        .filter(|s| !s.is_empty());

    let (Some(path), Some(pubkey)) = (path, pubkey) else {
        tracing::info!(
            "compliance-current ruleset: baseline — set RULESET_BUNDLE_PATH + \
             RULESET_PUBLISHER_PUBKEY for a signed channel"
        );
        return RulesetWiring {
            active: Arc::new(ActiveRuleset::baseline()),
            poll_interval: None,
        };
    };

    let source = Box::new(FileRulesetSource::new(&path));
    tracing::info!(source = %source.describe(), "compliance-current ruleset channel configured");
    RulesetWiring {
        active: Arc::new(ActiveRuleset::baseline().with_channel(source, pubkey)),
        poll_interval: poll_interval_from_env(),
    }
}

/// Parse `RULESET_POLL_INTERVAL_SECS`. `None` for an explicit `0` (polling off);
/// an unparseable value falls back to the default rather than silently
/// disabling the poller, because the failure mode of a typo must not be a node
/// that quietly stops taking regulatory updates.
fn poll_interval_from_env() -> Option<Duration> {
    match std::env::var("RULESET_POLL_INTERVAL_SECS")
        .ok()
        .filter(|s| !s.is_empty())
    {
        None => Some(DEFAULT_POLL_INTERVAL),
        Some(raw) => match raw.parse::<u64>() {
            Ok(0) => {
                tracing::info!(
                    "ruleset polling disabled (RULESET_POLL_INTERVAL_SECS=0) — \
                     POST /vault/api/v1/ruleset/reload is the only trigger"
                );
                None
            }
            Ok(secs) => Some(Duration::from_secs(secs)),
            Err(e) => {
                tracing::warn!(
                    value = %raw,
                    error = %e,
                    default_secs = DEFAULT_POLL_INTERVAL.as_secs(),
                    "RULESET_POLL_INTERVAL_SECS is not a number — using the default"
                );
                Some(DEFAULT_POLL_INTERVAL)
            }
        },
    }
}

/// Run one reload and log/count the outcome. Shared by the boot load and the
/// poller so a bundle that is refused reports identically whichever asked for
/// it — and so `ruleset_load_failures_total`, which the fleet self-check already
/// alarms on, covers both.
///
/// `at_boot` only changes the wording: at boot a refusal means the node is
/// serving its baseline, later it means the node is still serving the last
/// bundle that was good.
pub async fn reload_and_report(active: &ActiveRuleset, at_boot: bool) {
    match active.reload().await {
        Ok(r) if r.changed => {
            metrics::counter!("ruleset_swaps_total").increment(1);
            tracing::info!(version = %r.ruleset_version, "compliance-current ruleset in force");
        }
        Ok(r) => tracing::debug!(
            version = %r.ruleset_version,
            "ruleset channel re-read; already in force"
        ),
        // Not an error: the overwhelmingly common deployment has no channel, and
        // `from_env` has already said so once at boot.
        Err(RulesetReloadError::NotConfigured) => {}
        Err(e) => {
            metrics::counter!("ruleset_load_failures_total").increment(1);
            tracing::error!(
                code = event_codes::RULESET_LOAD_FAILED,
                error = %e,
                "ruleset bundle refused — {} (fail-closed)",
                if at_boot {
                    "staying on baseline"
                } else {
                    "keeping the ruleset in force"
                }
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use serial_test::serial;

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

    // ── The trigger: reload over a source ────────────────────────────────────

    /// Writes bundles to a real file the way a channel drop would, so the file
    /// source is exercised rather than stubbed.
    struct ChannelDrop {
        dir: tempfile::TempDir,
    }

    impl ChannelDrop {
        fn new() -> Self {
            Self {
                dir: tempfile::tempdir().expect("temp dir"),
            }
        }

        fn path(&self) -> PathBuf {
            self.dir.path().join("ruleset.json")
        }

        fn write(&self, bundle: &SignedBundle) {
            std::fs::write(
                self.path(),
                serde_json::to_vec(bundle).expect("serialise bundle"),
            )
            .expect("write bundle");
        }

        fn source(&self) -> Box<dyn RulesetSource> {
            Box::new(FileRulesetSource::new(self.path()))
        }
    }

    #[tokio::test]
    async fn a_node_with_no_channel_reports_that_rather_than_failing() {
        // The distinction the route depends on: "nothing to reload" is not the
        // same answer as "the reload failed", and an operator on a baseline node
        // must not be shown a verification error.
        let active = ActiveRuleset::baseline();
        assert!(!active.has_channel());
        assert!(matches!(
            active.reload().await,
            Err(RulesetReloadError::NotConfigured)
        ));
    }

    #[tokio::test]
    async fn reload_adopts_a_bundle_dropped_after_boot() {
        // The whole issue in one test: the node is running, a new bundle lands
        // on the channel, and it takes effect without a restart.
        let (store, kid, pubkey, _dir) = publisher();
        let drop = ChannelDrop::new();
        drop.write(&bundle_at(
            &store,
            &kid,
            "2026-Q3.1",
            5,
            Utc::now() - chrono::Duration::days(7),
        ));
        let active = ActiveRuleset::baseline().with_channel(drop.source(), &pubkey);

        let first = active.reload().await.expect("boot load");
        assert_eq!(first.ruleset_version, "2026-Q3.1");
        assert!(first.changed, "adopting over the baseline is a change");

        // A newer bundle replaces the file while the node keeps running.
        drop.write(&bundle_at(
            &store,
            &kid,
            "2026-Q3.2",
            7,
            Utc::now() - chrono::Duration::days(1),
        ));
        let second = active.reload().await.expect("hot reload");
        assert_eq!(second.ruleset_version, "2026-Q3.2");
        assert!(second.changed);
        assert_eq!(active.get().content()["textileFibreThreshold"], 7);
        assert_eq!(
            active.active_version(),
            "2026-Q3.2",
            "the port must report the version in force, not the one loaded at boot"
        );
    }

    #[tokio::test]
    async fn re_reading_an_unchanged_channel_is_not_a_change() {
        // What the poller does on every quiet tick. Reporting `changed` here
        // would turn a five-minute timer into a stream of false adoptions.
        let (store, kid, pubkey, _dir) = publisher();
        let drop = ChannelDrop::new();
        drop.write(&bundle(&store, &kid, "2026-Q3.1", 5));
        let active = ActiveRuleset::baseline().with_channel(drop.source(), &pubkey);

        assert!(active.reload().await.expect("first").changed);
        let again = active.reload().await.expect("second");
        assert_eq!(again.ruleset_version, "2026-Q3.1");
        assert!(!again.changed, "the same bundle is not a new one");
    }

    #[tokio::test]
    async fn a_republish_at_the_same_date_with_new_content_is_a_change() {
        // `verify_bundle` accepts an equal effective date as a correction, so
        // version-only comparison would report "unchanged" for a bundle that
        // carries different rules — and an operator would have no signal that
        // the correction landed.
        let (store, kid, pubkey, _dir) = publisher();
        let effective = Utc::now() - chrono::Duration::days(3);
        let drop = ChannelDrop::new();
        drop.write(&bundle_at(&store, &kid, "2026-Q3.1", 5, effective));
        let active = ActiveRuleset::baseline().with_channel(drop.source(), &pubkey);
        active.reload().await.expect("first");

        drop.write(&bundle_at(&store, &kid, "2026-Q3.1", 6, effective));
        let corrected = active.reload().await.expect("correction");
        assert_eq!(corrected.ruleset_version, "2026-Q3.1");
        assert!(corrected.changed, "same version, different rules");
        assert_eq!(active.get().content()["textileFibreThreshold"], 6);
    }

    #[tokio::test]
    async fn a_rollback_dropped_on_the_channel_is_refused_and_named() {
        // The adversarial case for a poller specifically: anyone who can write
        // the channel file can offer an authentic older bundle, and without the
        // currency check the poller would adopt it on its own within minutes.
        let (store, kid, pubkey, _dir) = publisher();
        let drop = ChannelDrop::new();
        drop.write(&bundle_at(
            &store,
            &kid,
            "2026-Q3.2",
            7,
            Utc::now() - chrono::Duration::days(2),
        ));
        let active = ActiveRuleset::baseline().with_channel(drop.source(), &pubkey);
        active.reload().await.expect("adopt current");

        drop.write(&bundle_at(
            &store,
            &kid,
            "2026-Q3.1",
            5,
            Utc::now() - chrono::Duration::days(9),
        ));
        assert!(
            matches!(
                active.reload().await,
                Err(RulesetReloadError::Superseded(_))
            ),
            "a rollback must be reported as superseded, not as a generic rejection"
        );
        assert_eq!(active.active_version(), "2026-Q3.2");
        assert_eq!(active.get().content()["textileFibreThreshold"], 7);
    }

    #[tokio::test]
    async fn a_future_dated_bundle_is_held_rather_than_rejected() {
        let (store, kid, pubkey, _dir) = publisher();
        let drop = ChannelDrop::new();
        drop.write(&bundle_at(
            &store,
            &kid,
            "2027-Q1.1",
            9,
            Utc::now() + chrono::Duration::days(365),
        ));
        let active = ActiveRuleset::baseline().with_channel(drop.source(), &pubkey);

        assert!(matches!(
            active.reload().await,
            Err(RulesetReloadError::NotYetEffective(_))
        ));
        assert_eq!(active.active_version(), "baseline");
    }

    #[tokio::test]
    async fn a_forged_bundle_on_the_channel_leaves_the_ruleset_in_force() {
        let (store, kid, pubkey, _dir) = publisher();
        let (bad_store, bad_kid, _, _bad_dir) = publisher();
        let drop = ChannelDrop::new();
        drop.write(&bundle(&store, &kid, "2026-Q3.1", 5));
        let active = ActiveRuleset::baseline().with_channel(drop.source(), &pubkey);
        active.reload().await.expect("adopt");

        drop.write(&bundle(&bad_store, &bad_kid, "evil", 0));
        assert!(matches!(
            active.reload().await,
            Err(RulesetReloadError::Rejected(_))
        ));
        assert_eq!(active.active_version(), "2026-Q3.1");
    }

    #[tokio::test]
    async fn a_missing_channel_file_is_unavailable_not_rejected() {
        // Transport failure and verification failure are different alarms: the
        // first says fix the drop, the second says distrust the bytes.
        let (_store, _kid, pubkey, _dir) = publisher();
        let drop = ChannelDrop::new();
        let active = ActiveRuleset::baseline().with_channel(drop.source(), &pubkey);

        assert!(matches!(
            active.reload().await,
            Err(RulesetReloadError::Unavailable(_))
        ));
        assert_eq!(active.active_version(), "baseline");
    }

    #[tokio::test]
    async fn a_source_reporting_no_change_holds_the_ruleset_in_force() {
        // The seam an HTTP source needs: answer `None` to a conditional GET and
        // the swap path must report what is in force, not treat it as an error
        // or as an adoption.
        struct Quiet;

        #[async_trait]
        impl RulesetSource for Quiet {
            fn describe(&self) -> String {
                "quiet".to_owned()
            }
            async fn fetch(&self) -> anyhow::Result<Option<SignedBundle>> {
                Ok(None)
            }
        }

        let (_store, _kid, pubkey, _dir) = publisher();
        let active = ActiveRuleset::baseline().with_channel(Box::new(Quiet), &pubkey);

        let r = active.reload().await.expect("no change is not a failure");
        assert_eq!(r.ruleset_version, "baseline");
        assert!(!r.changed);
    }

    #[tokio::test]
    async fn concurrent_reloads_cannot_land_a_rollback() {
        // Verification reads what is in force and then installs. If those two
        // steps could interleave, two reloads racing could both pass the
        // currency check against the same in-force manifest and the older one
        // could land last — the rollback `Superseded` exists to refuse,
        // arriving through the door left open beside it.
        let (store, kid, pubkey, _dir) = publisher();
        let newer = Arc::new(bundle_at(
            &store,
            &kid,
            "2026-Q3.2",
            7,
            Utc::now() - chrono::Duration::days(1),
        ));
        let older = Arc::new(bundle_at(
            &store,
            &kid,
            "2026-Q3.1",
            5,
            Utc::now() - chrono::Duration::days(9),
        ));

        // Two things this needs to detect the bug at all, both learned by
        // removing the lock and watching it pass anyway:
        //
        // A **barrier**, because the window is only the ~100µs of Ed25519
        // verification between reading what is in force and installing, and
        // threads spawned one at a time mostly serialise past it on their own.
        //
        // **Rounds**, because even released together the losing interleaving
        // showed up in roughly two runs in five. Ten rounds takes that to
        // better than 99% while staying well inside the slow-test budget. With the
        // lock in place every round is deterministic, so this cannot fail the
        // other way.
        const THREADS: usize = 16;
        const ROUNDS: usize = 10;

        for round in 0..ROUNDS {
            let active = Arc::new(ActiveRuleset::baseline());
            let start = Arc::new(std::sync::Barrier::new(THREADS));

            let mut handles = Vec::new();
            for i in 0..THREADS {
                let active = active.clone();
                let pubkey = pubkey.clone();
                let newer = newer.clone();
                let older = older.clone();
                let start = start.clone();
                handles.push(std::thread::spawn(move || {
                    let b = if i % 2 == 0 { &*newer } else { &*older };
                    start.wait();
                    let _ = active.load_and_swap(b, &pubkey);
                }));
            }
            for h in handles {
                h.join().expect("thread");
            }

            assert_eq!(
                active.version(),
                "2026-Q3.2",
                "round {round}: the newer bundle must win no matter the interleaving"
            );
            assert_eq!(active.get().content()["textileFibreThreshold"], 7);
        }
    }

    // ── Wiring from the environment ──────────────────────────────────────────

    /// Clear all three channel vars, then set the ones this case is about.
    /// Clearing first makes these hermetic: a `.env` loaded into the process
    /// (e.g. via `just`'s `set dotenv-load`) would otherwise leak a real
    /// channel into the assertions below.
    fn set_ruleset_env(vars: &[(&str, &str)]) {
        for key in &[
            "RULESET_BUNDLE_PATH",
            "RULESET_PUBLISHER_PUBKEY",
            "RULESET_POLL_INTERVAL_SECS",
        ] {
            unsafe { std::env::remove_var(key) };
        }
        for (key, value) in vars {
            unsafe { std::env::set_var(key, value) };
        }
    }

    #[test]
    #[serial]
    fn a_poll_interval_of_zero_disables_polling() {
        set_ruleset_env(&[("RULESET_POLL_INTERVAL_SECS", "0")]);
        assert!(poll_interval_from_env().is_none());
    }

    #[test]
    #[serial]
    fn an_unset_poll_interval_takes_the_default() {
        set_ruleset_env(&[]);
        assert_eq!(poll_interval_from_env(), Some(DEFAULT_POLL_INTERVAL));
    }

    #[test]
    #[serial]
    fn a_malformed_poll_interval_falls_back_rather_than_disabling() {
        // A typo must not be the way a node silently stops taking regulatory
        // updates — the quiet failure is worse than the loud one here.
        set_ruleset_env(&[("RULESET_POLL_INTERVAL_SECS", "five minutes")]);
        assert_eq!(poll_interval_from_env(), Some(DEFAULT_POLL_INTERVAL));
    }

    #[test]
    #[serial]
    fn a_bundle_path_without_a_pinned_key_configures_no_channel() {
        // Half a channel is not a channel: a source with no publisher key would
        // be a node that adopts whatever bytes it is handed.
        set_ruleset_env(&[("RULESET_BUNDLE_PATH", "/tmp/ruleset.json")]);
        let wiring = from_env();
        assert!(!wiring.active.has_channel());
        assert!(wiring.poll_interval.is_none());
    }

    #[test]
    #[serial]
    fn a_pinned_key_without_a_bundle_path_configures_no_channel() {
        set_ruleset_env(&[("RULESET_PUBLISHER_PUBKEY", "not-a-real-key")]);
        let wiring = from_env();
        assert!(!wiring.active.has_channel());
        assert!(wiring.poll_interval.is_none());
    }

    #[test]
    #[serial]
    fn both_settings_configure_a_polled_channel() {
        set_ruleset_env(&[
            ("RULESET_BUNDLE_PATH", "/tmp/ruleset.json"),
            ("RULESET_PUBLISHER_PUBKEY", "not-a-real-key"),
        ]);
        let wiring = from_env();
        assert!(wiring.active.has_channel());
        assert_eq!(wiring.poll_interval, Some(DEFAULT_POLL_INTERVAL));
    }
}
