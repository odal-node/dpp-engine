//! `odal snapshot verify` — check a continuity snapshot's signed freshness
//! bound, with no node involved.
//!
//! # Why the key is supplied rather than discovered
//!
//! The obvious design fetches the operator's key from the `did:web` document at
//! the configured `identity_url`. That reads as safe — a DID document is static
//! and cacheable — but on the deployment this command is for it is not: the
//! single-binary node mounts `dpp-identity`'s router itself, and the CLI's
//! default `identity_url` is `http://localhost:8001/identity`. The node being
//! down takes the DID document down with it, so key discovery fails in exactly
//! the situation the static tier exists to survive.
//!
//! So the key is an argument. `--did-url` remains available for the deployment
//! where identity really is served from somewhere else, but nothing is read
//! from the profile implicitly — a check that silently reached for a live
//! service would be answering a different question than the one asked.
//!
//! # `Absent` is a failure here
//!
//! `SnapshotBound::Absent` means the document claims no bound. On a live read
//! that is normal. On a copy pulled off the static tier — which is the only
//! thing this command is ever pointed at — it means the outer proof was
//! stripped, leaving `asOf`/`validUntil` as text anyone could have written.
//! Core deliberately ships no `is_valid()` because only the caller knows which
//! of the two it fetched. This caller knows: it is always the static-tier
//! question, so `Absent` is reported as unverifiable and never as valid.

use anyhow::{Context, Result, anyhow};
use chrono::{DateTime, Utc};
use dpp_vc::SnapshotBound;

/// Read the snapshot, resolve the key, and check the bound.
///
/// `now` is a parameter rather than a call to the clock, matching
/// `verify_snapshot_bound`'s own reasoning: the expiry boundary is then a
/// function of its inputs and a test can sit on either side of it.
///
/// # Errors
/// The document could not be read, fetched, or parsed as JSON; or the key could
/// not be resolved. All of these are exit 2 — the check did not happen, which is
/// a different outcome from a check that happened and failed.
pub async fn action_snapshot_verify(
    target: &str,
    key: Option<&str>,
    did_url: Option<&str>,
    now: DateTime<Utc>,
) -> Result<SnapshotBound> {
    let document = load_document(target).await?;
    let key_b64 = resolve_key(&document, key, did_url).await?;
    Ok(dpp_vc::verify_snapshot_bound(&document, &key_b64, now))
}

/// The client both fetches use.
///
/// This file is on `outbound-check`'s allow-list — its targets are typed by the
/// operator, and the guard would refuse the localhost and private-endpoint
/// copies that are the normal case here. Taking that exemption means setting by
/// hand what the guard would otherwise have set: `reqwest`'s default client has
/// **no timeout at all** and follows ten redirects, so an unresponsive host
/// hangs the command for ever and a redirect chain is an unbounded walk.
///
/// Three hops rather than none: a bucket URL legitimately redirects to a
/// regional endpoint, and a static tier behind a CDN can add one more.
///
/// # Errors
/// [`reqwest::Error`] if the client cannot be built, which needs a broken TLS
/// backend — surfaced rather than unwrapped so it reads as exit 2 like every
/// other "the check did not happen".
fn client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::limited(3))
        .build()
        .context("building the HTTP client")
}

/// Fetch or read the snapshot document.
///
/// An `http(s)` target is fetched; anything else is a path. The static tier is
/// a bucket, so the URL form is the common one — but a copy already pulled down
/// is the case where there is no network at all, and that has to work too.
async fn load_document(target: &str) -> Result<serde_json::Value> {
    let bytes = if is_url(target) {
        let response = client()?
            .get(target)
            .send()
            .await
            .with_context(|| format!("fetching snapshot from {target}"))?;
        let status = response.status();
        if !status.is_success() {
            return Err(anyhow!("fetching snapshot from {target}: HTTP {status}"));
        }
        response
            .bytes()
            .await
            .with_context(|| format!("reading snapshot body from {target}"))?
            .to_vec()
    } else {
        std::fs::read(target).with_context(|| format!("reading snapshot file {target}"))?
    };

    serde_json::from_slice(&bytes).with_context(|| format!("{target} is not JSON"))
}

/// The base64 public key to check the snapshot's proof under.
///
/// With `--did-url`, the proof's own `kid` picks the verification method, and
/// only the primary key is used when it names none. That ordering matters
/// across a key rotation: a snapshot signed before the rotation verifies under
/// the archived key the DID document still carries, and resolving straight to
/// the primary would report a perfectly sound copy as unproven.
async fn resolve_key(
    document: &serde_json::Value,
    key: Option<&str>,
    did_url: Option<&str>,
) -> Result<String> {
    if let Some(key) = key {
        return Ok(key.to_owned());
    }
    let did_url = did_url.ok_or_else(|| anyhow!("no key source given: pass --key or --did-url"))?;

    let did_document: serde_json::Value = client()?
        .get(did_url)
        .send()
        .await
        .with_context(|| format!("fetching DID document from {did_url}"))?
        .json()
        .await
        .with_context(|| format!("{did_url} did not return a JSON DID document"))?;

    let kid = document
        .get("snapshotJwsSignature")
        .and_then(serde_json::Value::as_str)
        .and_then(dpp_crypto::jws::extract_kid_from_jws);

    let resolved = match kid {
        Some(kid) => dpp_crypto::jws::extract_key_by_fingerprint(&did_document, &kid),
        None => dpp_crypto::jws::extract_primary_public_key(&did_document),
    };

    resolved.ok_or_else(|| anyhow!("no usable Ed25519 public key in the DID document at {did_url}"))
}

/// True for a target this command should fetch rather than open.
fn is_url(target: &str) -> bool {
    target.starts_with("http://") || target.starts_with("https://")
}

/// The process exit code for a verdict.
///
/// `0` only for a proven, unexpired bound. Everything else is `1` — including
/// [`SnapshotBound::Absent`], for the reason in this module's docs. A target
/// that could not be read never reaches here; that is `2`, produced by the
/// `Err` arm in the command.
#[must_use]
pub fn exit_code(bound: &SnapshotBound) -> i32 {
    match bound {
        SnapshotBound::Current { .. } => 0,
        // `SnapshotBound` is `#[non_exhaustive]`: a variant added by a later
        // core release lands here. Failing closed is the only safe default —
        // an unrecognised verdict is not a verdict this command can vouch for.
        _ => 1,
    }
}

/// The verdict as JSON, for `--json`.
///
/// Hand-built rather than derived: [`SnapshotBound`] is not `Serialize`, and
/// `#[non_exhaustive]` means a later core release could add a variant this
/// build has never seen. `outcome` is the machine-readable discriminant and
/// `verified` is the same fail-closed judgement [`exit_code`] makes, so a
/// script reading either one gets the same answer.
#[must_use]
pub fn verdict_json(bound: &SnapshotBound) -> serde_json::Value {
    let rfc3339 = |t: &DateTime<Utc>| t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let mut value = match bound {
        SnapshotBound::Current { as_of, valid_until } => serde_json::json!({
            "outcome": "current",
            "asOf": rfc3339(as_of),
            "validUntil": rfc3339(valid_until),
        }),
        SnapshotBound::Expired { as_of, valid_until } => serde_json::json!({
            "outcome": "expired",
            "asOf": rfc3339(as_of),
            "validUntil": rfc3339(valid_until),
        }),
        SnapshotBound::Absent => serde_json::json!({
            "outcome": "absent",
            "reason": "the document carries no snapshot proof; on a static-tier \
                       copy that means the bound was stripped",
        }),
        SnapshotBound::Unproven(reason) => serde_json::json!({
            "outcome": "unproven",
            "reason": reason,
        }),
        _ => serde_json::json!({ "outcome": "unrecognised" }),
    };
    value["verified"] = serde_json::Value::Bool(exit_code(bound) == 0);
    // Said in the payload, not only in the prose: a consumer that serves the
    // content still owes the publish-time check, and a script reading this
    // should not conclude the passport is verified end to end.
    value["covers"] = serde_json::Value::String("the outer snapshot proof only".to_owned());
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A keystore with one key, plus the base64 public key that checks its
    /// signatures — the pair every fixture below is built from.
    ///
    /// `tempfile`, never `env::temp_dir()`: these files hold an Ed25519 private
    /// key, and only the former creates the directory with restrictive
    /// permissions and removes it on drop. The `TempDir` is returned so it
    /// outlives the store.
    fn keystore() -> (tempfile::TempDir, dpp_crypto::keystore::KeyStore, String) {
        let dir = tempfile::tempdir().expect("temp dir");
        let store =
            dpp_crypto::keystore::KeyStore::open(dir.path().join("keystore.json"), "test-pass")
                .expect("open keystore");
        store.generate_key("root").expect("generate key");
        let did = dpp_vc::build_did_document(&store, "snapshot-test.example.com", "root")
            .expect("build did document");
        let key = dpp_crypto::jws::extract_primary_public_key(&did)
            .expect("did document carries a primary key");
        (dir, store, key)
    }

    /// A snapshot document in the shape `render_public_snapshot` writes: the
    /// dates go in, the document is signed as it then stands, and the proof is
    /// inserted afterwards so it never signs over itself.
    fn signed_snapshot(
        store: &dpp_crypto::keystore::KeyStore,
        as_of: DateTime<Utc>,
        valid_until: DateTime<Utc>,
    ) -> serde_json::Value {
        let rfc3339 = |t: DateTime<Utc>| t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let mut document = serde_json::json!({
            "id": "0198f000-0000-7000-8000-000000000000",
            "productGroup": "battery",
            "asOf": rfc3339(as_of),
            "validUntil": rfc3339(valid_until),
        });
        let proof = dpp_crypto::jws::sign(store, "root", &document).expect("sign snapshot");
        document["snapshotJwsSignature"] = serde_json::Value::String(proof);
        document
    }

    /// Write a document to a file and run the real command path over it.
    async fn check(
        document: &serde_json::Value,
        key: &str,
        now: DateTime<Utc>,
    ) -> (tempfile::TempDir, SnapshotBound) {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("public.json");
        std::fs::write(&path, serde_json::to_vec(document).expect("serialise")).expect("write");
        let bound =
            action_snapshot_verify(path.to_str().expect("utf-8 path"), Some(key), None, now)
                .await
                .expect("the document is readable");
        (dir, bound)
    }

    #[tokio::test]
    async fn a_fresh_snapshot_is_current() {
        let (_dir, store, key) = keystore();
        let as_of = Utc::now();
        let valid_until = as_of + chrono::Duration::days(7);
        let document = signed_snapshot(&store, as_of, valid_until);

        let (_d, bound) = check(&document, &key, as_of + chrono::Duration::days(1)).await;

        assert!(
            matches!(bound, SnapshotBound::Current { .. }),
            "expected Current, got {bound:?}"
        );
        assert_eq!(exit_code(&bound), 0);
    }

    #[tokio::test]
    async fn a_snapshot_read_after_its_bound_is_expired() {
        let (_dir, store, key) = keystore();
        let as_of = Utc::now() - chrono::Duration::days(30);
        let valid_until = as_of + chrono::Duration::days(7);
        let document = signed_snapshot(&store, as_of, valid_until);

        let (_d, bound) = check(&document, &key, Utc::now()).await;

        assert!(
            matches!(bound, SnapshotBound::Expired { .. }),
            "expected Expired, got {bound:?}"
        );
        assert_eq!(exit_code(&bound), 1);
    }

    /// 🚨 The one this command exists to get right. Stripping the proof while
    /// leaving the dates in place yields `Absent`, not `Expired` — an
    /// unverified `validUntil` is not a bound — and `Absent` off the static
    /// tier means the bound was removed. It must not read as a pass.
    #[tokio::test]
    async fn stripping_the_proof_is_unverifiable_not_valid() {
        let (_dir, store, key) = keystore();
        let as_of = Utc::now();
        let valid_until = as_of + chrono::Duration::days(7);
        let mut document = signed_snapshot(&store, as_of, valid_until);
        document
            .as_object_mut()
            .expect("object")
            .remove("snapshotJwsSignature");

        let (_d, bound) = check(&document, &key, as_of).await;

        assert_eq!(bound, SnapshotBound::Absent);
        assert_ne!(exit_code(&bound), 0, "a stripped bound must not exit 0");
        assert_eq!(verdict_json(&bound)["verified"], serde_json::json!(false));
    }

    #[tokio::test]
    async fn editing_a_covered_date_does_not_verify() {
        let (_dir, store, key) = keystore();
        let as_of = Utc::now();
        let mut document = signed_snapshot(&store, as_of, as_of - chrono::Duration::days(1));
        // Push the bound years out while leaving the proof in place. The dates
        // are inside what the proof covers, so this is the edit the outer
        // signature exists to catch.
        document["validUntil"] = serde_json::Value::String(
            (as_of + chrono::Duration::days(3650))
                .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        );

        let (_d, bound) = check(&document, &key, as_of).await;

        assert!(
            matches!(bound, SnapshotBound::Unproven(_)),
            "expected Unproven, got {bound:?}"
        );
        assert_eq!(exit_code(&bound), 1);
    }

    #[tokio::test]
    async fn another_operators_key_does_not_verify() {
        let (_dir, store, _key) = keystore();
        let (_other_dir, _other_store, other_key) = keystore();
        let as_of = Utc::now();
        let document = signed_snapshot(&store, as_of, as_of + chrono::Duration::days(7));

        let (_d, bound) = check(&document, &other_key, as_of).await;

        assert!(
            matches!(bound, SnapshotBound::Unproven(_)),
            "expected Unproven, got {bound:?}"
        );
    }

    #[tokio::test]
    async fn an_unreadable_target_is_an_error_not_a_verdict() {
        let (_dir, _store, key) = keystore();
        let err = action_snapshot_verify("no/such/snapshot.json", Some(&key), None, Utc::now())
            .await
            .expect_err("a missing file cannot produce a verdict");
        assert!(
            format!("{err:?}").contains("no/such/snapshot.json"),
            "the error should name the target, got: {err:?}"
        );
    }

    #[tokio::test]
    async fn no_key_source_is_refused_before_anything_is_fetched() {
        let (_dir, store, _key) = keystore();
        let as_of = Utc::now();
        let document = signed_snapshot(&store, as_of, as_of + chrono::Duration::days(7));
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("public.json");
        std::fs::write(&path, serde_json::to_vec(&document).expect("serialise")).expect("write");

        // clap enforces this too, but the action is callable on its own and a
        // key source that silently defaulted would be the wrong kind of helpful.
        let err = action_snapshot_verify(path.to_str().expect("utf-8"), None, None, as_of)
            .await
            .expect_err("no key source");
        assert!(format!("{err:?}").contains("--key"), "got: {err:?}");
    }

    #[test]
    fn the_json_verdict_names_what_it_does_not_cover() {
        let as_of = Utc::now();
        let json = verdict_json(&SnapshotBound::Current {
            as_of,
            valid_until: as_of + chrono::Duration::days(7),
        });
        assert_eq!(json["outcome"], serde_json::json!("current"));
        assert_eq!(json["verified"], serde_json::json!(true));
        assert!(
            json["covers"]
                .as_str()
                .unwrap_or_default()
                .contains("outer"),
            "the payload must say it is the outer proof only: {json}"
        );
    }

    #[test]
    fn only_a_current_bound_exits_zero() {
        let as_of = Utc::now();
        let valid_until = as_of + chrono::Duration::days(7);

        assert_eq!(exit_code(&SnapshotBound::Current { as_of, valid_until }), 0);
        assert_eq!(exit_code(&SnapshotBound::Expired { as_of, valid_until }), 1);
        assert_eq!(exit_code(&SnapshotBound::Unproven("torn".into())), 1);
    }

    /// The distinction this command exists to preserve: a stripped bound is not
    /// a passing check. Pinned separately from the table above because it is
    /// the one that reads as harmless and is not.
    #[test]
    fn a_stripped_bound_is_not_reported_as_valid() {
        assert_eq!(exit_code(&SnapshotBound::Absent), 1);
    }

    #[test]
    fn a_target_is_fetched_only_when_it_is_an_http_url() {
        assert!(is_url("http://localhost:9000/bucket/public.json"));
        assert!(is_url("https://cdn.example/dpp/public.json"));
        assert!(!is_url("./public.json"));
        assert!(!is_url("C:\\snapshots\\public.json"));
        // Not a scheme this command fetches — it is a path, and opening it
        // fails with a readable error rather than being silently requested.
        assert!(!is_url("ftp://example/public.json"));
    }
}
