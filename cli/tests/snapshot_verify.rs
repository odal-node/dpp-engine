//! `odal snapshot verify` driven as the real binary.
//!
//! The unit suite in `core::snapshot` pins the verdicts. This pins what an
//! operator and a script actually meet: the exit code, the argument group, and
//! the fact that a stripped bound does not come back looking like a pass.

mod helpers;
use helpers::{odal, signed_snapshot, static_server};

use chrono::{Duration, Utc};
use tempfile::TempDir;

/// Write a document into `home` and return its path as a string.
fn snapshot_file(home: &TempDir, document: &serde_json::Value) -> String {
    let path = home.path().join("public.json");
    std::fs::write(&path, serde_json::to_vec(document).expect("serialise")).expect("write");
    path.to_str().expect("utf-8 path").to_owned()
}

#[test]
fn a_current_snapshot_exits_zero_and_says_so() {
    let home = TempDir::new().unwrap();
    let as_of = Utc::now();
    let fixture = signed_snapshot(as_of, as_of + Duration::days(7));
    let path = snapshot_file(&home, &fixture.document);

    let run = odal(
        home.path(),
        &["snapshot", "verify", &path, "--key", &fixture.key_b64],
    );

    assert_eq!(
        run.code,
        0,
        "expected exit 0, got {}: {}",
        run.code,
        run.output()
    );
    assert!(run.output().contains("CURRENT"), "got: {}", run.output());
}

#[test]
fn an_expired_snapshot_exits_one_and_is_not_called_tampered() {
    let home = TempDir::new().unwrap();
    let as_of = Utc::now() - Duration::days(30);
    let fixture = signed_snapshot(as_of, as_of + Duration::days(7));
    let path = snapshot_file(&home, &fixture.document);

    let run = odal(
        home.path(),
        &["snapshot", "verify", &path, "--key", &fixture.key_b64],
    );

    assert_eq!(run.code, 1, "got: {}", run.output());
    assert!(run.output().contains("EXPIRED"), "got: {}", run.output());
    // The signatures on an expired snapshot are fine. Saying anything that
    // sends a reader hunting for tampering would be actively misleading.
    assert!(
        run.output().contains("intact"),
        "an expired copy must be described as intact and stale: {}",
        run.output()
    );
}

/// 🚨 The failure mode #259 is written around, checked through the binary.
#[test]
fn a_stripped_bound_exits_nonzero_and_is_never_called_current() {
    let home = TempDir::new().unwrap();
    let as_of = Utc::now();
    let mut fixture = signed_snapshot(as_of, as_of + Duration::days(7));
    fixture
        .document
        .as_object_mut()
        .expect("object")
        .remove("snapshotJwsSignature");
    let path = snapshot_file(&home, &fixture.document);

    let run = odal(
        home.path(),
        &["snapshot", "verify", &path, "--key", &fixture.key_b64],
    );

    assert_eq!(
        run.code,
        1,
        "a stripped bound must not exit 0: {}",
        run.output()
    );
    assert!(
        run.output().contains("UNVERIFIABLE"),
        "got: {}",
        run.output()
    );
    assert!(
        !run.output().contains("CURRENT"),
        "a stripped bound must never render as current: {}",
        run.output()
    );
}

#[test]
fn a_snapshot_is_fetched_over_http_when_the_target_is_a_url() {
    let home = TempDir::new().unwrap();
    let as_of = Utc::now();
    let fixture = signed_snapshot(as_of, as_of + Duration::days(7));
    let origin = static_server(vec![(
        "/dpp/x/public.json".to_owned(),
        fixture.document.to_string(),
    )]);
    let url = format!("{origin}/dpp/x/public.json");

    let run = odal(
        home.path(),
        &["snapshot", "verify", &url, "--key", &fixture.key_b64],
    );

    assert_eq!(run.code, 0, "got: {}", run.output());
    assert!(run.output().contains("CURRENT"), "got: {}", run.output());
}

/// The `--did-url` path, against a DID document served from somewhere the
/// node's outage would not take down — the only deployment where it helps.
#[test]
fn the_key_can_come_from_a_separately_hosted_did_document() {
    let home = TempDir::new().unwrap();
    let as_of = Utc::now();
    let fixture = signed_snapshot(as_of, as_of + Duration::days(7));
    let origin = static_server(vec![
        ("/public.json".to_owned(), fixture.document.to_string()),
        (
            "/.well-known/did.json".to_owned(),
            fixture.did_document.to_string(),
        ),
    ]);

    let run = odal(
        home.path(),
        &[
            "snapshot",
            "verify",
            &format!("{origin}/public.json"),
            "--did-url",
            &format!("{origin}/.well-known/did.json"),
        ],
    );

    assert_eq!(run.code, 0, "got: {}", run.output());
    assert!(run.output().contains("CURRENT"), "got: {}", run.output());
}

/// 🚨 A key beginning with `-` is a key, not a flag.
///
/// The public key is **base64url**, whose alphabet includes `-` and `_`. About
/// one key in sixty-four therefore starts with a hyphen, and clap read it as an
/// unknown flag: `error: unexpected argument '-S' found`, exit 2. Nothing the
/// operator typed was wrong, and re-running never helped, because it depends on
/// their key rather than their command.
///
/// This surfaced as an intermittent failure of
/// `a_current_snapshot_exits_zero_and_says_so`, whose key is freshly generated
/// each run — so the suite passed until a run happened to generate one. The key
/// here is a **fixed** wrong-but-hyphen-leading value so the parse is exercised
/// every time; the verdict is `UNVERIFIABLE` because it is not the signing key,
/// which is exactly the point: the argument has to reach the verifier at all.
#[test]
fn a_key_beginning_with_a_hyphen_is_parsed_as_a_value() {
    let home = TempDir::new().unwrap();
    let as_of = Utc::now();
    let fixture = signed_snapshot(as_of, as_of + Duration::days(7));
    let path = snapshot_file(&home, &fixture.document);

    let run = odal(
        home.path(),
        &[
            "snapshot",
            "verify",
            &path,
            "--key",
            "-Sm1bW9ja19rZXlfdGhhdF9zdGFydHNfd2l0aF9hX2h5cGhlbg",
        ],
    );

    assert_ne!(
        run.code,
        2,
        "a hyphen-leading key was rejected as a flag rather than read as a value: {}",
        run.output()
    );
    assert_eq!(run.code, 1, "got: {}", run.output());
    assert!(
        run.output().contains("UNVERIFIABLE"),
        "got: {}",
        run.output()
    );
}

#[test]
fn a_target_that_cannot_be_read_exits_two() {
    let home = TempDir::new().unwrap();
    let fixture = signed_snapshot(Utc::now(), Utc::now() + Duration::days(7));

    let run = odal(
        home.path(),
        &[
            "snapshot",
            "verify",
            "no/such/file.json",
            "--key",
            &fixture.key_b64,
        ],
    );

    // Exit 2 is "the check did not happen", which is a different thing from a
    // check that happened and failed. Collapsing it into 1 would tell a script
    // the snapshot is bad when nothing was ever looked at.
    assert_eq!(run.code, 2, "got: {}", run.output());
}

#[test]
fn a_key_source_is_required_and_only_one_is_accepted() {
    let home = TempDir::new().unwrap();
    let fixture = signed_snapshot(Utc::now(), Utc::now() + Duration::days(7));
    let path = snapshot_file(&home, &fixture.document);

    // Exit 2, not merely non-zero: a usage error is "the check could not be
    // made", which is the same class as an unreadable target and the contract
    // gives it the same code. clap's own usage-error code is 2, so the two
    // agree — pinned here so a later change to either is caught.
    let neither = odal(home.path(), &["snapshot", "verify", &path]);
    assert_eq!(neither.code, 2, "got: {}", neither.output());

    let both = odal(
        home.path(),
        &[
            "snapshot",
            "verify",
            &path,
            "--key",
            &fixture.key_b64,
            "--did-url",
            "https://example.invalid/.well-known/did.json",
        ],
    );
    assert_eq!(
        both.code,
        2,
        "two key sources must be refused: {}",
        both.output()
    );
}

#[test]
fn the_json_verdict_is_machine_readable_and_states_its_scope() {
    let home = TempDir::new().unwrap();
    let as_of = Utc::now();
    let fixture = signed_snapshot(as_of, as_of + Duration::days(7));
    let path = snapshot_file(&home, &fixture.document);

    let run = odal(
        home.path(),
        &[
            "snapshot",
            "verify",
            &path,
            "--key",
            &fixture.key_b64,
            "--json",
        ],
    );

    assert_eq!(run.code, 0, "got: {}", run.output());
    let verdict: serde_json::Value =
        serde_json::from_str(&run.stdout).expect("--json emits JSON on stdout");
    assert_eq!(verdict["outcome"], serde_json::json!("current"));
    assert_eq!(verdict["verified"], serde_json::json!(true));
    assert!(
        verdict["covers"]
            .as_str()
            .unwrap_or_default()
            .contains("outer"),
        "the verdict must say it is the outer proof only: {verdict}"
    );
}

/// This command must not need a configured profile — it is for the case where
/// there is no node to have a profile for.
#[test]
fn it_works_on_a_machine_with_no_profile_configured() {
    let home = TempDir::new().unwrap();
    let as_of = Utc::now();
    let fixture = signed_snapshot(as_of, as_of + Duration::days(7));
    let path = snapshot_file(&home, &fixture.document);

    let run = odal(
        home.path(),
        &["snapshot", "verify", &path, "--key", &fixture.key_b64],
    );

    assert_eq!(run.code, 0, "got: {}", run.output());
    assert!(
        !run.output().contains("No profile configured yet"),
        "the no-node check must not ask for a profile: {}",
        run.output()
    );
}
