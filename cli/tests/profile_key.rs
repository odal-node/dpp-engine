//! Which node a profile's stored API key is sent to.
//!
//! The credentials store is keyed by profile name, not by node, so a key
//! outlives any one URL the profile holds. `odal profile create --force` over an
//! existing profile used to replace its URLs and keep its key, and the next
//! command sent the previous node's key to the new one. These pin the rule that
//! replaced it: a key is kept only while the profile's vault URL is unchanged.

mod helpers;
use helpers::{Recorded, config_path, odal, odal_env, recording_server};

use std::path::Path;
use std::sync::mpsc::Receiver;

use tempfile::TempDir;

const WHOAMI: &str = r#"{"userId":"key:1","scope":"admin","keyId":"1"}"#;
const FIRST_NODES_KEY: &str = "odal_sk_issued_by_the_first_node";

/// A home whose profile `site` points at `origin`, holding a key that node
/// accepted through `odal key use`.
fn home_with_key_from(origin: &str) -> TempDir {
    let home = TempDir::new().expect("temp dir");
    let run = odal(
        home.path(),
        &["profile", "create", "site", "--node-url", origin],
    );
    assert_eq!(run.code, 0, "{}", run.output());
    let run = odal_env(
        home.path(),
        &["--profile", "site", "key", "use"],
        &[("ODAL_API_SECRET", FIRST_NODES_KEY)],
    );
    assert_eq!(run.code, 0, "{}", run.output());
    home
}

/// Every request `node` has received so far.
///
/// The command under test has exited when this runs, and the server records a
/// request before it answers it, so nothing is still in flight.
fn received(node: &Receiver<Recorded>) -> Vec<Recorded> {
    node.try_iter().collect()
}

fn credentials(home: &Path) -> String {
    std::fs::read_to_string(home.join(".config").join("odal").join("credentials.toml"))
        .unwrap_or_default()
}

/// Assert that `whoami` reaches `node` and that no request carries `key`.
fn whoami_reaches_without(home: &Path, node: &Receiver<Recorded>, key: &str) {
    let _ = odal(home, &["--profile", "site", "whoami"]);
    let requests = received(node);
    assert!(
        !requests.is_empty(),
        "whoami never reached the node the profile names, so this proves nothing"
    );
    for request in &requests {
        assert!(
            !request
                .authorization
                .as_deref()
                .unwrap_or_default()
                .contains(key),
            "{} {} carried a key this node never issued",
            request.method,
            request.path
        );
    }
}

#[test]
fn a_profile_pointed_at_another_node_does_not_send_it_the_previous_nodes_key() {
    let (first, _first_node) = recording_server("200 OK", WHOAMI);
    let home = home_with_key_from(&first);
    let (second, second_node) = recording_server("200 OK", WHOAMI);

    let run = odal(
        home.path(),
        &[
            "profile",
            "create",
            "site",
            "--force",
            "--node-url",
            &second,
        ],
    );

    assert_eq!(run.code, 0, "{}", run.output());
    assert!(
        run.output().contains("was removed") && run.output().contains("key use"),
        "removing the key must be said, with the command that saves another:\n{}",
        run.output()
    );
    assert!(
        !credentials(home.path()).contains(FIRST_NODES_KEY),
        "the first node's key is still stored under the re-pointed profile"
    );
    whoami_reaches_without(home.path(), &second_node, FIRST_NODES_KEY);
}

#[test]
fn overwriting_a_profile_with_the_same_vault_url_keeps_its_key() {
    let (node, requests) = recording_server("200 OK", WHOAMI);
    let home = home_with_key_from(&node);
    received(&requests); // the check `key use` made

    let run = odal(
        home.path(),
        &[
            "profile",
            "create",
            "site",
            "--force",
            "--node-url",
            &node,
            "--resolver-url",
            "http://127.0.0.1:9",
        ],
    );

    assert_eq!(run.code, 0, "{}", run.output());
    assert!(!run.output().contains("was removed"), "{}", run.output());
    let _ = odal(home.path(), &["--profile", "site", "whoami"]);
    let expected = format!("Bearer {FIRST_NODES_KEY}");
    assert!(
        received(&requests)
            .iter()
            .any(|r| r.authorization.as_deref() == Some(expected.as_str())),
        "the node that issued the key no longer receives it"
    );
}

#[test]
fn a_key_stored_under_a_name_no_profile_holds_is_not_sent_to_a_new_profiles_node() {
    let home = TempDir::new().expect("temp dir");
    let store = home.path().join(".config").join("odal");
    std::fs::create_dir_all(&store).expect("make the config dir");
    std::fs::write(
        store.join("credentials.toml"),
        "[keys]\nsite = \"odal_sk_left_behind\"\n",
    )
    .expect("seed the credentials store");
    let (node, requests) = recording_server("200 OK", WHOAMI);

    let run = odal(
        home.path(),
        &["profile", "create", "site", "--node-url", &node],
    );

    assert_eq!(run.code, 0, "{}", run.output());
    assert!(run.output().contains("was removed"), "{}", run.output());
    whoami_reaches_without(home.path(), &requests, "odal_sk_left_behind");
}

/// The key goes before the profile is written, so a failed write never leaves
/// the new URL holding the old key. The cost of that order is that the old
/// profile survives the failure without its key, and the error is the only
/// place left to say so.
#[cfg(unix)]
#[test]
fn a_key_removed_before_the_profile_write_fails_is_still_reported() {
    use std::os::unix::fs::PermissionsExt;

    let (first, _first_node) = recording_server("200 OK", WHOAMI);
    let home = home_with_key_from(&first);
    let config = config_path(home.path());
    std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o444))
        .expect("make config.toml read-only");
    if std::fs::OpenOptions::new()
        .write(true)
        .open(&config)
        .is_ok()
    {
        eprintln!("skipped: this user can write a read-only file, so the write cannot fail");
        return;
    }

    let run = odal(
        home.path(),
        &[
            "profile",
            "create",
            "site",
            "--force",
            "--node-url",
            "http://127.0.0.1:9",
        ],
    );

    assert_ne!(run.code, 0, "{}", run.output());
    assert!(
        run.output().contains("already removed") && run.output().contains("key use"),
        "a failed write must still say the key is gone, and how to save one:\n{}",
        run.output()
    );
    assert!(
        !credentials(home.path()).contains(FIRST_NODES_KEY),
        "the key was expected to be removed before the write"
    );
}
