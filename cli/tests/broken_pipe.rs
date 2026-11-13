//! A reader that goes away is not a crash, and it is not a success either.
//!
//! `odal passport list | head -n 1` ended in "failed printing to stdout: Broken
//! pipe" and exit code 101, because `println!` panics when the pipe it writes to
//! has been closed. `head` closing early is how it is meant to be used, so the
//! message is silenced, but the command was cut short and exits 141 (128 plus
//! SIGPIPE), never 0. A mutating command cut short that way must not report
//! success, and `key create --use` saves the key before it prints for the same
//! reason.

mod helpers;

use std::process::{Command, Stdio};

use helpers::{closed_origin, home_with_node, odal_env, recording_server};

#[test]
fn a_closed_pipe_ends_the_command_quietly() {
    let origin = closed_origin();
    let home = tempfile::TempDir::new().unwrap();
    let node = Command::new(env!("CARGO_BIN_EXE_odal"))
        .args(["profile", "create", "stub", "--node-url", &origin])
        .env("HOME", home.path())
        .env("USERPROFILE", home.path())
        .current_dir(home.path())
        .output()
        .expect("create a profile");
    assert!(node.status.success());

    // `status` prints a table whatever the node says, which makes it a command
    // that writes to stdout without needing a node to answer.
    let mut child = Command::new(env!("CARGO_BIN_EXE_odal"))
        .arg("status")
        .env("HOME", home.path())
        .env("USERPROFILE", home.path())
        .env_remove("ODAL_API_KEY")
        .current_dir(home.path())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start odal");
    // The reader goes away before the first line is written.
    drop(child.stdout.take());
    let output = child.wait_with_output().expect("wait for odal");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("Broken pipe") && !stderr.contains("panicked"),
        "a closed pipe should not be reported: {stderr}"
    );
    assert_eq!(output.status.code(), Some(141), "{stderr}");
}

#[test]
fn a_key_minted_into_a_closed_pipe_is_still_saved_as_the_active_key() {
    let (origin, requests) = recording_server(
        "201 Created",
        r#"{"secret":"odal_sk_minted_into_a_closed_pipe","name":"ci","scope":"admin"}"#,
    );
    let home = home_with_node(&origin);

    let mut child = Command::new(env!("CARGO_BIN_EXE_odal"))
        .args(["key", "create", "ci", "--use"])
        .env("HOME", home.path())
        .env("USERPROFILE", home.path())
        .env_remove("HOMEDRIVE")
        .env_remove("HOMEPATH")
        .env_remove("ODAL_PROFILE")
        .env_remove("ODAL_VAULT_URL")
        // A key is needed so the request is sent at all.
        .env("ODAL_API_KEY", "odal_sk_test")
        .current_dir(home.path())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start odal");
    // The reader goes away before the secret is printed.
    drop(child.stdout.take());
    let output = child.wait_with_output().expect("wait for odal");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("Broken pipe") && !stderr.contains("panicked"),
        "a closed pipe should not be reported: {stderr}"
    );
    assert_eq!(output.status.code(), Some(141), "{stderr}");
    let minted = requests
        .recv()
        .expect("the key-creation request reached the stub");
    assert_eq!(minted.path, "/vault/api/v1/api-keys");

    // The credential is kept in the 0600 store, not in config.toml.
    let store = home
        .path()
        .join(".config")
        .join("odal")
        .join("credentials.toml");
    let saved = std::fs::read_to_string(&store)
        .unwrap_or_else(|e| panic!("no credentials store at {}: {e}", store.display()));
    assert!(
        saved.contains("odal_sk_minted_into_a_closed_pipe"),
        "the minted key was not saved before the closed pipe ended the command: {saved}"
    );
}

#[test]
fn a_minted_key_is_printed_even_when_it_cannot_be_saved() {
    let (origin, _requests) = recording_server(
        "201 Created",
        r#"{"secret":"odal_sk_printed_though_unsaved","name":"ci","scope":"admin"}"#,
    );
    let home = home_with_node(&origin);
    // A directory where the credentials file belongs makes the save fail, and
    // unlike a permission change it fails for root too.
    let store = home
        .path()
        .join(".config")
        .join("odal")
        .join("credentials.toml");
    std::fs::create_dir_all(&store).expect("make the store a directory");

    let run = odal_env(
        home.path(),
        &["key", "create", "ci", "--use"],
        &[("ODAL_API_KEY", "odal_sk_test")],
    );

    assert_ne!(run.code, 0, "{}", run.output());
    assert!(
        run.stdout.contains("odal_sk_printed_though_unsaved"),
        "the secret is shown once and cannot be fetched again, so it must print: {}",
        run.output()
    );
    assert!(
        run.stderr.contains("could not be saved"),
        "the failed save should be named: {}",
        run.output()
    );
}
