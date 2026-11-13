//! `odal key create` mints the scope it is asked for.
//!
//! It always minted an admin key: the request carried only a name, so a read or
//! write key could be made only through the HTTP API.

mod helpers;
use helpers::{home_with_node, odal, odal_env, recording_server};

use std::time::Duration;

const CREATED: &str = r#"{"id":"0198f000-0000-7000-8000-0000000000bb","secret":"odal_sk_created"}"#;

fn create_key(extra: &[&str]) -> (helpers::Run, serde_json::Value) {
    let (origin, received) = recording_server("201 Created", CREATED);
    let home = home_with_node(&origin);
    let mut args = vec!["key", "create", "ci"];
    args.extend_from_slice(extra);
    let run = odal_env(home.path(), &args, &[("ODAL_API_KEY", "odal_sk_test")]);
    let sent = received
        .recv_timeout(Duration::from_secs(5))
        .unwrap_or_else(|_| panic!("the node was never asked: {}", run.output()));
    assert_eq!(sent.path, "/vault/api/v1/api-keys");
    (
        run,
        serde_json::from_slice(&sent.body).expect("a JSON body"),
    )
}

#[test]
fn a_key_is_created_with_the_scope_asked_for() {
    for scope in ["read", "write", "admin"] {
        let (run, body) = create_key(&["--scope", scope]);

        assert_eq!(run.code, 0, "{scope}: {}", run.output());
        assert_eq!(body["scope"], scope, "{scope}: {body}");
        assert_eq!(body["name"], "ci");
        assert!(
            run.output().contains(scope),
            "the output should say which scope was minted: {}",
            run.output()
        );
    }
}

#[test]
fn a_key_created_without_a_scope_is_an_admin_key_and_the_request_says_so() {
    let (run, body) = create_key(&[]);

    assert_eq!(run.code, 0, "{}", run.output());
    assert_eq!(
        body["scope"], "admin",
        "the help names the default, so the request must not leave it to the node"
    );
}

#[test]
fn the_help_says_which_scope_the_default_creates() {
    let home = tempfile::TempDir::new().unwrap();
    let run = odal(home.path(), &["key", "create", "--help"]);

    assert_eq!(run.code, 0, "{}", run.output());
    let out = run.output();
    assert!(out.contains("--scope"), "{out}");
    assert!(out.contains("[default: admin]"), "{out}");
    for scope in ["read", "write", "admin"] {
        assert!(out.contains(scope), "{scope} missing from the help: {out}");
    }
}

#[test]
fn a_scope_the_node_does_not_know_is_refused_before_any_request() {
    let home = tempfile::TempDir::new().unwrap();
    let run = odal(home.path(), &["key", "create", "ci", "--scope", "root"]);

    assert_eq!(run.code, 2, "{}", run.output());
}
