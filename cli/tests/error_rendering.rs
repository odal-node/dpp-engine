//! One node error, rendered the same way by every command that meets it.
//!
//! The failure this pins: against the same node and the same HTTP 401,
//! `odal key list` printed a sentence while `odal stats` printed the raw
//! RFC 7807 body — `requestId`, `status` and `type` included. The shared
//! renderer already existed and fifty-nine call sites used it; one did not.
//!
//! No node is needed to test this. The behaviour under test is how the CLI
//! renders a problem body, so what it needs is a server that emits one, not a
//! node that means it.

mod helpers;
use helpers::{odal, problem_server};

use tempfile::TempDir;

const PROBLEM: &str = r#"{"type":"https://problems.odal-node.io/unauthorized","title":"Unauthorized","status":401,"detail":"Invalid or expired token.","requestId":"01a024b2-f555-7bb2-8d87-a5f33466315d"}"#;

/// Point a profile at `origin` so the CLI has somewhere to send its requests.
fn configured_home(origin: &str) -> TempDir {
    let home = TempDir::new().unwrap();
    let run = odal(
        home.path(),
        &["profile", "create", "stub", "--node-url", origin],
    );
    assert_eq!(run.code, 0, "{}", run.output());
    home
}

#[test]
fn every_command_renders_one_problem_body_the_same_way() {
    let origin = problem_server("401 Unauthorized", PROBLEM);
    let home = configured_home(&origin);

    for args in [
        vec!["stats"],
        vec!["key", "list"],
        vec!["operator", "show"],
        vec!["passport", "list"],
    ] {
        let run = odal(home.path(), &args);
        let output = run.output();
        let command = args.join(" ");

        assert!(
            output.contains("Unauthorized — Invalid or expired token."),
            "`odal {command}` did not render the problem as a sentence:\n{output}"
        );
        // The three fields that made one of these a JSON dump. A caller reading
        // an error message has no use for them, and their presence is the
        // signature of a call site formatting the response itself.
        for leaked in ["requestId", r#""status""#, "problems.odal-node.io"] {
            assert!(
                !output.contains(leaked),
                "`odal {command}` leaked `{leaked}` from the raw body:\n{output}"
            );
        }
        assert_eq!(run.code, 1, "`odal {command}` must fail:\n{output}");
    }
}

/// A body that is not a problem document must not be mistaken for one. The
/// fallback names the status and shows what arrived, rather than inventing a
/// title the server never sent.
#[test]
fn a_non_problem_body_falls_back_to_the_raw_response() {
    let origin = problem_server("502 Bad Gateway", "<html>502 Bad Gateway</html>");
    let home = configured_home(&origin);

    let run = odal(home.path(), &["key", "list"]);
    let output = run.output();
    assert!(
        output.contains("HTTP 502"),
        "the fallback must name the status:\n{output}"
    );
    assert!(
        output.contains("502 Bad Gateway"),
        "the fallback must show what arrived:\n{output}"
    );
}
