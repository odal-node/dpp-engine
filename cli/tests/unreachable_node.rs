//! A node that does not answer is reported one way, by every command.
//!
//! `odal bootstrap` said "could not reach the node", `odal whoami` printed the
//! transport library's `error sending request for url` and its cause chain, and
//! `odal status` printed a bare "unreachable". Each also pointed at `odal up`,
//! which starts a local stack, whether or not the profile named a local node.

mod helpers;
use helpers::{closed_origin, home_with_node, odal_env};

const KEY: [(&str, &str); 1] = [("ODAL_API_KEY", "odal_sk_test")];

#[test]
fn an_unreachable_node_is_one_sentence_and_not_a_transport_dump() {
    let origin = closed_origin();
    let home = home_with_node(&origin);

    let run = odal_env(home.path(), &["whoami"], &KEY);

    assert_ne!(run.code, 0, "{}", run.output());
    let out = run.output();
    assert!(
        out.contains(&format!("could not reach the node at {origin}")),
        "{out}"
    );
    assert!(!out.contains("error sending request"), "{out}");
    assert!(!out.contains("Caused by"), "{out}");
}

#[test]
fn bootstrap_and_whoami_say_the_same_thing_about_a_node_that_is_down() {
    let origin = closed_origin();
    let home = home_with_node(&origin);
    let sentence = format!("could not reach the node at {origin}");

    let whoami = odal_env(home.path(), &["whoami"], &KEY);
    let bootstrap = odal_env(
        home.path(),
        &["bootstrap"],
        &[("ADMIN_USERNAME", "admin"), ("ADMIN_PASSWORD", "pw")],
    );

    assert!(whoami.output().contains(&sentence), "{}", whoami.output());
    assert!(
        bootstrap.output().contains(&sentence),
        "{}",
        bootstrap.output()
    );
    assert!(
        !bootstrap.output().contains("error sending request"),
        "{}",
        bootstrap.output()
    );
}

#[test]
fn a_local_node_that_is_down_is_pointed_at_odal_up() {
    let home = home_with_node(&closed_origin());

    let run = odal_env(home.path(), &["whoami"], &KEY);

    assert!(run.output().contains("odal up"), "{}", run.output());
}

/// `.invalid` is a reserved top-level domain that never resolves, so this is a
/// remote host that cannot be found without depending on what the network is
/// doing.
#[test]
fn a_remote_node_that_is_unreachable_is_not_told_to_start_a_local_stack() {
    let home = home_with_node("https://node.example.invalid");

    let run = odal_env(home.path(), &["whoami"], &KEY);

    assert_ne!(run.code, 0, "{}", run.output());
    let out = run.output();
    assert!(
        out.contains("could not reach the node at https://node.example.invalid"),
        "{out}"
    );
    assert!(
        !out.contains("odal up"),
        "`odal up` starts a local stack, which this profile does not use: {out}"
    );
}

#[test]
fn status_says_why_a_service_did_not_answer() {
    let home = home_with_node(&closed_origin());

    let run = odal_env(home.path(), &["status"], &KEY);

    assert_ne!(run.code, 0, "{}", run.output());
    assert!(
        run.output().contains("connection refused"),
        "a refused connection should read as one: {}",
        run.output()
    );
}
