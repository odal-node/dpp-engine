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

/// A TLS listener that answers the handshake with plain HTTP, so the client's
/// TLS library fails to read a handshake from it. Returns an `https` origin.
fn plain_http_answering_tls_origin() -> String {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind a port");
    let port = listener.local_addr().expect("local addr").port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf);
            let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
            let _ = stream.flush();
        }
    });
    format!("https://127.0.0.1:{port}")
}

/// The TLS library's own cause is kept, where it used to be replaced by the bare
/// "connection failed". Its wording here is "received corrupt message of type
/// InvalidContentType": it names no certificate, so it is not labelled as a TLS
/// failure, only shown.
#[test]
fn a_node_whose_tls_handshake_fails_keeps_the_cause() {
    let origin = plain_http_answering_tls_origin();
    let home = home_with_node(&origin);

    let run = odal_env(home.path(), &["whoami"], &KEY);

    assert_ne!(run.code, 0, "{}", run.output());
    let out = run.output();
    assert!(
        out.contains("received corrupt message of type InvalidContentType"),
        "the TLS cause should reach the operator: {out}"
    );
    assert!(
        !out.contains("(connection failed)."),
        "the cause was dropped: {out}"
    );
}
