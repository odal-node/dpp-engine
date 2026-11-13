//! A dossier file the CLI wrote is one the CLI can verify.
//!
//! `odal passport evidence -o d.json` writes the record the node stored: the
//! dossier, wrapped in the `id`, `passportId`, `docHash`, `actor` and
//! `createdAt` that persisting it added. The node's verify route takes the
//! dossier alone and refuses the record's other fields, so `odal verify d.json`
//! exited 2 on a file this same CLI had just written.

mod helpers;
use helpers::{home_with_node, odal_env, recording_server};

use std::time::Duration;

const REPORT: &str = r#"{"trustAnchorNote":"test","checks":[]}"#;

const DOSSIER: &str = r#"{"version":1,"passportId":"0198f000-0000-7000-8000-000000000001","generatedAt":"2026-11-12T20:00:00Z"}"#;

fn the_stored_record() -> String {
    format!(
        r#"{{"id":"0198f000-0000-7000-8000-0000000000aa","passportId":"0198f000-0000-7000-8000-000000000001","actor":"admin","createdAt":"2026-11-12T20:00:01Z","docHash":"abc123","dossier":{DOSSIER}}}"#
    )
}

/// Verify a file holding `contents`, and return what the node was sent.
fn verify_file(contents: &str) -> (helpers::Run, helpers::Recorded) {
    let (origin, received) = recording_server("200 OK", REPORT);
    let home = home_with_node(&origin);
    std::fs::write(home.path().join("d.json"), contents).unwrap();
    let run = odal_env(
        home.path(),
        &["verify", "d.json"],
        &[("ODAL_API_KEY", "odal_sk_test")],
    );
    let sent = received
        .recv_timeout(Duration::from_secs(5))
        .unwrap_or_else(|_| panic!("the node was never asked: {}", run.output()));
    (run, sent)
}

#[test]
fn a_file_holding_the_stored_record_is_verified_as_the_dossier_it_holds() {
    let (run, sent) = verify_file(&the_stored_record());

    assert_eq!(run.code, 0, "{}", run.output());
    assert_eq!(sent.method, "POST");
    assert_eq!(sent.path, "/vault/api/v1/evidence/verify");
    let sent_body: serde_json::Value = serde_json::from_slice(&sent.body).unwrap();
    let dossier: serde_json::Value = serde_json::from_str(DOSSIER).unwrap();
    assert_eq!(
        sent_body, dossier,
        "the node takes the dossier, not the record around it"
    );
}

#[test]
fn a_file_holding_the_dossier_itself_goes_up_as_it_is() {
    let (run, sent) = verify_file(DOSSIER);

    assert_eq!(run.code, 0, "{}", run.output());
    assert_eq!(sent.body, DOSSIER.as_bytes());
}
