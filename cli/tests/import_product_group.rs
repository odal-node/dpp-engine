//! `odal passport import` takes the product group from a flag as well as from
//! the file.
//!
//! `odal template textile -o t.csv` writes a header with no `productGroup`
//! column, and import then refused the file it had just been given a template
//! for. The integrator picks the product group from the route, so the CLI only
//! needs to be told which one.

mod helpers;
use helpers::{home_with_node, odal_env, recording_server};

use std::time::Duration;

const SUMMARY: &str = r#"{"successCount":1,"errorCount":0,"errors":[]}"#;

/// A CSV as the template serves it: no product group column.
const TEMPLATE_ROWS: &str = "productName,gtin\nWidget,09506000134352\n";

fn import(csv: &str, extra: &[&str]) -> (helpers::Run, Option<helpers::Recorded>) {
    let (origin, received) = recording_server("200 OK", SUMMARY);
    let home = home_with_node(&origin);
    std::fs::write(home.path().join("t.csv"), csv).unwrap();
    let mut args = vec!["passport", "import", "t.csv"];
    args.extend_from_slice(extra);
    let run = odal_env(home.path(), &args, &[("ODAL_API_KEY", "odal_sk_test")]);
    (run, received.recv_timeout(Duration::from_millis(500)).ok())
}

#[test]
fn a_template_is_imported_under_the_product_group_the_flag_names() {
    let (run, sent) = import(TEMPLATE_ROWS, &["--product-group", "textile"]);

    assert_eq!(run.code, 0, "{}", run.output());
    let sent = sent.expect("the integrator was never asked");
    assert_eq!(sent.method, "POST");
    assert_eq!(sent.path, "/integrator/api/v1/import/textile");
}

#[test]
fn the_flag_is_read_the_way_the_column_is() {
    let (run, sent) = import(TEMPLATE_ROWS, &["--product-group", "Textile"]);

    assert_eq!(run.code, 0, "{}", run.output());
    assert_eq!(
        sent.expect("the integrator was never asked").path,
        "/integrator/api/v1/import/textile"
    );
}

#[test]
fn a_file_with_no_product_group_anywhere_is_told_about_the_flag() {
    let (run, sent) = import(TEMPLATE_ROWS, &[]);

    assert_ne!(run.code, 0, "{}", run.output());
    assert!(
        run.output().contains("--product-group"),
        "the refusal should name the flag: {}",
        run.output()
    );
    assert!(sent.is_none(), "nothing should have been uploaded");
}

/// Each record in a JSON file states its own product group, so a flag has
/// nothing to decide. Refused, not ignored: ignoring it would look like it had
/// been honoured.
#[test]
fn a_json_file_refuses_the_flag_instead_of_ignoring_it() {
    let (origin, received) = recording_server("201 Created", r#"{"id":"x"}"#);
    let home = home_with_node(&origin);
    std::fs::write(home.path().join("p.json"), r#"{"productName":"Widget"}"#).unwrap();

    let run = odal_env(
        home.path(),
        &["passport", "import", "p.json", "--product-group", "textile"],
        &[("ODAL_API_KEY", "odal_sk_test")],
    );

    assert_ne!(run.code, 0, "{}", run.output());
    assert!(run.output().contains("--product-group"), "{}", run.output());
    assert!(received.recv_timeout(Duration::from_millis(500)).is_err());
}

#[test]
fn a_flag_that_contradicts_the_files_own_column_is_refused() {
    let (run, sent) = import(
        "productName,productGroup,gtin\nCell,battery,09506000134352\n",
        &["--product-group", "textile"],
    );

    assert_ne!(run.code, 0, "{}", run.output());
    let out = run.output();
    assert!(out.contains("battery") && out.contains("textile"), "{out}");
    assert!(sent.is_none(), "nothing should have been uploaded");
}
