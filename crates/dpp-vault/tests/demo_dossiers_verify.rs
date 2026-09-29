//! The shipped demo dossiers must still get the verdict their README promises.
//!
//! `ops/demo/dossiers/` exists to demonstrate the verifier: four dossiers that
//! verify, four tampered in different ways, two that are not dossiers at all.
//! Nothing checked them, and when the format moved on (`manifest.coreVersion`
//! became required, the transfer acceptance got its own signed payload) every
//! one of them was refused as malformed — including the four meant to verify —
//! and the first person to find out would have been whoever ran the demo.
//!
//! Two things are held to what `verify_dossier_json` says today:
//!
//! - `expected.json`, the verdict `generate_demo_dossiers` recorded for each
//!   file, compared whole. Error text included: `09` must be refused *for its
//!   unknown field*, and an exit code alone cannot tell that from a file
//!   refused for a field it lacks — which is how the old corpus failed.
//! - The README table's `Expected` exit code and `Fails` column, which are what
//!   a person running the demo reads.
//!
//! And one thing the verifier cannot see: that each dossier is one a node could
//! have exported, its views and end-of-life record being what the assembler
//! reads out of its own audit trail.
//!
//! Pure file-and-verify: no Docker, no HTTP, so it runs in the fast gate.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use dpp_types::evidence::{DossierV1, SignedKeyOrder};
use dpp_vault::domain::service::{declared_eol, published_views};
use dpp_vault::domain::verify::verify_dossier_json;
use serde_json::{Value, json};

const REGENERATE: &str = "regenerate with `cargo run -p dpp-vault --example \
     generate_demo_dossiers -- ops/demo/dossiers` from the repository root, and if a \
     verdict changed on purpose, update the README table to match";

fn dossier_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../ops/demo/dossiers")
}

/// Every demo input in the directory: all of it but the README and the
/// verdicts file.
fn dossier_files() -> BTreeSet<String> {
    let dir = dossier_dir();
    let files: BTreeSet<String> = fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("read {}: {e}", dir.display()))
        .filter_map(Result::ok)
        .filter(|e| e.path().is_file())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|name| name != "README.md" && name != "expected.json")
        .collect();
    // A loop over an empty directory passes.
    assert!(
        files.len() >= 10,
        "expected the ten demo dossiers in {}, found {} — if they moved, move this test \
         with them",
        dir.display(),
        files.len()
    );
    files
}

fn expected_verdicts() -> BTreeMap<String, Value> {
    let path = dossier_dir().join("expected.json");
    let raw = fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_str(&raw).unwrap_or_else(|e| panic!("{} is not JSON: {e}", path.display()))
}

/// One row of the README's dataset table.
struct ReadmeRow {
    exit: u32,
    fails: BTreeSet<String>,
}

/// The README's table rows, keyed by file name.
///
/// A row is `| # | \`file\` | exit N, … | \`check\`, \`check\` or — | purpose |`.
/// Anything else, the header and separator included, is not a row; a dossier
/// whose row fails to parse then shows up as having none.
fn readme_rows() -> BTreeMap<String, ReadmeRow> {
    let path = dossier_dir().join("README.md");
    let readme =
        fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    readme
        .lines()
        .filter_map(|line| {
            let inner = line.trim().strip_prefix('|')?.strip_suffix('|')?;
            let cells: Vec<&str> = inner.split('|').map(str::trim).collect();
            let [_, file, expected, fails, _] = cells.as_slice() else {
                return None;
            };
            let file = file.strip_prefix('`')?.strip_suffix('`')?;
            let exit = expected
                .strip_prefix("exit ")?
                .chars()
                .next()?
                .to_digit(10)?;
            let fails = fails
                .split(',')
                .map(|f| f.trim().trim_matches('`'))
                .filter(|f| !f.is_empty() && *f != "—")
                .map(String::from)
                .collect();
            Some((file.to_owned(), ReadmeRow { exit, fails }))
        })
        .collect()
}

/// What the generator records: the report's checks and the exit code
/// `odal verify` turns it into, or exit 2 and the reason for a file that is not
/// a dossier.
fn verdict(file: &str) -> Value {
    let path = dossier_dir().join(file);
    let bytes = fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    match verify_dossier_json(&bytes, None) {
        Ok(report) => json!({ "exit": report.exit_code(), "checks": report.checks }),
        Err(e) => json!({ "exit": 2, "error": e.to_string() }),
    }
}

fn failing_checks(verdict: &Value) -> BTreeSet<String> {
    verdict["checks"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|c| c["status"] == "fail")
        .filter_map(|c| c["name"].as_str().map(String::from))
        .collect()
}

#[test]
fn every_dossier_has_a_recorded_verdict_and_a_readme_row() {
    let files = dossier_files();
    let recorded: BTreeSet<String> = expected_verdicts().into_keys().collect();
    let documented: BTreeSet<String> = readme_rows().into_keys().collect();
    assert_eq!(
        files, recorded,
        "the dossier files and expected.json's entries differ — {REGENERATE}"
    );
    assert_eq!(
        files, documented,
        "the dossier files and the README table's rows differ — every file needs a row"
    );
}

#[test]
fn every_dossier_gets_its_recorded_verdict() {
    let expected = expected_verdicts();
    let stale: Vec<String> = dossier_files()
        .into_iter()
        .filter_map(|file| {
            let got = verdict(&file);
            let want = expected.get(&file).unwrap_or(&Value::Null);
            (got != *want).then(|| format!("{file}\n  recorded: {want}\n  now:      {got}"))
        })
        .collect();
    assert!(
        stale.is_empty(),
        "the verifier no longer agrees with expected.json — {REGENERATE}:\n{}",
        stale.join("\n")
    );
}

#[test]
fn every_dossier_gets_the_verdict_its_readme_row_promises() {
    let rows = readme_rows();
    let wrong: Vec<String> = dossier_files()
        .into_iter()
        .filter_map(|file| {
            let row = rows.get(&file)?;
            let got = verdict(&file);
            let exit = got["exit"].as_u64().expect("exit code");
            let fails = failing_checks(&got);
            (exit != u64::from(row.exit) || fails != row.fails).then(|| {
                format!(
                    "{file}: README says exit {} failing {:?}; the verifier says exit {exit} \
                     failing {fails:?}",
                    row.exit, row.fails
                )
            })
        })
        .collect();
    assert!(
        wrong.is_empty(),
        "the README's table no longer describes the dossiers:\n{}",
        wrong.join("\n")
    );
}

/// Every dossier is one a node could have exported: its signed views are the
/// payloads its last `published` entry recorded, and its `eolEvent` is its
/// `deactivated` entry's metadata — [`published_views`] and [`declared_eol`],
/// the lookups the assembler builds a real dossier with.
///
/// The verifier checks neither, and does not need to: the manifest signature
/// binds every member either way. So the corpus went on verifying with a
/// history no node writes — `publish` for `published`, `eol` for
/// `deactivated`, an `eolEvent` no entry held — until someone set it beside a
/// live export.
#[test]
fn every_dossier_is_one_a_node_could_have_assembled() {
    let expected = expected_verdicts();
    let wrong: Vec<String> = dossier_files()
        .into_iter()
        // 09 and 10 are refused before a history exists to read.
        .filter(|file| expected.get(file).is_none_or(|v| v["exit"] != 2))
        .filter_map(|file| {
            let bytes = fs::read(dossier_dir().join(&file)).expect("read dossier");
            let d: DossierV1 = serde_json::from_slice(&bytes)
                .unwrap_or_else(|e| panic!("{file} verifies, so it must parse: {e}"));
            let mut faults = Vec::new();
            match published_views(&d.audit_entries) {
                None => faults.push("no `published` entry carries the signed views".to_owned()),
                Some((full, public)) => {
                    if full != d.full_view.payload {
                        faults.push(
                            "fullView is not what the last `published` entry recorded".into(),
                        );
                    }
                    if public != d.public_view.payload {
                        faults.push(
                            "publicView is not what the last `published` entry recorded".into(),
                        );
                    }
                }
            }
            if declared_eol(&d.audit_entries) != d.eol_event {
                faults.push("eolEvent is not the `deactivated` entry's metadata".into());
            }
            (!faults.is_empty()).then(|| format!("{file}: {}", faults.join("; ")))
        })
        .collect();
    assert!(
        wrong.is_empty(),
        "a node could not have exported these — {REGENERATE}:\n{}",
        wrong.join("\n")
    );
}

/// The corpus is only a canonicalisation vector while it holds a pair of keys
/// that UTF-16 order and code point order put the other way round. `😀` is the
/// surrogate pair `0xD83D 0xDE00`; `\u{FF21}` is the single unit `0xFF21`. The
/// signed bytes must have the emoji first, which is what a verifier sorting by
/// code point or by UTF-8 bytes gets wrong.
#[test]
fn the_signed_full_view_orders_keys_by_utf16_code_unit() {
    use base64::Engine as _;

    let path = dossier_dir().join("04-valid-full-lifecycle.json");
    let doc: Value = serde_json::from_slice(&fs::read(&path).expect("read the dossier"))
        .expect("the dossier is JSON");
    let jws = doc["fullView"]["jws"].as_str().expect("fullView.jws");
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(jws.split('.').nth(1).expect("a JWS payload segment"))
        .expect("the payload segment is base64url");
    let payload = String::from_utf8(payload).expect("the signed payload is UTF-8");

    let emoji = payload.find("\"😀\":5").expect("the emoji key is signed");
    let fullwidth = payload
        .find("\"\u{FF21}\":6")
        .expect("the fullwidth key is signed");
    assert!(
        emoji < fullwidth,
        "keys must be ordered by UTF-16 code unit, so 😀 (0xD83D) comes before \u{FF21} (0xFF21)"
    );
}

/// The readable copy of each signed view holds exactly what its JWS signed:
/// written compactly in signed key order, it is the signed bytes. This checks
/// content, not the order the file lists it in; the next test holds the file to
/// that order. Together they mean the payload a reader sees beside a signature
/// is the one that was signed, key for key and in the same order.
#[test]
fn each_readable_view_is_its_signed_payload() {
    use base64::Engine as _;

    for file in dossier_files() {
        let text = fs::read_to_string(dossier_dir().join(&file)).expect("read the dossier");
        let Ok(doc) = serde_json::from_str::<Value>(&text) else {
            continue;
        };
        for view in ["fullView", "publicView"] {
            let jws = doc[view]["jws"].as_str().expect("a JWS");
            let signed = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(jws.split('.').nth(1).expect("a JWS payload segment"))
                .expect("the payload segment is base64url");
            let signed = String::from_utf8(signed).expect("the signed payload is UTF-8");
            let readable = serde_json::to_string(&SignedKeyOrder(&doc[view]["payload"]))
                .expect("serialise the readable copy");
            assert_eq!(
                readable, signed,
                "{file}: the readable {view} payload is not the bytes its JWS signed; {REGENERATE}"
            );
        }
    }
}

/// Every file is exactly what the generator writes, and the generator writes
/// every object in signed key order. A file regenerated by a generator that
/// lost that, or edited by hand in plain `serde_json` order, fails here.
#[test]
fn every_dossier_file_lists_its_keys_in_signed_order() {
    for file in dossier_files() {
        let text = fs::read_to_string(dossier_dir().join(&file)).expect("read the dossier");
        let Ok(doc) = serde_json::from_str::<Value>(&text) else {
            continue;
        };
        let rewritten =
            serde_json::to_string_pretty(&SignedKeyOrder(&doc)).expect("serialise the dossier");
        assert!(
            rewritten == text,
            "{file} is not written in signed key order; {REGENERATE}"
        );
    }
}
