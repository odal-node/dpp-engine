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
//! Pure file-and-verify: no Docker, no HTTP, so it runs in the fast gate.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

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
