//! Retention-guard → core drift guard.
//!
//! Pure filesystem check — no Docker/Postgres required, so it runs in the fast
//! `cargo nextest run --workspace` gate.
//!
//! The `odal.passport_retention_guard` trigger decides which passport keys may
//! change once `retention_locked` is set. That is a domain statement, and core
//! owns it as [`dpp_domain::RETENTION_MUTABLE_FIELDS`]. SQL cannot read a Rust
//! constant, so the trigger necessarily restates the list — this test is what
//! makes that restatement a *checked copy* rather than a second source of truth.
//!
//! # Why this is needed
//!
//! The array has been re-typed in full **five times** (`0004`, `0011`, `0018`,
//! `0027`, `0028`), once for each field that became mutable after publish —
//! `publicJwsSignature`, `lintResult`, `disclosureSignatures`, `seal`. Nothing
//! signalled when the next one was due. A new post-publish-mutable field in core
//! simply failed at runtime, on a published record, with `ODAL_RETENTION` — the
//! first time anything tried to write it. Sealing is exactly that path, and
//! `seal` reached `mutable_keys` only in the same migration that introduced the
//! seal outbox.
//!
//! Now: add a field to `RETENTION_MUTABLE_FIELDS` and this test fails until a
//! migration redefines the trigger to match.

use std::fs;
use std::path::Path;

/// Extract the `mutable_keys` array literal from the newest migration that
/// defines one. `CREATE OR REPLACE FUNCTION` means the highest-numbered file
/// wins at apply time, so that is the definition in force.
fn mutable_keys_in_force() -> (String, Vec<String>) {
    let migrations_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../ops/pg");
    let mut files: Vec<_> = fs::read_dir(&migrations_dir)
        .expect("read ops/pg")
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "sql"))
        .collect();
    files.sort();

    let newest = files
        .iter()
        .rev()
        .find_map(|p| {
            let body = fs::read_to_string(p).ok()?;
            body.contains("mutable_keys").then_some((p.clone(), body))
        })
        .expect("no migration defines mutable_keys — has the retention guard been removed?");

    let (path, body) = newest;
    let start = body
        .find("mutable_keys")
        .and_then(|i| body[i..].find("ARRAY[").map(|j| i + j + "ARRAY[".len()))
        .expect("mutable_keys is not followed by an ARRAY[ literal");
    let end = start
        + body[start..]
            .find(']')
            .expect("unterminated ARRAY[ literal in the retention guard");

    let keys = body[start..end]
        .split(',')
        .map(|s| s.trim().trim_matches('\'').trim().to_owned())
        .filter(|s| !s.is_empty())
        .collect();

    (
        path.file_name().unwrap().to_string_lossy().into_owned(),
        keys,
    )
}

/// The trigger in force must permit exactly what core says is mutable.
#[test]
fn retention_trigger_matches_core() {
    let (file, sql_keys) = mutable_keys_in_force();

    let mut expected: Vec<&str> = dpp_domain::RETENTION_MUTABLE_FIELDS.to_vec();
    let mut actual: Vec<&str> = sql_keys.iter().map(String::as_str).collect();
    expected.sort_unstable();
    actual.sort_unstable();

    let missing: Vec<&&str> = expected.iter().filter(|k| !actual.contains(k)).collect();
    let extra: Vec<&&str> = actual.iter().filter(|k| !expected.contains(k)).collect();

    assert!(
        missing.is_empty(),
        "{file}'s mutable_keys is missing {missing:?}, which dpp-core says may change after \
         retention lock.\n\nWriting one of those on a published passport will fail at runtime \
         with ODAL_RETENTION. Add a migration that redefines odal.passport_retention_guard with \
         the full list."
    );
    assert!(
        extra.is_empty(),
        "{file}'s mutable_keys permits {extra:?}, which dpp-core does not list as mutable after \
         retention lock.\n\nEither the key is stale (a renamed or removed field, in which case \
         the trigger is silently allowing nothing) or core's list is wrong. The trigger must not \
         be the more permissive of the two."
    );
}

/// The array must not carry duplicates — a repeated key is the signature of a
/// hand-edit that appended instead of replacing, which is how this list grew.
#[test]
fn retention_trigger_keys_are_unique() {
    let (file, keys) = mutable_keys_in_force();
    let mut seen = std::collections::BTreeSet::new();
    for key in &keys {
        assert!(
            seen.insert(key),
            "{file} lists `{key}` twice in mutable_keys"
        );
    }
}
