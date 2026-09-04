//! Passport JSON key literals → core drift guard.
//!
//! Pure filesystem check — no Docker/Postgres required, so it runs in the fast
//! `cargo nextest run --workspace` gate.
//!
//! Every `doc->'x'` / `doc->>'x'` in the DAL's SQL, and in the migrations'
//! index expressions, addresses a `Passport` JSON key by a **string literal**.
//! A literal has no relationship to the field it names: rename the field in
//! dpp-core and the query still parses, still runs, and silently returns NULL
//! for every row. No error, no failing test, no log line — the column just
//! becomes empty.
//!
//! The same document is addressed two ways, and both are scanned. On read it is
//! the `doc` column; on write it is the **bound JSONB parameter** (`$2->>'x'`),
//! which is how the INSERT and UPDATE mirror a handful of keys into their own
//! scalar columns. Keying the scan on `doc` alone left every one of those write
//! mirrors unguarded — a rename in core would have made the INSERT write NULL
//! into `product_group`, `published_at` or `supersedes_id`, which is precisely
//! the silent failure described above, on the write side where it also destroys
//! the row rather than merely misreading it.
//!
//! SQL cannot read a Rust constant, so these literals cannot be replaced by
//! consumption. What they *can* do is check themselves against the vocabulary
//! core publishes as [`dpp_domain::PASSPORT_WIRE_KEYS`], which core proves
//! complete against a fully-populated `Passport`. That makes the literals a
//! checked copy rather than an independent guess.
//!
//! Nested paths (`doc->'productGroupData'->>'gtin'`) are checked at the first hop
//! only: `productGroupData` is a `Passport` key, `gtin` belongs to the product group payload
//! and is versioned through the lens chain, which is a different contract with
//! its own machinery.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Migrations whose key literals are **history**, paired with the migration that
/// replaced them.
///
/// The migration set is append-only — `sqlx::migrate!` checksums every file, so
/// editing an applied one makes a node that has already run it refuse to boot.
/// A migration that built an index over a key that has since been renamed
/// therefore keeps naming the old key forever, and nothing can be done to the
/// file about it.
///
/// Exempting the **file**, never the key, is what keeps this honest: the old
/// name stays a failure everywhere else, so a live query that still uses it is
/// caught exactly as before. Each row must name its replacement, so the claim
/// "this is superseded" is checkable rather than asserted — and a row whose
/// replacement is missing is a row that should not be here.
const SUPERSEDED_MIGRATIONS: &[(&str, &str)] = &[(
    "0019_passport_identity_index.sql",
    "0032_product_group_rename.sql — the identity index is dropped and rebuilt \
     there over `productGroupData`, after the envelope key was renamed from \
     `sectorData`.",
)];

/// True when the text to the left of a `->`/`->>` is the passport document
/// itself — the `doc` column, or a bind parameter carrying it.
///
/// Anything else is a deeper hop (`…->'productGroupData'->>'gtin'`), whose keys
/// belong to the product group payload and travel through the lens chain, which
/// is a different contract with its own machinery.
fn addresses_the_document(before: &str) -> bool {
    let before = before.trim_end();
    // `$1`, `$2`, … — the bound JSONB document on the write paths.
    let without_digits = before.trim_end_matches(|c: char| c.is_ascii_digit());
    if without_digits.len() < before.len() && without_digits.ends_with('$') {
        return true;
    }
    // The `doc` column, as a whole word — `mydoc->` is something else.
    before.strip_suffix("doc").is_some_and(|head| {
        !head
            .chars()
            .next_back()
            .is_some_and(|c| c.is_alphanumeric() || c == '_')
    })
}

/// Every first-hop key literal found under a directory, mapped to the files it
/// appears in.
fn key_literals_under(dir: &Path, extension: &str) -> BTreeMap<String, Vec<String>> {
    let mut found: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut stack = vec![dir.to_path_buf()];
    let mut files: Vec<PathBuf> = Vec::new();

    while let Some(path) = stack.pop() {
        let Ok(entries) = fs::read_dir(&path) else {
            continue;
        };
        for entry in entries.filter_map(Result::ok) {
            let p = entry.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().is_some_and(|x| x == extension) {
                files.push(p);
            }
        }
    }

    for file in files {
        let Ok(body) = fs::read_to_string(&file) else {
            continue;
        };
        let name = file
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned();

        // Scan for `->` / `->>` applied directly to the passport document,
        // followed by a single-quoted key.
        let mut cursor = 0usize;
        while let Some(at) = body[cursor..].find("->") {
            let arrow = cursor + at;
            cursor = arrow + "->".len();
            if body[cursor..].starts_with('>') {
                cursor += 1;
            }
            if !addresses_the_document(&body[..arrow]) {
                continue;
            }
            let after_arrow = &body[cursor..];
            let Some(open) = after_arrow.find('\'') else {
                break;
            };
            // Only whitespace may sit between the arrow and the literal;
            // anything else means this was not a direct key access.
            if !after_arrow[..open].trim().is_empty() {
                continue;
            }
            let after = &after_arrow[open + 1..];
            let Some(close) = after.find('\'') else { break };
            let key = after[..close].to_owned();
            if !key.is_empty() {
                found.entry(key).or_default().push(name.clone());
            }
            cursor += open + 1 + close;
        }
    }
    found
}

#[test]
fn every_passport_key_literal_is_a_real_wire_key() {
    let dal_src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let migrations = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../ops/pg");

    let mut all = key_literals_under(&dal_src, "rs");
    for (key, files) in key_literals_under(&migrations, "sql") {
        let live: Vec<String> = files
            .into_iter()
            .filter(|f| !SUPERSEDED_MIGRATIONS.iter().any(|(name, _)| name == f))
            .collect();
        if !live.is_empty() {
            all.entry(key).or_default().extend(live);
        }
    }

    assert!(
        !all.is_empty(),
        "found no key literals at all — the scanner is matching nothing, \
         which is indistinguishable from a passing gate"
    );

    let unknown: Vec<String> = all
        .iter()
        .filter(|(key, _)| !dpp_domain::PASSPORT_WIRE_KEYS.contains(&key.as_str()))
        .map(|(key, files)| {
            let mut files = files.clone();
            files.sort();
            files.dedup();
            format!("  `{key}` in {}", files.join(", "))
        })
        .collect();

    assert!(
        unknown.is_empty(),
        "these SQL literals address passport JSON keys that `Passport` does not emit:\n{}\n\n\
         Each one silently returns NULL for every row. Either the field was renamed in dpp-core \
         and these were not, or the key never existed. Check against \
         `dpp_domain::PASSPORT_WIRE_KEYS`.",
        unknown.join("\n")
    );
}

/// Every superseded migration names a replacement that exists.
///
/// Without this, [`SUPERSEDED_MIGRATIONS`] is a list of files the gate has been
/// told to stop looking at, on nothing but the assertion that something else
/// covers them. A missing replacement means the exemption is hiding a live
/// defect rather than recording history.
#[test]
fn every_superseded_migration_names_a_replacement_that_exists() {
    let migrations = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../ops/pg");
    for (superseded, reason) in SUPERSEDED_MIGRATIONS {
        assert!(
            migrations.join(superseded).exists(),
            "{superseded} is exempted but does not exist"
        );
        let replacement = reason
            .split_whitespace()
            .next()
            .expect("a reason names its replacement first");
        assert!(
            migrations.join(replacement).exists(),
            "{superseded} claims to be superseded by {replacement}, which does not exist"
        );
    }
}
