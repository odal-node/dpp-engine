//! Which code may write to `odal.passport`, and why the list is a gate.
//!
//! ✅ COMPLIANCE-PIN: EN 18221:2026 clause 4.2 — every change to a passport is
//! archived.
//!
//! `repo_passport.rs` archives the stored record in the transaction of every
//! change it writes, so a change made through its statements cannot skip the
//! archive. That holds for exactly as long as those statements are the only way
//! a passport changes, and it is not an argument the file can make about itself:
//! a new `sqlx::query` in a new module writing `odal.passport` directly would
//! change a passport with no version taken, and nothing would fail.
//!
//! So two things are checked here by walking the DAL's own source: which files
//! write the table, and that every `UPDATE` in `repo_passport.rs` archives first.
//! Adding a writer is then a decision somebody has to record, in this file, next
//! to the reason the existing exception is allowed.
//!
//! # 🚨 There is an exception
//!
//! `PgSealOutboxRepo::mark_sealed` sets `doc->seal` with `jsonb_set`, in the
//! same transaction that closes the outbox row, and archives nothing. An earlier
//! statement of the rule said *"every mutation in this workspace goes through
//! `PassportRepository`"*, and that was false when it was written.
//!
//! **That write is correctly outside the archive**, which is why this is a
//! documentation fix and not a defect:
//!
//! - A seal is an eIDAS attestation **over the passport's published signature**,
//!   added after publication. Every attribute a reader relies on is identical
//!   before and after it lands, so a version taken either side of it would differ only
//!   in a field that is not passport content. Clause 4.2 archives changes to the
//!   passport; this does not change the passport.
//! - It lands on a **published, retention-locked** record whose content is
//!   already frozen — there is no product change to preserve.
//! - Routing it through the port would mean a full `Passport` round-trip, which
//!   `mark_sealed` deliberately avoids: re-serialising a record read moments
//!   earlier would clobber any concurrent change to a mutable field, and the
//!   seal write is one `jsonb_set` precisely so it cannot.
//!
//! The honest statement is therefore the narrower one: every change to passport
//! **content** goes through `repo_passport.rs`, and is archived there.

use std::collections::BTreeSet;
use std::path::Path;

/// Files permitted to write the `odal.passport` table, and why.
///
/// Keyed by file name rather than path because the DAL is flat under `src/pg/`.
const ALLOWED_WRITERS: &[(&str, &str)] = &[
    (
        "repo_passport.rs",
        "the `PassportRepository` implementation itself and the in-transaction \
         statements `PgStateChangeLog` and the registry outbox use. Each `UPDATE` \
         archives the stored record in its own transaction first, which \
         `every_update_in_the_repository_archives_first` holds",
    ),
    (
        "repo_seal.rs",
        "`mark_sealed` sets `doc->seal` by key, in the transaction that closes the \
         outbox row. An attestation over an already-published signature, not a change \
         to passport content — see this file's header",
    ),
];

/// A write to the passport table, in SQL this repository actually writes.
///
/// Matched on the statement rather than the table name alone: the table is named
/// in every `SELECT` in the DAL, and a reader is not a writer.
fn writes_to_passport(source: &str) -> bool {
    // `odal.passport p SET` covers the aliased `UPDATE ... FROM` form.
    let markers = [
        "UPDATE odal.passport SET",
        "UPDATE odal.passport p SET",
        "INSERT INTO odal.passport\n",
        "INSERT INTO odal.passport ",
        "DELETE FROM odal.passport ",
        "DELETE FROM odal.passport\n",
    ];
    markers.iter().any(|m| source.contains(m))
}

/// Every file that writes a passport is one somebody decided may.
///
/// 🚨 If this fails, the question is **not** "how do I add the file to the
/// list". It is: does that write change passport content, and if so, why is it
/// not going through `repo_passport.rs`, where the EN 18221 clause 4.2 archive is
/// taken? A write that changes content and skips it is a version that is never
/// taken, and nothing else in this workspace would notice.
#[test]
fn only_the_known_writers_touch_the_passport_table() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/pg");
    let mut found: BTreeSet<String> = BTreeSet::new();

    for entry in std::fs::read_dir(&dir).expect("the DAL's pg module is readable") {
        let path = entry.expect("a directory entry").path();
        if path.extension().is_none_or(|e| e != "rs") {
            continue;
        }
        let source = std::fs::read_to_string(&path).expect("a source file is readable");
        if writes_to_passport(&source) {
            found.insert(
                path.file_name()
                    .expect("a file has a name")
                    .to_string_lossy()
                    .into_owned(),
            );
        }
    }

    let allowed: BTreeSet<String> = ALLOWED_WRITERS
        .iter()
        .map(|(f, _)| (*f).to_owned())
        .collect();

    let unexpected: Vec<_> = found.difference(&allowed).cloned().collect();
    assert!(
        unexpected.is_empty(),
        "these files write to `odal.passport` and are not in ALLOWED_WRITERS: {unexpected:?}\n\
         \n\
         Before adding one: does the write change passport content? If it does, it belongs \
         in `repo_passport.rs`, whose writes archive the record they replace (EN 18221 \
         clause 4.2). A content change that skips them is a version that is never taken, \
         and nothing else here would notice."
    );

    let vanished: Vec<_> = allowed.difference(&found).cloned().collect();
    assert!(
        vanished.is_empty(),
        "these files are listed as passport writers and no longer write one: {vanished:?}. \
         Drop them from ALLOWED_WRITERS — a stale entry silently licenses a future write."
    );
}

/// The gate can actually tell a writer from a reader.
///
/// Without this the test above would pass on a repository where nothing matched
/// at all, which is the failure mode of every source scan: an expression that
/// finds nothing agrees with an allow-list that expects nothing.
#[test]
fn the_scan_recognises_a_write_and_ignores_a_read() {
    assert!(writes_to_passport(
        "UPDATE odal.passport SET doc = $2 WHERE id = $1"
    ));
    assert!(writes_to_passport(
        "UPDATE odal.passport p SET doc = jsonb_set(p.doc, '{seal}', $2, true)"
    ));
    assert!(writes_to_passport(
        "DELETE FROM odal.passport WHERE id = $1"
    ));
    assert!(writes_to_passport("INSERT INTO odal.passport (id, doc)"));

    assert!(
        !writes_to_passport("SELECT doc FROM odal.passport WHERE id = $1"),
        "a read is not a write, or every file in the DAL would be a writer"
    );
    assert!(
        !writes_to_passport("UPDATE odal.passport_audit SET actor = $1"),
        "and a different table is a different table"
    );
    assert!(
        !writes_to_passport("UPDATE odal.passport_version SET doc = $1"),
        "including the archive's own"
    );
}

/// The functions in `source` that update `odal.passport` without calling
/// `archive_stored` first.
///
/// A function runs from one `fn` line to the next, which is coarse and enough:
/// the statements here are built inline, so the `UPDATE` and the archive it needs
/// sit in the same body.
fn updates_without_an_archive(source: &str) -> Vec<&str> {
    const UPDATES: [&str; 2] = ["UPDATE odal.passport SET", "UPDATE odal.passport p SET"];
    let mut found = Vec::new();
    let mut current: Option<(&str, bool, bool)> = None;
    for line in source.lines() {
        let line = line.trim_start();
        let opens = ["pub(crate) ", "pub "]
            .iter()
            .fold(line, |rest, vis| rest.strip_prefix(vis).unwrap_or(rest));
        let opens = opens.strip_prefix("async ").unwrap_or(opens);
        if let Some(rest) = opens.strip_prefix("fn ") {
            if let Some((name, true, false)) = current {
                found.push(name);
            }
            current = Some((rest.split(['(', '<']).next().unwrap_or(rest), false, false));
        }
        if let Some((_, updates, archives)) = current.as_mut() {
            *updates |= UPDATES.iter().any(|u| line.contains(u));
            *archives |= line.contains("archive_stored(");
        }
    }
    if let Some((name, true, false)) = current {
        found.push(name);
    }
    found
}

/// Every statement in `repo_passport.rs` that changes a stored passport archives
/// the record it replaces, in the same transaction.
///
/// ✅ COMPLIANCE-PIN: EN 18221:2026 clause 4.2. The list above keeps writes in
/// this file; this keeps each write in it archiving. A new `UPDATE` that skipped
/// it would change passports with no version kept, and every test of the
/// existing writes would still pass.
#[test]
fn every_update_in_the_repository_archives_first() {
    let source = include_str!("../src/pg/repo_passport.rs");
    let unarchived = updates_without_an_archive(source);
    assert!(
        unarchived.is_empty(),
        "these functions in repo_passport.rs update `odal.passport` without \
         `archive_stored`: {unarchived:?}. Archive the stored record under the change's \
         lock first, or the change keeps no version (EN 18221 clause 4.2)."
    );
}

/// The check above can tell an archiving update from one that is not.
#[test]
fn the_archive_check_finds_an_update_that_skips_it() {
    let skips = "async fn write(&self) {\n    sqlx::query(\"UPDATE odal.passport SET doc = $2\")\n}\n\
                 fn read(&self) {\n    sqlx::query(\"SELECT doc FROM odal.passport\")\n}\n";
    assert_eq!(updates_without_an_archive(skips), ["write"]);

    let archives = "pub(crate) async fn write(&self) {\n    self.archive_stored(tx, id).await?;\n    \
                    sqlx::query(\"UPDATE odal.passport SET doc = $2\")\n}\n";
    assert!(updates_without_an_archive(archives).is_empty());
}
