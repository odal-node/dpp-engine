//! Which code may write to `odal.passport`, and why the list is a gate.
//!
//! ✅ COMPLIANCE-PIN: EN 18221:2026 clause 4.2 — *"all changes to the digital
//! product passport shall be archived"*.
//!
//! [`ArchivingPassportRepo`](dpp_dal::pg::ArchivingPassportRepo) makes archiving
//! unavoidable by wrapping [`PassportRepository`], and that argument holds for
//! exactly as long as the port is the only way a passport changes. It is not an
//! argument the type can make about itself: a new `sqlx::query` in a new module
//! writing `odal.passport` directly would leave the decorator wrapping a door
//! nobody uses any more, and nothing would fail.
//!
//! So the set is enumerated here, and the test walks the DAL's own source to
//! check it. Adding a writer is then a decision somebody has to record, in this
//! file, next to the reason the existing exception is allowed.
//!
//! # 🚨 There is an exception, and the archive's own documentation got it wrong
//!
//! `ArchivingPassportRepo` said *"every mutation in this workspace goes through
//! `PassportRepository`"*. That was already false when it was written.
//! `PgSealOutboxRepo::mark_sealed` sets `doc->seal` with `jsonb_set`, in the same
//! transaction that closes the outbox row, and never touches the port.
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
//! The honest statement is therefore narrower than the one that shipped, and it
//! is the one the archive's doc now makes: every change to passport **content**
//! goes through the port.

use std::collections::BTreeSet;
use std::path::Path;

/// Files permitted to write the `odal.passport` table, and why.
///
/// Keyed by file name rather than path because the DAL is flat under `src/pg/`.
const ALLOWED_WRITERS: &[(&str, &str)] = &[
    (
        "repo_passport.rs",
        "the `PassportRepository` implementation itself — the door the archiving \
         decorator wraps",
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
/// not going through `PassportRepository`, where the EN 18221 clause 4.2 archive
/// would see it? A write that changes content and skips the port is a version
/// that is never taken, and nothing else in this workspace would notice.
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
         behind `PassportRepository`, where `ArchivingPassportRepo` archives the version it \
         replaces (EN 18221 clause 4.2). A content change that skips the port is a version \
         that is never taken, and nothing else here would notice."
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
