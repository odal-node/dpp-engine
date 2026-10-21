//! Every IETF specification this repository cites has a row in the standards
//! register, and the row says what its status was when it was last read.
//!
//! # The gap this closes
//!
//! An RFC can be obsoleted, and an Internet-Draft can gain a revision or become
//! an RFC. A citation written against either goes stale silently: it still
//! compiles and it still reads as true. This repository cited RFC 7807 in thirty
//! seven places, and RFC 7235 in two, after RFC 9457 and RFC 9110 had replaced
//! them, while the resolver already cited RFC 9457 for the same error shape: one
//! concept under two numbers, and nothing that said which was current.
//!
//! # The rules
//!
//! These apply to every `RFC NNNN` and `draft-ietf-…` cited anywhere this gate
//! reads:
//!
//! 1. **A citation has a row** in `docs/architecture/STANDARDS.md`. A new
//!    citation therefore forces its status to be read when it is written, not
//!    discovered later.
//! 2. **An obsoleted specification is not cited** unless its row gives a
//!    `kept:` reason. Otherwise the fix is to cite the successor.
//! 3. **An Internet-Draft is cited with its revision** (`-NN`). A draft name
//!    without one points at a moving text.
//! 4. **A row is cited somewhere.** A row nothing cites records the status of a
//!    text this repository no longer relies on, and every release would re-read
//!    it for nothing.
//!
//! And two that apply to every row:
//!
//! 5. **A row carries a status and the date it was read.** An empty `Status as
//!    read`, or a `Read` that is not a `YYYY-MM-DD` date, fails. Without this the
//!    promise below, that every citation has a status somebody read and dated,
//!    would hold only until a cell was cleared.
//! 6. **No row claims conformance.** This repository claims none, so every row
//!    says `No`. The day a claim is made it needs evidence and a rule that holds
//!    it to that, as in dpp-core's register, and this fails until both exist.
//!
//! # What this cannot prove
//!
//! That a recorded status is **current**. The gate reads a file, not the IETF.
//! What it proves is that every citation has a row, and that every row has a
//! status somebody read and dated. That makes the release-time re-read
//! (`docs/governance/RELEASE.md`) a walk down one table, not a search. Only IETF
//! documents are matched: other specifications take too many shapes to find
//! reliably.
//!
//! # What it reads
//!
//! Every `.rs`, `.md`, `.toml`, `.json`, `.yml` and `.yaml` file in the
//! repository, plus `justfile` and `.gitattributes`. It skips build output and
//! hidden directories other than `.github`. Two files are skipped: the register
//! itself, which is what citations are checked against, and `CHANGELOG.md`, a
//! record of what was said at each release, since rewriting a released entry
//! changes no claim made today. This file is skipped too: its fixtures cite on
//! purpose.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

/// The register, relative to the workspace root.
const REGISTER: &str = "docs/architecture/STANDARDS.md";

/// Files this gate does not read, each for the reason in the module docs.
const SKIPPED: &[&str] = &[
    REGISTER,
    "CHANGELOG.md",
    "crates/dpp-node/tests/standard_citations.rs",
];

const EXTENSIONS: &[&str] = &["rs", "md", "toml", "json", "yml", "yaml"];

const NAMED_FILES: &[&str] = &[".gitattributes", "justfile"];

/// A register row whose specification is an IETF document.
struct Row {
    /// `RFC 9457`, or a draft's full name with its revision.
    spec: String,
    status: String,
    read: String,
    conformance: String,
    /// The whole line, for its `kept:` reason.
    text: String,
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..")
}

fn is_word_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

fn starts_a_word(line: &str, at: usize) -> bool {
    !line[..at].chars().next_back().is_some_and(is_word_char)
}

/// Every IETF specification `line` cites, spelled as the register spells it.
///
/// Case-sensitive on purpose: `rfc9901_vector_tests` is a file name, not a
/// citation, and JSON Schema's `draft-07` is not an Internet-Draft name. An RFC
/// number has up to five digits: RFC 10007 exists.
fn citations(line: &str) -> Vec<String> {
    let mut found = Vec::new();

    for (at, _) in line.match_indices("RFC") {
        if !starts_a_word(line, at) {
            continue;
        }
        let rest = &line[at + 3..];
        let rest = rest.strip_prefix(' ').unwrap_or(rest);
        let digits = rest.len() - rest.trim_start_matches(|c: char| c.is_ascii_digit()).len();
        let ends_cleanly = !rest[digits..].chars().next().is_some_and(is_word_char);
        if (3..=5).contains(&digits) && ends_cleanly {
            found.push(format!("RFC {}", &rest[..digits]));
        }
    }

    for (at, _) in line.match_indices("draft-ietf-") {
        if !starts_a_word(line, at) {
            continue;
        }
        let name: String = line[at..]
            .chars()
            .take_while(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == '-')
            .collect();
        found.push(name.trim_end_matches('-').to_owned());
    }

    found
}

/// Whether a draft name ends in its two-digit revision.
fn has_revision(draft: &str) -> bool {
    draft
        .rsplit_once('-')
        .is_some_and(|(_, rev)| rev.len() == 2 && rev.bytes().all(|b| b.is_ascii_digit()))
}

/// Whether `text` is a `YYYY-MM-DD` calendar date.
fn is_a_date(text: &str) -> bool {
    let parts: Vec<&str> = text.split('-').collect();
    let [year, month, day] = parts.as_slice() else {
        return false;
    };
    let number = |s: &str, width: usize| {
        (s.len() == width && s.bytes().all(|b| b.is_ascii_digit()))
            .then(|| s.parse::<u32>().ok())
            .flatten()
    };
    matches!(
        (number(year, 4), number(month, 2), number(day, 2)),
        (Some(_), Some(1..=12), Some(1..=31))
    )
}

/// A Markdown table line split into trimmed cells, or `None` if it is not one.
fn cells(line: &str) -> Option<Vec<String>> {
    let inner = line.trim().strip_prefix('|')?.strip_suffix('|')?;
    Some(inner.split('|').map(|c| c.trim().to_owned()).collect())
}

/// The register's IETF rows, read from the table whose header opens `| Spec |`.
fn register() -> Vec<Row> {
    let path = workspace_root().join(REGISTER);
    let text =
        fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    rows_of(&text)
}

fn rows_of(text: &str) -> Vec<Row> {
    let mut header: Option<Vec<String>> = None;
    let mut rows = Vec::new();
    for line in text.lines() {
        let Some(row) = cells(line) else {
            header = None;
            continue;
        };
        if row.first().is_some_and(|c| c == "Spec") {
            header = Some(row);
            continue;
        }
        let Some(columns) = header.as_ref() else {
            continue;
        };
        let spec = row[0].trim_matches('`').to_owned();
        if !(spec.starts_with("RFC ") || spec.starts_with("draft-")) {
            continue;
        }
        let column = |name: &str| {
            let index = columns
                .iter()
                .position(|c| c == name)
                .unwrap_or_else(|| panic!("{REGISTER}: the IETF table has no `{name}` column"));
            row.get(index).cloned().unwrap_or_default()
        };
        rows.push(Row {
            status: column("Status as read"),
            read: column("Read"),
            conformance: column("Conformance claimed"),
            text: line.to_owned(),
            spec,
        });
    }

    assert!(
        !rows.is_empty(),
        "{REGISTER} yielded no IETF rows — the gate would pass by reading nothing"
    );
    rows
}

/// Every file this gate reads.
fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries =
        fs::read_dir(dir).unwrap_or_else(|e| panic!("cannot scan {}: {e}", dir.display()));
    for entry in entries {
        let path = entry
            .unwrap_or_else(|e| panic!("cannot scan {}: {e}", dir.display()))
            .path();
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        if path.is_dir() {
            let hidden = name.starts_with('.') && name != ".github";
            if !hidden && name != "target" && name != "node_modules" {
                walk(&path, out);
            }
        } else if NAMED_FILES.contains(&name)
            || path
                .extension()
                .and_then(|e| e.to_str())
                .is_some_and(|e| EXTENSIONS.contains(&e))
        {
            out.push(path);
        }
    }
}

/// Every cited specification, with each `path:line` that cites it.
fn cited() -> BTreeMap<String, Vec<String>> {
    let root = workspace_root();
    let mut files = Vec::new();
    walk(&root, &mut files);
    assert!(
        files.len() > 200,
        "found {} files — has the layout moved?",
        files.len()
    );

    let mut cited: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for file in files {
        let relative = file
            .strip_prefix(&root)
            .unwrap_or(&file)
            .display()
            .to_string()
            .replace('\\', "/");
        if SKIPPED.contains(&relative.as_str()) {
            continue;
        }
        let bytes =
            fs::read(&file).unwrap_or_else(|e| panic!("cannot read {}: {e}", file.display()));
        let text = String::from_utf8_lossy(&bytes);
        for (index, line) in text.lines().enumerate() {
            for spec in citations(line) {
                cited
                    .entry(spec)
                    .or_default()
                    .push(format!("{relative}:{}", index + 1));
            }
        }
    }
    cited
}

fn listing(cited: &BTreeMap<String, Vec<String>>, specs: &[&String]) -> String {
    specs
        .iter()
        .map(|spec| format!("  {spec}: {}", cited[spec.as_str()].join(", ")))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Rules 1 and 3: every citation has a row, and a draft is cited with its
/// revision.
#[test]
fn every_cited_ietf_specification_has_a_register_row() {
    let rows = register();
    let cited = cited();

    let unversioned: Vec<&String> = cited
        .keys()
        .filter(|spec| spec.starts_with("draft-") && !has_revision(spec))
        .collect();
    assert!(
        unversioned.is_empty(),
        "an Internet-Draft is cited without its revision number, which names a \
         moving text. Cite it as `name-NN`:\n{}",
        listing(&cited, &unversioned)
    );

    let unregistered: Vec<&String> = cited
        .keys()
        .filter(|spec| !rows.iter().any(|row| &row.spec == *spec))
        .collect();
    assert!(
        unregistered.is_empty(),
        "cited with no row in {REGISTER}. Read each one's current status at \
         https://www.rfc-editor.org/info/rfcNNNN (or the datatracker, for a \
         draft) and add a dated row:\n{}",
        listing(&cited, &unregistered)
    );
}

/// Rule 2: an obsoleted specification is cited only with a stated reason.
#[test]
fn an_obsoleted_specification_is_cited_only_with_a_reason() {
    let cited = cited();
    let offenders: Vec<&String> = register()
        .iter()
        .filter(|row| row.status.contains("Obsoleted by") && !row.text.contains("kept:"))
        .filter_map(|row| cited.get_key_value(&row.spec).map(|(spec, _)| spec))
        .collect();
    assert!(
        offenders.is_empty(),
        "cited although {REGISTER} records it as obsoleted. Cite the successor, \
         or give the row a `kept:` reason saying why this one must stay:\n{}",
        listing(&cited, &offenders)
    );
}

/// Rule 4: every row is cited somewhere, so the register cannot go stale.
#[test]
fn every_register_row_is_still_cited() {
    let cited = cited();
    let stale: Vec<String> = register()
        .into_iter()
        .filter(|row| !cited.contains_key(&row.spec))
        .map(|row| row.spec)
        .collect();
    assert!(
        stale.is_empty(),
        "{REGISTER} has rows nothing cites any more. Remove them, or they will be \
         re-read at every release for a text this repository no longer relies on: \
         {stale:?}"
    );
}

/// Rule 5: every row carries a status and the date it was read.
#[test]
fn every_register_row_carries_a_status_and_a_read_date() {
    let faulty: Vec<String> = register()
        .into_iter()
        .filter_map(|row| {
            let mut faults = Vec::new();
            if row.status.is_empty() {
                faults.push("no `Status as read`");
            }
            if !is_a_date(&row.read) {
                faults.push("`Read` is not a YYYY-MM-DD date");
            }
            (!faults.is_empty()).then(|| format!("  {}: {}", row.spec, faults.join(", ")))
        })
        .collect();
    assert!(
        faulty.is_empty(),
        "{REGISTER} has rows without a dated status. Read the specification's \
         current status at its source and record it with the date:\n{}",
        faulty.join("\n")
    );
}

/// Rule 6: no row claims conformance.
#[test]
fn no_row_claims_conformance() {
    let claimed: Vec<String> = register()
        .into_iter()
        .filter(|row| row.conformance != "No")
        .map(|row| format!("{} ({})", row.spec, row.conformance))
        .collect();
    assert!(
        claimed.is_empty(),
        "this repository claims conformance to no specification, so every row \
         says `No` under Conformance claimed. A claim needs evidence and a rule \
         that holds it to that before this can be relaxed: {claimed:?}"
    );
}

// What follows tests the gate. A gate nobody has watched fail is a gate nobody
// knows works, and this one is a scanner: it can fail by finding too little.

#[test]
fn a_citation_is_found_in_every_shape_it_is_written() {
    assert_eq!(citations("see RFC 9457 §3.2"), ["RFC 9457"]);
    assert_eq!(
        citations("(RFC 6750 §3 / RFC 7617)"),
        ["RFC 6750", "RFC 7617"]
    );
    assert_eq!(citations("//! RFC1918, link-local"), ["RFC 1918"]);
    assert_eq!(
        citations("RFC 3161 / RFC 5126 §6.1.1"),
        ["RFC 3161", "RFC 5126"]
    );
    assert_eq!(citations("updated by RFC 10007"), ["RFC 10007"]);
    assert_eq!(
        citations("draft-ietf-oauth-sd-jwt-vc-19, draft-ietf-oauth-status-list"),
        [
            "draft-ietf-oauth-sd-jwt-vc-19",
            "draft-ietf-oauth-status-list"
        ]
    );
}

#[test]
fn what_only_looks_like_a_citation_is_not_one() {
    for line in [
        "fn rfc9901_vector_tests()",
        "a JSON Schema draft-07 keyword",
        "RFC 12 is too short, and RFC 123456 too long",
        "NORFC 9457 is one word",
        "RFC 9457x is one word",
        "an RFC is a document",
        "rfc 9457 in lower case",
    ] {
        assert!(
            citations(line).is_empty(),
            "{line:?} was read as a citation"
        );
    }
}

#[test]
fn a_draft_is_cited_with_two_digits_of_revision_or_not_at_all() {
    assert!(has_revision("draft-ietf-oauth-sd-jwt-vc-19"));
    assert!(!has_revision("draft-ietf-oauth-sd-jwt-vc"));
    assert!(!has_revision("draft-ietf-oauth-sd-jwt-vc-1"));
}

#[test]
fn a_read_date_is_a_calendar_date() {
    assert!(is_a_date("2026-10-21"));
    for bad in [
        "",
        "2026-10",
        "2026-13-01",
        "2026-10-32",
        "21-10-2026",
        "2026/10/21",
        "soon",
    ] {
        assert!(!is_a_date(bad), "{bad:?} was accepted as a date");
    }
}

#[test]
fn a_register_that_yields_no_rows_is_an_error_not_a_pass() {
    let result = std::panic::catch_unwind(|| rows_of("# Standards Register\n\nNo table here.\n"));
    assert!(result.is_err(), "reading no rows must fail loudly");
}

#[test]
fn a_row_is_read_by_the_name_of_its_columns() {
    let rows = rows_of(
        "| Spec | Title | Status as read | Read | Conformance claimed |\n\
         |---|---|---|---|---|\n\
         | RFC 2822 | Message | Obsoleted by RFC 5322. **kept:** chrono | 2026-10-21 | No |\n",
    );
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].spec, "RFC 2822");
    assert!(rows[0].status.starts_with("Obsoleted by"));
    assert!(rows[0].text.contains("kept:"));
    assert_eq!(rows[0].read, "2026-10-21");
    assert_eq!(rows[0].conformance, "No");
}
