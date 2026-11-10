//! The record of the resolver's conformance to the GS1 Conformant Resolver
//! Standard says only what its evidence shows.
//!
//! `docs/architecture/GS1_RESOLVER_CONFORMANCE.md` has a table of the standard's 25
//! criteria, each with a status and the tests that back it. The standards register
//! (`docs/architecture/STANDARDS.md`) has one row that says whether conformance is
//! claimed. Neither is read by the build, so each could drift from the code and from
//! the other: a test renamed in `dpp-resolver` would leave a row pointing at
//! nothing, and a criterion fixed would leave a register that still declines a
//! claim it could now make.
//!
//! # The rules
//!
//! 1. **The table has a row for each of the 25 criteria, in order.**
//! 2. **Every row has a status the record defines**, and a row that is met, met in
//!    part, or not applicable names evidence.
//! 3. **Every test a row names exists** in the resolver's sources, and every file it
//!    names exists. A test is found by its `fn` declaration, not by running it:
//!    `just test` runs them.
//! 4. **The register row agrees with the table.** It says `Yes` only when no
//!    criterion marked `SHALL` or `SHALL NOT` is partly met or not met, and `No`
//!    only when one is. A `No` with nothing unmet is a claim being withheld without
//!    a reason, which is as unsupported as a `Yes` with a gap.
//!
//! # What this cannot prove
//!
//! That the tests assert what the row says. It proves the evidence exists and the
//! verdict follows from the statuses; whether a status is true is the tests' job
//! and a reviewer's.

use std::fs;
use std::path::{Path, PathBuf};

const CONFORMANCE: &str = "docs/architecture/GS1_RESOLVER_CONFORMANCE.md";
const REGISTER: &str = "docs/architecture/STANDARDS.md";

/// Where a test a row names may live.
const TEST_SOURCES: &[&str] = &["crates/dpp-resolver/tests", "crates/dpp-resolver/src"];

/// The register's name for the standard.
const REGISTER_NAME: &str = "GS1 Conformant Resolver Standard";

const STATUSES: &[&str] = &[
    "Met",
    "Met by deployment",
    "Partly met",
    "Not met",
    "Not applicable",
];

/// The number of criteria in section 5 of release 1.2.1.
const CRITERIA: usize = 25;

struct Criterion {
    number: usize,
    keyword: String,
    status: String,
    evidence: String,
}

impl Criterion {
    /// Whether a conformance claim cannot stand while this row is as it is.
    fn blocks_a_claim(&self) -> bool {
        (self.keyword.contains("SHALL")) && matches!(self.status.as_str(), "Partly met" | "Not met")
    }
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..")
}

fn read(relative: &str) -> String {
    let path = workspace_root().join(relative);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

/// A Markdown table line split into trimmed cells, or `None` if it is not one.
fn cells(line: &str) -> Option<Vec<String>> {
    let inner = line.trim().strip_prefix('|')?.strip_suffix('|')?;
    Some(inner.split('|').map(|c| c.trim().to_owned()).collect())
}

/// The criteria table's rows: the ones whose first cell is a number.
fn criteria(text: &str) -> Vec<Criterion> {
    text.lines()
        .filter_map(cells)
        .filter_map(|row| {
            let number = row.first()?.parse().ok()?;
            // `# | Section | Keyword | What it asks | Status | Evidence`
            Some(Criterion {
                number,
                keyword: row.get(2)?.clone(),
                status: row.get(4)?.clone(),
                evidence: row.get(5)?.clone(),
            })
        })
        .collect()
}

/// What a row names between backticks.
fn named(evidence: &str) -> Vec<&str> {
    evidence
        .split('`')
        .enumerate()
        .filter(|(i, _)| i % 2 == 1)
        .map(|(_, name)| name)
        .collect()
}

/// Whether `name` is a path rather than a test: a test is a bare identifier.
fn is_a_path(name: &str) -> bool {
    name.contains('/') || name.contains('.')
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// The text of every file a test may be declared in.
fn test_sources() -> String {
    let mut files = Vec::new();
    for dir in TEST_SOURCES {
        rust_files(&workspace_root().join(dir), &mut files);
    }
    assert!(
        !files.is_empty(),
        "no resolver sources found to look for tests in"
    );
    files
        .iter()
        .filter_map(|f| fs::read_to_string(f).ok())
        .map(|text| code_only(&text))
        .collect::<Vec<_>>()
        .join("\n")
}

/// `source` with every comment, and the inside of every string and character
/// literal, blanked to spaces, so that what is left is code and a test named in
/// a comment or quoted in a string is not found. Line breaks are kept, so a
/// function and the attributes above it stay on the lines they were.
fn code_only(source: &str) -> String {
    let chars: Vec<char> = source.chars().collect();
    let mut out = String::with_capacity(source.len());
    let blank = |c: char| if c == '\n' { '\n' } else { ' ' };
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        let next = chars.get(i + 1).copied();
        if c == '/' && next == Some('/') {
            // A line comment, to the end of the line.
            while i < chars.len() && chars[i] != '\n' {
                out.push(' ');
                i += 1;
            }
        } else if c == '/' && next == Some('*') {
            // A block comment, which Rust lets nest.
            let mut depth = 0;
            while i < chars.len() {
                if chars[i] == '/' && chars.get(i + 1) == Some(&'*') {
                    depth += 1;
                    out.push_str("  ");
                    i += 2;
                } else if chars[i] == '*' && chars.get(i + 1) == Some(&'/') {
                    depth -= 1;
                    out.push_str("  ");
                    i += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    out.push(blank(chars[i]));
                    i += 1;
                }
            }
        } else if c == 'r'
            && matches!(next, Some('"' | '#'))
            && raw_string_hashes(&chars, i).is_some()
        {
            // A raw string: r"..." or r#"..."#, with as many hashes as it opens.
            let hashes = raw_string_hashes(&chars, i).unwrap_or(0);
            let open = i + 2 + hashes;
            let close: Vec<char> = std::iter::once('"')
                .chain(std::iter::repeat_n('#', hashes))
                .collect();
            let mut end = open;
            while end < chars.len() && chars[end..].get(..close.len()) != Some(&close[..]) {
                end += 1;
            }
            let end = (end + close.len()).min(chars.len());
            out.extend(chars[i..end].iter().map(|&c| blank(c)));
            i = end;
        } else if c == '"' {
            // A string, to its closing quote, past any escaped one.
            out.push(' ');
            i += 1;
            while i < chars.len() && chars[i] != '"' {
                if chars[i] == '\\' && i + 1 < chars.len() {
                    out.push(' ');
                    i += 1;
                }
                out.push(blank(chars[i]));
                i += 1;
            }
            out.push(' ');
            i += 1;
        } else if c == '\'' {
            // A character literal, and not a lifetime: `'x'` or `'\n'`.
            let literal = match (chars.get(i + 1), chars.get(i + 2), chars.get(i + 3)) {
                (Some('\\'), Some(_), Some('\'')) => Some(4),
                (Some(a), Some('\''), _) if *a != '\'' => Some(3),
                _ => None,
            };
            match literal {
                Some(len) => {
                    out.extend(std::iter::repeat_n(' ', len));
                    i += len;
                }
                None => {
                    out.push(c);
                    i += 1;
                }
            }
        } else {
            out.push(c);
            i += 1;
        }
    }
    out
}

/// The number of `#` a raw string starting at `chars[at]` (an `r`) opens with, if
/// it is a raw string at all.
fn raw_string_hashes(chars: &[char], at: usize) -> Option<usize> {
    // `r` must not end an identifier, as in `for"`.
    if at > 0 && (chars[at - 1].is_alphanumeric() || chars[at - 1] == '_') {
        return None;
    }
    let hashes = chars[at + 1..].iter().take_while(|&&c| c == '#').count();
    (chars.get(at + 1 + hashes) == Some(&'"')).then_some(hashes)
}

/// Whether a function called `name` is declared in `sources` as a test: an item
/// that carries `#[test]`, or an attribute whose path ends in `test` such as
/// `#[tokio::test]`, with nothing but other attributes and blank lines between.
///
/// `sources` is [`code_only`] text. A function that lost its attribute, or sits
/// in a comment or a string, does not count, and nor does the name of one.
fn declares(sources: &str, name: &str) -> bool {
    let needle = format!("fn {name}(");
    let lines: Vec<&str> = sources.lines().collect();
    lines.iter().enumerate().any(|(at, line)| {
        let declared = line.find(&needle).is_some_and(|col| {
            // `fn` starts a word: `async fn`, `pub fn`, and not `my_fn`.
            !line[..col]
                .chars()
                .next_back()
                .is_some_and(|c| c.is_alphanumeric() || c == '_')
        });
        declared
            && lines[..at]
                .iter()
                .rev()
                .map(|l| l.trim())
                .filter(|l| !l.is_empty())
                .take_while(|l| l.starts_with("#["))
                .any(is_a_test_attribute)
    })
}

/// Whether an attribute line is `#[test]` or `#[<path>::test…]`.
fn is_a_test_attribute(attribute: &str) -> bool {
    let inner = attribute.trim_start_matches("#[");
    let path = inner.split(['(', ']']).next().unwrap_or_default().trim();
    path == "test" || path.ends_with("::test")
}

/// Everything wrong with the criteria table, as sentences.
fn table_problems(
    criteria: &[Criterion],
    declared: &dyn Fn(&str) -> bool,
    exists: &dyn Fn(&str) -> bool,
) -> Vec<String> {
    let mut problems = Vec::new();

    let numbers: Vec<usize> = criteria.iter().map(|c| c.number).collect();
    let expected: Vec<usize> = (1..=CRITERIA).collect();
    if numbers != expected {
        problems.push(format!(
            "the table must have rows 1 to {CRITERIA} in order, and has {numbers:?}"
        ));
    }

    for c in criteria {
        let n = c.number;
        if !STATUSES.contains(&c.status.as_str()) {
            problems.push(format!(
                "criterion {n}: `{}` is not a status ({STATUSES:?})",
                c.status
            ));
        }
        let names = named(&c.evidence);
        let needs_evidence = matches!(
            c.status.as_str(),
            "Met" | "Met by deployment" | "Partly met" | "Not applicable"
        );
        if needs_evidence && names.is_empty() {
            problems.push(format!(
                "criterion {n}: `{}` but names no evidence",
                c.status
            ));
        }
        if c.status == "Met by deployment" && !names.iter().any(|name| is_a_path(name)) {
            problems.push(format!(
                "criterion {n}: met by deployment, so its evidence is a document, and it names none"
            ));
        }
        for name in names {
            let found = if is_a_path(name) {
                exists(name)
            } else {
                declared(name)
            };
            if !found {
                problems.push(format!("criterion {n}: `{name}` does not exist"));
            }
        }
    }
    problems
}

/// Everything wrong with the register's verdict, given the table.
fn verdict_problems(criteria: &[Criterion], claimed: &str) -> Vec<String> {
    let blocking: Vec<usize> = criteria
        .iter()
        .filter(|c| c.blocks_a_claim())
        .map(|c| c.number)
        .collect();
    match (claimed, blocking.is_empty()) {
        ("Yes", false) => vec![format!(
            "the register claims conformance, but criteria {blocking:?} are mandatory and not met"
        )],
        ("No", true) => vec![
            "the register declines a claim, but no mandatory criterion is unmet: either make \
             the claim or mark the criterion that stops it"
                .to_owned(),
        ],
        ("Yes" | "No", _) => Vec::new(),
        (other, _) => vec![format!("`{other}` is neither `Yes` nor `No`")],
    }
}

/// The register's GS1 row, as `(revision, claimed)`.
fn register_row(text: &str) -> (String, String) {
    let mut header: Option<Vec<String>> = None;
    for line in text.lines() {
        let Some(row) = cells(line) else {
            header = None;
            continue;
        };
        if row.first().is_some_and(|c| c == "Standard") {
            header = Some(row);
            continue;
        }
        let Some(columns) = header.as_ref() else {
            continue;
        };
        if row[0] == REGISTER_NAME {
            let column = |name: &str| {
                let index = columns
                    .iter()
                    .position(|c| c == name)
                    .unwrap_or_else(|| panic!("{REGISTER}: the GS1 table has no `{name}` column"));
                row.get(index).cloned().unwrap_or_default()
            };
            return (column("Revision"), column("Conformance claimed"));
        }
    }
    panic!("{REGISTER} has no GS1 row for {REGISTER_NAME}");
}

fn real_criteria() -> Vec<Criterion> {
    criteria(&read(CONFORMANCE))
}

#[test]
fn the_criteria_table_is_complete_and_its_evidence_exists() {
    let sources = test_sources();
    let root = workspace_root();
    let problems = table_problems(
        &real_criteria(),
        &|name| declares(&sources, name),
        &|path| root.join(path).exists(),
    );
    assert!(
        problems.is_empty(),
        "{CONFORMANCE}:\n  {}",
        problems.join("\n  ")
    );
}

#[test]
fn the_register_row_agrees_with_the_criteria_table() {
    let (revision, claimed) = register_row(&read(REGISTER));
    assert_eq!(revision, "1.2.1", "the register row is for another release");
    assert!(
        read(CONFORMANCE).contains("release 1.2.1"),
        "{CONFORMANCE} must name the release it assessed"
    );
    let problems = verdict_problems(&real_criteria(), &claimed);
    assert!(
        problems.is_empty(),
        "{REGISTER}:\n  {}",
        problems.join("\n  ")
    );
}

// What follows tests the gate. One that has never been watched failing is one
// nobody knows works, and this one reads two documents: it can fail by finding
// too little.

fn row(number: usize, keyword: &str, status: &str, evidence: &str) -> Criterion {
    Criterion {
        number,
        keyword: keyword.into(),
        status: status.into(),
        evidence: evidence.into(),
    }
}

/// A table of the right length whose every row is met by `a_test`.
fn all_met() -> Vec<Criterion> {
    (1..=CRITERIA)
        .map(|n| row(n, "SHALL", "Met", "`a_test`"))
        .collect()
}

#[test]
fn a_row_is_read_by_its_columns() {
    let rows = criteria(
        "| # | Section | Keyword | What it asks | Status | Evidence |\n\
         |---|---|---|---|---|---|\n\
         | 4 | 2.2 | SHALL | CORS | Met | `cross_origin_requests_are_allowed` |\n\
         | not a row | | | | | |\n",
    );
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].number, 4);
    assert_eq!(rows[0].keyword, "SHALL");
    assert_eq!(rows[0].status, "Met");
    assert_eq!(
        named(&rows[0].evidence),
        ["cross_origin_requests_are_allowed"]
    );
}

#[test]
fn a_missing_a_misnumbered_or_an_unknown_row_is_found() {
    let yes = |_: &str| true;
    assert!(table_problems(&all_met(), &yes, &yes).is_empty());

    let mut short = all_met();
    short.pop();
    assert!(!table_problems(&short, &yes, &yes).is_empty());

    let mut swapped = all_met();
    swapped.swap(2, 3);
    assert!(!table_problems(&swapped, &yes, &yes).is_empty());

    let mut unknown = all_met();
    unknown[6].status = "Mostly".into();
    assert!(!table_problems(&unknown, &yes, &yes).is_empty());
}

#[test]
fn evidence_that_does_not_exist_or_is_not_named_is_found() {
    let nothing = |_: &str| false;
    let yes = |_: &str| true;

    assert!(!table_problems(&all_met(), &nothing, &yes).is_empty());

    let mut bare = all_met();
    bare[0].evidence = "tested".into();
    assert!(!table_problems(&bare, &yes, &yes).is_empty());

    let mut missing_file = all_met();
    missing_file[2].status = "Met by deployment".into();
    missing_file[2].evidence = "`docs/gone.md`".into();
    assert!(!table_problems(&missing_file, &yes, &nothing).is_empty());

    let mut no_document = all_met();
    no_document[2].status = "Met by deployment".into();
    assert!(!table_problems(&no_document, &yes, &yes).is_empty());
}

#[test]
fn a_claim_and_a_gap_cannot_both_stand() {
    // Nothing unmet: a claim is the only honest verdict.
    assert!(verdict_problems(&all_met(), "Yes").is_empty());
    assert!(!verdict_problems(&all_met(), "No").is_empty());

    // A mandatory criterion partly met: the claim cannot stand.
    let mut gap = all_met();
    gap[4].status = "Partly met".into();
    assert!(!verdict_problems(&gap, "Yes").is_empty());
    assert!(verdict_problems(&gap, "No").is_empty());

    // A recommendation that is not met does not stop a claim.
    let mut recommended = all_met();
    recommended[5].keyword = "SHOULD".into();
    recommended[5].status = "Not met".into();
    assert!(verdict_problems(&recommended, "Yes").is_empty());

    assert!(!verdict_problems(&all_met(), "Maybe").is_empty());
}

#[test]
fn only_a_live_test_function_counts_as_a_test() {
    let found = |source: &str, name: &str| declares(&code_only(source), name);

    // Live, in each spelling the resolver's tests use.
    assert!(found("#[test]\nfn a_test() {}", "a_test"));
    assert!(found("#[tokio::test]\nasync fn a_test() {}", "a_test"));
    assert!(found(
        "#[tokio::test(flavor = \"multi_thread\")]\n\n/// docs\n#[ignore]\npub async fn a_test() {}",
        "a_test"
    ));

    // A declaration in a comment, a block comment or a string is not a test.
    assert!(!found("// #[test]\n// fn a_test() {}", "a_test"));
    assert!(!found("#[test]\n// fn a_test() {}", "a_test"));
    assert!(!found("/* #[test]\nfn a_test() {} */", "a_test"));
    assert!(!found("let s = \"#[test]\\nfn a_test() {}\";", "a_test"));
    assert!(!found("let s = r#\"#[test]\nfn a_test() {}\"#;", "a_test"));

    // A function with no test attribute, or whose attribute is another one.
    assert!(!found("fn a_test() {}", "a_test"));
    assert!(!found("#[inline]\nfn a_test() {}", "a_test"));
    assert!(!found("#[test]\nfn other() {}\nfn a_test() {}", "a_test"));

    // A name that only ends in the one asked for.
    assert!(!found("#[test]\nfn not_a_test() {}", "a_test"));
    assert!(!found("#[test]\nfn my_fn_a_test() {}", "a_test"));
}

#[test]
fn a_lifetime_is_not_mistaken_for_a_character_literal() {
    // If `'a` opened a character literal, the real test after it would be blanked.
    let source = "fn f<'a>(x: &'a str) -> &'a str { x }\n#[test]\nfn a_test() {}";
    assert!(declares(&code_only(source), "a_test"));
}

#[test]
fn a_register_without_the_gs1_row_is_an_error_not_a_pass() {
    let result = std::panic::catch_unwind(|| register_row("# Standards Register\n\nNothing.\n"));
    assert!(result.is_err());
}
