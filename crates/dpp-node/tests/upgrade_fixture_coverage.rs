//! A release cannot be cut without a fixture of the release before it.
//!
//! `operator_paths.rs` upgrades every database in `tests/fixtures/upgrade/` to
//! the build under test, and that only protects the upgrade an operator actually
//! makes if the newest release is among them. The fixture has to come from that
//! release's own binaries, so it is captured by hand when the release is tagged
//! (`scripts/capture-upgrade-fixture.sh`). A step done by hand is a step that gets
//! skipped, so this makes the skip fail: when a release pull request moves the
//! workspace version on, the release it moves on from must have a fixture.
//!
//! Pure filesystem check — no Docker, so it runs in the fast gate.

use std::fs;
use std::path::{Path, PathBuf};

/// The first release captured. The requirement starts here; releases before it
/// predate the fixtures and are not reconstructed.
const FIRST_FIXTURE: Version = (0, 14, 0);

type Version = (u64, u64, u64);

fn parse(version: &str) -> Option<Version> {
    let mut parts = version.split('.').map(|p| p.parse::<u64>().ok());
    let version = (parts.next()??, parts.next()??, parts.next()??);
    parts.next().is_none().then_some(version)
}

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Every version `CHANGELOG.md` records as released: a `## [X.Y.Z] - <date>`
/// heading. `[Unreleased]` carries no date and no version, so it is skipped.
fn released() -> Vec<Version> {
    let changelog = fs::read_to_string(repo().join("CHANGELOG.md")).expect("read CHANGELOG.md");
    changelog
        .lines()
        .filter_map(|line| line.strip_prefix("## ["))
        .filter_map(|rest| rest.split_once("] - "))
        .filter_map(|(version, _date)| parse(version))
        .collect()
}

fn show((major, minor, patch): Version) -> String {
    format!("{major}.{minor}.{patch}")
}

fn fixture_dir(version: Version) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("tests/fixtures/upgrade/v{}", show(version)))
}

#[test]
fn the_release_before_this_one_has_an_upgrade_fixture() {
    let current = parse(env!("CARGO_PKG_VERSION")).expect("the workspace version is X.Y.Z");
    let Some(previous) = released().into_iter().filter(|v| *v < current).max() else {
        panic!("CHANGELOG.md records no release before {}", show(current));
    };
    if previous < FIRST_FIXTURE {
        return;
    }
    let dir = fixture_dir(previous);
    for file in ["dump.sql", "public.json"] {
        assert!(
            dir.join(file).is_file(),
            "{} is missing. This workspace is version {}, so an operator upgrades to it \
             from {previous}, and nothing tests that upgrade without a database a real \
             {previous} node wrote. Capture one from the tagged release with \
             `bash scripts/capture-upgrade-fixture.sh {previous}` and commit it.",
            dir.join(file).display(),
            show(current),
            previous = show(previous),
        );
    }
}

#[test]
fn every_fixture_is_a_release_and_complete() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/upgrade");
    let released = released();
    let mut seen = 0;
    for entry in fs::read_dir(&root).expect("read tests/fixtures/upgrade") {
        let path = entry.expect("dir entry").path();
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default()
            .to_owned();
        let version = name
            .strip_prefix('v')
            .and_then(parse)
            .unwrap_or_else(|| panic!("{name}: a fixture directory is named v<X.Y.Z>"));
        assert!(
            released.contains(&version),
            "{name}: CHANGELOG.md records no release {}, so this was not captured \
             from one",
            show(version)
        );
        for file in ["dump.sql", "public.json"] {
            assert!(path.join(file).is_file(), "{name}: {file} is missing");
        }
        seen += 1;
    }
    assert!(
        seen > 0,
        "no upgrade fixtures at all under {}",
        root.display()
    );
}

#[test]
fn the_version_parser_reads_releases_and_refuses_the_rest() {
    assert_eq!(parse("0.15.0"), Some((0, 15, 0)));
    assert_eq!(parse("1.2.10"), Some((1, 2, 10)));
    assert_eq!(parse("Unreleased"), None);
    assert_eq!(parse("0.15"), None);
    assert_eq!(parse("0.15.0.1"), None);
    assert_eq!(parse("0.15.0-rc.1"), None);
}
