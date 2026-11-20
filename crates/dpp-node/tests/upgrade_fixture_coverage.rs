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

/// The first release whose fixture carries its key store. The capture script has
/// kept the store since, so every fixture from this one on must have it: without
/// it, `operator_paths.rs` starts the node on a fresh store and checks no
/// signature the release stored.
const FIRST_KEY_STORE: Version = (0, 16, 0);

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
///
/// Any other heading that does not parse fails rather than being skipped. A
/// release written as `## [0.14.1] – 2026-11-01`, with an en dash, would drop out
/// of the list, and the gate would then compare against an older release and pass
/// without the fixture it exists to require.
fn released() -> Vec<Version> {
    let changelog = fs::read_to_string(repo().join("CHANGELOG.md")).expect("read CHANGELOG.md");
    changelog
        .lines()
        .filter_map(|line| line.strip_prefix("## ["))
        .filter(|rest| !rest.starts_with("Unreleased]"))
        .map(|rest| {
            rest.split_once("] - ")
                .and_then(|(version, _date)| parse(version))
                .unwrap_or_else(|| {
                    panic!("CHANGELOG.md heading `## [{rest}` is not `## [X.Y.Z] - <date>`")
                })
        })
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

/// What is wrong with the key store a fixture directory carries, if anything.
///
/// The store is optional, since the first two fixtures were captured before the
/// script kept one. But a store with no passphrase beside it cannot be opened by
/// the upgrade test, and a passphrase with no store opens nothing, so either
/// half alone is a fixture that was captured wrongly or half deleted.
fn key_store_gap(dir: &Path) -> Option<String> {
    let store = dir.join("keystore.enc").is_file();
    let passphrase = dir.join("keystore.passphrase");
    match (store, passphrase.is_file()) {
        (true, false) => Some("keystore.enc has no keystore.passphrase beside it".to_owned()),
        (false, true) => Some("keystore.passphrase has no keystore.enc beside it".to_owned()),
        (true, true) => fs::read_to_string(&passphrase)
            .expect("read keystore.passphrase")
            .trim()
            .is_empty()
            .then(|| "keystore.passphrase is empty".to_owned()),
        (false, false) => None,
    }
}

#[test]
fn a_fixture_key_store_and_its_passphrase_come_together() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/upgrade");
    for entry in fs::read_dir(&root).expect("read tests/fixtures/upgrade") {
        let path = entry.expect("dir entry").path();
        if let Some(gap) = key_store_gap(&path) {
            panic!(
                "{}: {gap}. Re-capture the fixture with `scripts/capture-upgrade-fixture.sh`, \
                 which writes both.",
                path.display()
            );
        }
    }
}

#[test]
fn every_fixture_from_the_first_key_store_on_carries_one() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/upgrade");
    let mut checked = 0;
    for entry in fs::read_dir(&root).expect("read tests/fixtures/upgrade") {
        let path = entry.expect("dir entry").path();
        // A directory that is not named for a release fails
        // `every_fixture_is_a_release_and_complete`.
        let Some(version) = path
            .file_name()
            .and_then(|n| n.to_str())
            .and_then(|n| n.strip_prefix('v'))
            .and_then(parse)
        else {
            continue;
        };
        if version < FIRST_KEY_STORE {
            continue;
        }
        assert!(
            path.join("keystore.enc").is_file(),
            "{}: keystore.enc is missing. Every fixture from v{} on carries the \
             release's key store, and without it the upgrade test starts the node on a \
             fresh one and checks no signature the release stored. Re-capture the \
             fixture with `scripts/capture-upgrade-fixture.sh`, which keeps it.",
            path.display(),
            show(FIRST_KEY_STORE),
        );
        checked += 1;
    }
    assert!(
        checked > 0,
        "no fixture from v{} on, so no upgrade test opens a key store a release wrote",
        show(FIRST_KEY_STORE)
    );
}

#[test]
fn a_key_store_without_a_passphrase_or_the_reverse_is_reported() {
    let dir = tempfile::tempdir().expect("fixture dir");
    assert_eq!(key_store_gap(dir.path()), None, "neither is allowed");

    fs::write(dir.path().join("keystore.enc"), "{}").expect("write store");
    assert!(
        key_store_gap(dir.path())
            .expect("a store alone is a gap")
            .contains("no keystore.passphrase")
    );

    fs::write(dir.path().join("keystore.passphrase"), " \n").expect("write passphrase");
    assert!(
        key_store_gap(dir.path())
            .expect("a blank passphrase is a gap")
            .contains("empty")
    );

    fs::write(dir.path().join("keystore.passphrase"), "secret\n").expect("write passphrase");
    assert_eq!(key_store_gap(dir.path()), None, "both is allowed");

    fs::remove_file(dir.path().join("keystore.enc")).expect("remove store");
    assert!(
        key_store_gap(dir.path())
            .expect("a passphrase alone is a gap")
            .contains("no keystore.enc")
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

/// Each captured release is upgraded by a test of its own in `operator_paths.rs`,
/// `v<X>_<Y>_<Z>_upgrades_to_this_build`, so each is held to the slow-test budget
/// alone and a failure names the release. A fixture with no test would be
/// captured and never upgraded, and a test with no fixture would fail only in the
/// Docker tier; both are caught here.
#[test]
fn every_fixture_has_its_own_upgrade_test() {
    let tests = include_str!("operator_paths.rs");
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/upgrade");
    for entry in fs::read_dir(&root).expect("read tests/fixtures/upgrade") {
        let name = entry.expect("dir entry").file_name();
        let name = name.to_str().unwrap_or_default();
        let test = format!(
            "async fn {}_upgrades_to_this_build()",
            name.replace('.', "_")
        );
        assert!(
            tests.contains(&test),
            "{name} has no upgrade test: add `{test}` to operator_paths.rs, as the others are"
        );
    }
    for line in tests.lines() {
        let Some(test) = line
            .trim()
            .strip_prefix("async fn ")
            .and_then(|rest| rest.strip_suffix("_upgrades_to_this_build() {"))
        else {
            continue;
        };
        let release = test.replace('_', ".");
        assert!(
            root.join(&release).is_dir(),
            "operator_paths.rs upgrades from {release}, which has no fixture"
        );
    }
}
