//! What `odal` does when `config.toml` or `credentials.toml` does not parse.
//!
//! The answer has to be "refuse, loudly, and touch nothing". Both files were
//! read with `toml::from_str(..).unwrap_or_default()`, and both are persisted by
//! a wholesale `fs::write` of the serialised struct, so a parse failure became a
//! silent erase: read fails → empty store → the next command that saves writes
//! that emptiness over the file → every profile's URL, and every profile's API
//! key, gone with nothing printed at any point.
//!
//! These drive the real binary because that chain is what has to be pinned, not
//! the parse step alone. Making the parse loud is not enough on its own — the
//! callers (`Config::save`, `credentials::save_key`) each held a second
//! `unwrap_or_default()` that would have swallowed the new error and written the
//! empty file anyway.

mod helpers;
use helpers::{config_path, odal, odal_env};

use std::path::{Path, PathBuf};

use tempfile::TempDir;

/// A hand-edit slip: an unterminated string, with the real values still plainly
/// in the file. This is recoverable by hand — which is the whole point, since
/// the bug's cost was that it stopped being recoverable.
const MALFORMED_CONFIG: &str = "current_profile = \"new_dev\"\n\
                                \n\
                                [profiles.new_dev]\n\
                                kind = \"prod\"\n\
                                vault_url = \"https://node.example.com/vault\n\
                                identity_url = \"https://node.example.com/identity\"\n";

const MALFORMED_CREDENTIALS: &str = "[keys]\n\
                                     new_dev = \"odal_sk_a_real_key\n";

fn credentials_path(home: &Path) -> PathBuf {
    home.join(".config").join("odal").join("credentials.toml")
}

/// Write `contents` to `path`, creating the config dir.
fn seed(path: &Path, contents: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, contents).unwrap();
}

/// The reported bug, end to end: a corrupt `config.toml` plus any command that
/// persists a profile used to rewrite the file with only the new profile in it.
///
/// `profile create` reaches the write with no node and no prompt, which is what
/// makes this assertable in the default test lane. The same write is reached by
/// `odal bootstrap`, `profile use`, and every `Config::save` caller.
#[test]
fn a_corrupt_config_is_not_overwritten_by_profile_create() {
    let home = TempDir::new().unwrap();
    let path = config_path(home.path());
    seed(&path, MALFORMED_CONFIG);

    let run = odal(
        home.path(),
        &[
            "profile",
            "create",
            "other",
            "--node-url",
            "http://localhost:8001",
        ],
    );

    assert_ne!(
        run.code,
        0,
        "a config that does not parse must fail the command, not be replaced:\n{}",
        run.output()
    );
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        MALFORMED_CONFIG,
        "the operator's config was rewritten — this is the data loss under test"
    );
    let out = run.output();
    assert!(
        out.contains("config.toml"),
        "the error must name the file to fix:\n{out}"
    );
}

/// A corrupt config must not be reported as a fresh install either. Reading it
/// as an empty file made `profile list` print nothing and exit 0, which says
/// "you have no profiles" to someone whose profiles are sitting in the file.
#[test]
fn a_corrupt_config_fails_profile_list_loudly() {
    let home = TempDir::new().unwrap();
    seed(&config_path(home.path()), MALFORMED_CONFIG);

    let run = odal(home.path(), &["profile", "list"]);

    assert_ne!(
        run.code,
        0,
        "a config that does not parse must not read as 'no profiles':\n{}",
        run.output()
    );
    assert!(
        run.output().contains("config.toml"),
        "the error must name the file to fix:\n{}",
        run.output()
    );
}

/// The credentials half: a corrupt store must not read as "no key stored".
///
/// It used to, and the consequence was worse than a missing profile. The CLI
/// went to the node with no credential, earned a 401, and reported a credential
/// problem — while the real key sat unread in the file, about to be erased by
/// the next save.
#[test]
fn a_corrupt_credentials_store_is_not_read_as_no_key() {
    let home = TempDir::new().unwrap();
    // A *valid* config, so the only thing under test is the credentials read.
    seed(
        &config_path(home.path()),
        "current_profile = \"new_dev\"\n\
         \n\
         [profiles.new_dev]\n\
         kind = \"prod\"\n\
         vault_url = \"https://node.example.com/vault\"\n",
    );
    let creds = credentials_path(home.path());
    seed(&creds, MALFORMED_CREDENTIALS);

    let run = odal(home.path(), &["profile", "show", "new_dev"]);

    assert_ne!(
        run.code,
        0,
        "a credentials store that does not parse must fail, not report no key:\n{}",
        run.output()
    );
    assert!(
        run.output().contains("credentials.toml"),
        "the error must name the file to fix:\n{}",
        run.output()
    );
    assert_eq!(
        std::fs::read_to_string(&creds).unwrap(),
        MALFORMED_CREDENTIALS,
        "the operator's key file was rewritten — this is the data loss under test"
    );
}

/// The credentials store must survive the command that writes a key into it.
///
/// `odal init --api-key` is the scriptable path to `Config::save`, which writes
/// `config.toml` and then hands the key to the credentials store — no node, no
/// prompt. That store held its own `unwrap_or_default()` on the read, so this is
/// the case where the erase actually happened: load fails → empty map → insert
/// this one key → `fs::write` the lot, and every other profile's key is gone.
#[test]
fn a_corrupt_credentials_store_is_not_overwritten_by_init() {
    let home = TempDir::new().unwrap();
    seed(
        &config_path(home.path()),
        "current_profile = \"new_dev\"\n\
         \n\
         [profiles.new_dev]\n\
         kind = \"prod\"\n\
         vault_url = \"https://node.example.com/vault\"\n",
    );
    let creds = credentials_path(home.path());
    seed(&creds, MALFORMED_CREDENTIALS);

    let run = odal(
        home.path(),
        &[
            "init",
            "--node-url",
            "http://localhost:8001",
            "--api-key",
            "odal_sk_brand_new",
        ],
    );

    assert_ne!(
        run.code,
        0,
        "saving a key into a store that does not parse must fail:\n{}",
        run.output()
    );
    assert_eq!(
        std::fs::read_to_string(&creds).unwrap(),
        MALFORMED_CREDENTIALS,
        "the operator's key file was rewritten — this is the data loss under test"
    );
    assert!(
        run.output().contains("credentials.toml"),
        "the error must name the file to fix:\n{}",
        run.output()
    );
}

/// The one path that writes the credentials store without having read it first.
///
/// `ODAL_API_KEY` wins in `resolve_api_key` before the store is opened, so
/// `Config::load` succeeds without touching it and `save_key` becomes the first
/// and only thing that does. Every other route to a write reads the store on the
/// way in, which is why `save_key`'s own swallowed load looked harmless: remove
/// the read that shields it and the erase is back. This is the test that holds
/// `save_key` to `?` on its own account.
#[test]
fn a_corrupt_store_survives_a_save_the_env_key_let_through() {
    let home = TempDir::new().unwrap();
    seed(
        &config_path(home.path()),
        "current_profile = \"new_dev\"\n\
         \n\
         [profiles.new_dev]\n\
         kind = \"prod\"\n\
         vault_url = \"https://node.example.com/vault\"\n",
    );
    let creds = credentials_path(home.path());
    seed(&creds, MALFORMED_CREDENTIALS);

    let run = odal_env(
        home.path(),
        &[
            "init",
            "--node-url",
            "http://localhost:8001",
            "--api-key",
            "odal_sk_brand_new",
        ],
        &[("ODAL_API_KEY", "odal_sk_from_the_environment")],
    );

    assert_ne!(
        run.code,
        0,
        "saving a key into a store that does not parse must fail, even when the \
         read that would have caught it was short-circuited:\n{}",
        run.output()
    );
    assert_eq!(
        std::fs::read_to_string(&creds).unwrap(),
        MALFORMED_CREDENTIALS,
        "the operator's key file was rewritten — this is the data loss under test"
    );
}

/// The config half of the same command: `init` must not rewrite a config it
/// could not read, and must say which file to fix.
#[test]
fn a_corrupt_config_is_not_overwritten_by_init() {
    let home = TempDir::new().unwrap();
    let path = config_path(home.path());
    seed(&path, MALFORMED_CONFIG);

    let run = odal(
        home.path(),
        &["init", "--node-url", "http://localhost:8001"],
    );

    assert_ne!(
        run.code,
        0,
        "a config that does not parse must fail the command, not be replaced:\n{}",
        run.output()
    );
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        MALFORMED_CONFIG,
        "the operator's config was rewritten — this is the data loss under test"
    );
    assert!(
        run.output().contains("config.toml"),
        "the error must name the file to fix:\n{}",
        run.output()
    );
}

/// The unknown-field tolerance that makes the migration reachable also lets a
/// *broken* flat config through the first read, and that erase is the same one.
///
/// `ConfigFile` ignores unknown top-level keys, so a flat file with a wrong-typed
/// value parses there as an empty file and only fails on the second read, as
/// `LegacyConfig`. While that second error was dropped, an operator still on a
/// pre-profiles config lost it to the next `profile create` — a whole class of
/// user the main fix did not reach. Found in review of this PR, not by me.
#[test]
fn a_broken_legacy_config_is_not_overwritten_by_profile_create() {
    let home = TempDir::new().unwrap();
    let path = config_path(home.path());
    // An integer where a URL belongs: valid TOML, invalid `LegacyConfig`.
    let broken = "vault_url = 8001\napi_key = \"odal_sk_legacy\"\n";
    seed(&path, broken);

    let run = odal(
        home.path(),
        &[
            "profile",
            "create",
            "other",
            "--node-url",
            "http://localhost:8001",
        ],
    );

    assert_ne!(
        run.code,
        0,
        "a legacy config that does not parse must fail the command:\n{}",
        run.output()
    );
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        broken,
        "the operator's legacy config was rewritten — this is the data loss under test"
    );
    assert!(
        run.output().contains("config.toml"),
        "the error must name the file to fix:\n{}",
        run.output()
    );
}

/// The legacy pre-profiles migration has to survive making the parse loud.
///
/// A flat config is valid TOML whose keys `ConfigFile` does not name, so it
/// parses as an empty file and reaches the migration on the no-profiles branch.
/// That is a narrow distinction to rest on, so it is pinned through the binary:
/// if propagating the parse error ever cut the fallback off, this goes red.
#[test]
fn a_legacy_flat_config_still_migrates() {
    let home = TempDir::new().unwrap();
    seed(
        &config_path(home.path()),
        "vault_url = \"https://old.example/vault\"\n\
         api_key = \"odal_sk_legacy\"\n",
    );

    let run = odal(home.path(), &["profile", "list"]);

    assert_eq!(
        run.code,
        0,
        "a legacy flat config must still load:\n{}",
        run.output()
    );
    assert!(
        run.output().contains("default"),
        "the legacy file must migrate into a 'default' profile:\n{}",
        run.output()
    );
    assert!(
        run.output().contains("old.example"),
        "the migrated profile must carry the legacy vault URL:\n{}",
        run.output()
    );
}

/// A fresh install must stay quiet. Making a parse failure loud must not turn
/// "nothing configured yet" into an error — that path has its own first-run
/// handling and is the common case on a new machine.
#[test]
fn an_absent_config_is_still_a_fresh_install() {
    let home = TempDir::new().unwrap();
    let run = odal(home.path(), &["profile", "list"]);
    assert_eq!(
        run.code,
        0,
        "no config file at all must not be an error:\n{}",
        run.output()
    );
}
