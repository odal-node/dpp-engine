//! What `odal profile create` and `odal init` actually write to `config.toml`.
//!
//! These pin the file on disk, not the in-memory shape. That distinction is the
//! whole point: the config loader normalises service URLs on the way in, so a
//! profile written raw looked correct to every command that reported one while
//! `config.toml` said `localhost`, and hand-editing the file was the only
//! apparent remedy.

mod helpers;
use helpers::{config_path, config_toml, odal};

use tempfile::TempDir;

/// The command from the audit: a remote vault URL and nothing else.
///
/// Identity must be re-hosted onto the vault's host *in the file*. The resolver
/// must not be — it is a separate deployment — but its localhost default must
/// be called out, or `odal status` reports a dead resolver against a healthy
/// node with nothing naming the cause.
#[test]
fn a_remote_vault_url_writes_a_remote_identity_url() {
    let home = TempDir::new().unwrap();
    let run = odal(
        home.path(),
        &[
            "profile",
            "create",
            "prod",
            "--vault-url",
            "https://node.example.com/vault",
        ],
    );
    assert_eq!(run.code, 0, "{}", run.output());

    let config = config_toml(home.path());
    assert!(
        config.contains(r#"identity_url = "https://node.example.com/identity""#),
        "identity was not re-hosted in the file:\n{config}"
    );
    assert!(
        run.output().contains("--resolver-url"),
        "an unstated prod resolver must name the flag that fixes it:\n{}",
        run.output()
    );
}

/// The two-flag shape a normal remote install uses.
#[test]
fn a_node_origin_and_a_resolver_settle_all_three_urls() {
    let home = TempDir::new().unwrap();
    let run = odal(
        home.path(),
        &[
            "profile",
            "create",
            "live",
            "--node-url",
            "https://node.example.com",
            "--resolver-url",
            "https://dpp.example.com",
        ],
    );
    assert_eq!(run.code, 0, "{}", run.output());

    let config = config_toml(home.path());
    for expected in [
        r#"kind = "prod""#,
        r#"vault_url = "https://node.example.com/vault""#,
        r#"identity_url = "https://node.example.com/identity""#,
        r#"resolver_url = "https://dpp.example.com""#,
    ] {
        assert!(
            config.contains(expected),
            "missing {expected} in:\n{config}"
        );
    }
    assert!(
        !run.output().contains("--resolver-url"),
        "a stated resolver must not warn:\n{}",
        run.output()
    );
}

/// A dev profile resolves locally on purpose, so the same default is correct
/// there and warning about it would train operators to ignore the warning.
#[test]
fn a_local_node_does_not_warn_about_its_local_resolver() {
    let home = TempDir::new().unwrap();
    let run = odal(
        home.path(),
        &[
            "profile",
            "create",
            "local",
            "--node-url",
            "http://localhost:8001",
        ],
    );
    assert_eq!(run.code, 0, "{}", run.output());
    assert!(config_toml(home.path()).contains(r#"kind = "dev""#));
    assert!(
        !run.output().contains("--resolver-url"),
        "a dev profile must not warn:\n{}",
        run.output()
    );
}

/// The two flags describe the same thing at different depths. Rejecting the
/// pair at the parser is what keeps a silent precedence rule out of the
/// handlers, so it is worth pinning that the parser still refuses it.
#[test]
fn node_url_and_vault_url_together_are_refused() {
    let home = TempDir::new().unwrap();
    let run = odal(
        home.path(),
        &[
            "profile",
            "create",
            "prod",
            "--node-url",
            "https://node.example.com",
            "--vault-url",
            "https://node.example.com/vault",
        ],
    );
    assert_eq!(run.code, 2, "clap usage errors exit 2: {}", run.output());
    assert!(
        !config_path(home.path()).exists(),
        "a refused command must not write a profile"
    );
}

/// A blank flag value must fall back to the default rather than become the bare
/// path `/vault`, which no normalisation repairs and which `EnvKind::infer`
/// reads as a remote host — producing a prod profile pointed at nothing.
#[test]
fn a_blank_node_url_falls_back_to_the_local_default() {
    let home = TempDir::new().unwrap();
    let run = odal(
        home.path(),
        &["profile", "create", "edge", "--node-url", ""],
    );
    assert_eq!(run.code, 0, "{}", run.output());

    let config = config_toml(home.path());
    assert!(
        config.contains(r#"vault_url = "http://localhost:8001/vault""#),
        "blank origin did not fall back:\n{config}"
    );
    assert!(
        config.contains(r#"kind = "dev""#),
        "a fallback to localhost is a dev profile:\n{config}"
    );
}

/// `init` is the scripting entrypoint and takes the same flags, so it must
/// write the same shape.
#[test]
fn init_writes_the_same_urls_as_profile_create() {
    let home = TempDir::new().unwrap();
    let run = odal(
        home.path(),
        &[
            "init",
            "--node-url",
            "https://node.example.com",
            "--resolver-url",
            "https://dpp.example.com",
        ],
    );
    assert_eq!(run.code, 0, "{}", run.output());

    let config = config_toml(home.path());
    assert!(config.contains(r#"vault_url = "https://node.example.com/vault""#));
    assert!(config.contains(r#"identity_url = "https://node.example.com/identity""#));
    assert!(config.contains(r#"resolver_url = "https://dpp.example.com""#));
}

/// `odal init` must scaffold every file the compose stack bind-mounts, not just
/// the compose file.
///
/// Docker does not fail on a missing bind-mount source — it creates an empty
/// directory there — and the Postgres entrypoint skips a directory. An install
/// scaffolded with only the compose file therefore starts, reports success, and
/// never provisions the database role's password, leaving the node retrying
/// authentication for as long as it runs.
#[test]
fn init_scaffolds_every_file_the_stack_mounts() {
    let home = TempDir::new().unwrap();
    let run = odal(
        home.path(),
        &["init", "--node-url", "http://localhost:8001"],
    );
    assert_eq!(run.code, 0, "{}", run.output());

    for rel in [
        "docker/docker-compose.yml",
        "ops/bootstrap/pg-init.sh",
        "ops/bootstrap/bootstrap.sql",
    ] {
        let path = home.path().join(rel);
        assert!(
            path.is_file(),
            "{rel} was not scaffolded:\n{}",
            run.output()
        );
        assert!(
            path.metadata().unwrap().len() > 0,
            "{rel} was scaffolded empty"
        );
    }
}

/// Re-running `init` must not clobber an operator's edited compose file.
#[test]
fn init_is_idempotent_and_does_not_overwrite() {
    let home = TempDir::new().unwrap();
    odal(home.path(), &["init"]);

    let compose = home.path().join("docker/docker-compose.yml");
    std::fs::write(&compose, "# edited\n").unwrap();

    let again = odal(home.path(), &["init"]);
    assert_eq!(again.code, 0, "{}", again.output());
    assert_eq!(std::fs::read_to_string(&compose).unwrap(), "# edited\n");
}
