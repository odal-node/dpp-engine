//! Docker Compose infrastructure actions (up/down/update/status) and install-root discovery.

use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    time::Instant,
};

use anyhow::{Context, Result};

use super::types::{ContainerHealth, ServiceHealth, ServiceStatus, StatusReport};
use crate::{config::Config, http::OdalClient};

/// Walk up from CWD to find the installation root — the directory that contains
/// a `docker/` folder with either compose file (dev or prod).
pub fn find_install_root() -> Result<PathBuf> {
    let mut dir = std::env::current_dir()?;
    loop {
        let docker = dir.join("docker");
        if docker.join("docker-compose.yml").exists()
            || docker.join("docker-compose.dev.yml").exists()
        {
            return Ok(dir);
        }
        if !dir.pop() {
            anyhow::bail!(
                "No docker/ compose file found in '{}' or any parent directory.\n\
                 Run `odal` and choose Setup / Reconfigure to configure your node.",
                std::env::current_dir()?.display()
            );
        }
    }
}

/// The compose file `odal` operates: the full self-host stack (node + resolver +
/// infra). The infra-only `docker-compose.dev.yml` is for engine development
/// (`just infra` + `cargo run`), not driven by `odal`.
pub const COMPOSE_FILE: &str = "docker-compose.yml";

/// The canonical compose file embedded at build time, used to scaffold
/// `docker/docker-compose.yml` for installs that don't ship the source tree
/// (`odal init` and the console's guided setup). Single source of truth so the
/// two scaffolders never drift.
pub const COMPOSE_TEMPLATE: &str = include_str!("../../../docker/docker-compose.yml");

/// The role-provisioning hook and the SQL it runs, embedded for the same reason
/// as [`COMPOSE_TEMPLATE`].
///
/// The compose file bind-mounts both of these out of `<root>/ops/bootstrap/`.
/// Docker does not fail on a missing bind-mount source — it creates an empty
/// **directory** in its place — and the Postgres entrypoint silently skips a
/// directory. An install scaffolded without them therefore starts, reports
/// success, and never sets the `odal_app` password, leaving the node retrying
/// `password authentication failed` for as long as it runs.
pub const PG_INIT_TEMPLATE: &str = include_str!("../../../ops/bootstrap/pg-init.sh");
pub const BOOTSTRAP_SQL_TEMPLATE: &str = include_str!("../../../ops/bootstrap/bootstrap.sql");

/// One file an install root needs, and what to write into it.
struct ScaffoldFile {
    rel: &'static str,
    contents: &'static str,
    /// The Postgres entrypoint runs an executable `.sh` hook and *sources* a
    /// non-executable one. `pg-init.sh` uses `set -e` and `exit 1`, which mean
    /// different things to a sourced script, so it is written executable.
    executable: bool,
}

const SCAFFOLD: &[ScaffoldFile] = &[
    ScaffoldFile {
        rel: "docker/docker-compose.yml",
        contents: COMPOSE_TEMPLATE,
        executable: false,
    },
    ScaffoldFile {
        rel: "ops/bootstrap/pg-init.sh",
        contents: PG_INIT_TEMPLATE,
        executable: true,
    },
    ScaffoldFile {
        rel: "ops/bootstrap/bootstrap.sql",
        contents: BOOTSTRAP_SQL_TEMPLATE,
        executable: false,
    },
];

/// Write every file the compose stack needs under `root`, leaving any that
/// already exist untouched. Returns the paths actually created.
///
/// Scaffolding the compose file alone is not enough, and the gap is silent
/// rather than loud — see [`PG_INIT_TEMPLATE`]. Both scaffolders call this so
/// neither can write a partial install.
pub fn scaffold_install(root: &Path) -> Result<Vec<PathBuf>> {
    let mut created = Vec::new();
    for file in SCAFFOLD {
        let path = root.join(file.rel);
        if path.exists() {
            continue;
        }
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create {}", parent.display()))?;
        }
        fs::write(&path, file.contents)
            .with_context(|| format!("Failed to write {}", path.display()))?;
        if file.executable {
            make_executable(&path)?;
        }
        created.push(path);
    }
    Ok(created)
}

/// Report which of the compose stack's files are missing from `root`.
///
/// Used before invoking compose, because Docker fabricates an empty directory
/// for a missing bind-mount source instead of refusing — so without this the
/// stack comes up and fails later, somewhere unrelated to the cause.
pub fn missing_scaffold_files(root: &Path) -> Vec<&'static str> {
    SCAFFOLD
        .iter()
        .filter(|f| !root.join(f.rel).is_file())
        .map(|f| f.rel)
        .collect()
}

#[cfg(unix)]
fn make_executable(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o755))
        .with_context(|| format!("Failed to set permissions on {}", path.display()))
}

#[cfg(not(unix))]
fn make_executable(_path: &Path) -> Result<()> {
    // Windows has no executable bit; Docker applies its own mode to the mount.
    Ok(())
}

/// True when the compose file's `build:` context resolves — that is, when this
/// install carries the engine source tree.
///
/// `odal up` used to decide whether to build from the profile *kind*. That asks
/// "is this a production deployment" and was being read as "does this operator
/// have the engine source". The two coincide only for someone developing the
/// engine: every self-hosted node is reached over localhost and therefore
/// infers `dev`, so every packaged install was forced down a build path with no
/// source to build from.
pub fn source_tree_present(compose_file: &Path) -> bool {
    // The compose file lives at `<root>/docker/<file>`, and its `build.context`
    // is `../..` from there, with `dpp-engine/docker/node.Dockerfile` inside.
    compose_file
        .parent()
        .and_then(Path::parent)
        .and_then(Path::parent)
        .is_some_and(|context| {
            context
                .join("dpp-engine")
                .join("docker")
                .join("node.Dockerfile")
                .is_file()
        })
}

/// Resolve the full-stack compose file at the install root, erroring helpfully
/// if it is absent.
pub fn compose_file() -> Result<PathBuf> {
    let root = find_install_root()?;
    let path = root.join("docker").join(COMPOSE_FILE);
    if !path.exists() {
        anyhow::bail!(
            "expected {} at the install root, but it was not found.\n\
             Run `odal` and choose Setup / Reconfigure to scaffold it.",
            path.display()
        );
    }
    Ok(path)
}

/// Production preflight: a prod stack must not boot on missing or dev-default
/// secrets. Verifies the deployment `.env` (next to the compose file's parent)
/// has every required secret set to a non-default value.
pub fn preflight_prod_env(compose_file: &Path) -> Result<()> {
    // compose lives at <root>/docker/<file>; the deployment .env is at <root>/.env.
    let root = compose_file
        .parent()
        .and_then(|p| p.parent())
        .unwrap_or_else(|| Path::new("."));
    let env_path = root.join(".env");

    const REQUIRED: &[&str] = &[
        "DATABASE_POSTGRES_PASS",
        "DATABASE_APP_PASS",
        "KEY_STORE_PASSPHRASE",
        "DID_WEB_BASE_URL",
        "ADMIN_USERNAME",
        "ADMIN_PASSWORD",
    ];
    const INSECURE_DEFAULTS: &[&str] = &[
        "dev_only_password",
        "change_me_in_env",
        "dev-passphrase-change-in-prod",
        "admin",
    ];

    if !env_path.exists() {
        anyhow::bail!(
            "no .env found at {} — a production node needs its secrets set first.\n\
             Required: {}",
            env_path.display(),
            REQUIRED.join(", ")
        );
    }

    let vars = parse_env(&fs::read_to_string(&env_path)?);
    let mut problems = Vec::new();
    for key in REQUIRED {
        match vars.get(*key).map(String::as_str) {
            None | Some("") => problems.push(format!("  • {key} is missing or empty")),
            Some(v) if INSECURE_DEFAULTS.contains(&v) => {
                problems.push(format!("  • {key} is still a dev default ({v})"))
            }
            _ => {}
        }
    }
    if !problems.is_empty() {
        anyhow::bail!(
            "production .env at {} is not safe to start:\n{}\nEdit it and try again.",
            env_path.display(),
            problems.join("\n")
        );
    }
    Ok(())
}

/// Read a single variable from the deployment `.env` at the install root.
/// Returns `None` if the install root, the file, or the key is absent.
pub fn deployment_env_var(key: &str) -> Option<String> {
    let root = find_install_root().ok()?;
    let content = fs::read_to_string(root.join(".env")).ok()?;
    parse_env(&content).get(key).cloned()
}

/// Minimal `.env` parser: `KEY=VALUE` per line, ignoring blanks and `#` comments,
/// trimming whitespace and a single pair of surrounding quotes.
fn parse_env(content: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            map.insert(k.trim().to_owned(), parse_env_value(v));
        }
    }
    map
}

/// Read one `.env` value the way Docker Compose reads it.
///
/// Both parsers read the same file — `odal` for the preflight and the port
/// lookups, Compose via `--env-file` — so disagreeing about what a line means
/// would be worse than either rule on its own. These are Compose's, confirmed
/// by running it against a file containing each case:
///
/// | line                | value             |
/// |---------------------|-------------------|
/// | `X=value  # note`   | `value`           |
/// | `X=value#nospace`   | `value#nospace`   |
/// | `X="value # inside"`| `value # inside`  |
/// | `X=p@ss#word`       | `p@ss#word`       |
///
/// Only whole-line comments were handled before, so a trailing one became part
/// of the value. That silently defeated `preflight_prod_env`: `ADMIN_USERNAME=admin
/// # the operator login` parsed as `admin  # the operator login`, which is not
/// the string `admin` the insecure-default check looks for, so the guard passed
/// a credential it exists to reject.
///
/// The `#`-needs-preceding-whitespace rule is what keeps a password containing
/// `#` intact — truncating at the first `#` would replace one silent failure
/// with another.
fn parse_env_value(raw: &str) -> String {
    let v = raw.trim_start();

    // A quoted value ends at its closing quote; anything after it is a comment,
    // and a `#` inside the quotes is part of the value.
    for quote in ['"', '\''] {
        if let Some(rest) = v.strip_prefix(quote)
            && let Some(end) = rest.find(quote)
        {
            return rest[..end].to_owned();
        }
    }

    // Unquoted: an inline comment is a `#` with whitespace in front of it.
    match v
        .char_indices()
        .find(|&(i, c)| c == '#' && i > 0 && v[..i].ends_with(char::is_whitespace))
    {
        Some((i, _)) => v[..i].trim_end().to_owned(),
        None => v.trim_end().to_owned(),
    }
}

/// Map a network error message to a short display category.
pub fn classify_error(msg: &str) -> &'static str {
    let m = msg.to_lowercase();
    if m.contains("connection refused") || m.contains("actively refused") {
        "not running (connection refused)"
    } else if m.contains("timed out") || m.contains("timeout") {
        "timeout"
    } else if m.contains("dns") || m.contains("no such host") {
        "DNS error"
    } else {
        "unreachable"
    }
}

/// Report service health for the active profile.
///
/// Always probes the node's service trio (vault / identity / resolver) over HTTP
/// so the output is consistent everywhere. For a self-hosted node it also
/// appends the Docker container health that `odal up` manages
/// (postgres/redis/nats, plus node/resolver in prod) — so the operator sees both
/// "is the node serving?" and "are the containers up?". A remote/managed node
/// has no local containers, so only the HTTP trio is shown.
pub async fn action_status(client: &OdalClient, cfg: &Config) -> Result<StatusReport> {
    let probes = http_probes(client, cfg).await?;
    let containers = if cfg.is_localhost() {
        infra_container_status().unwrap_or_default()
    } else {
        Vec::new()
    };
    // The trust posture lives on the authenticated `/node/state`, while the
    // probes above need no credential. `status` must keep answering for a
    // caller who has none, so an unreadable posture is absent, not fatal.
    //
    // Only asked when the vault answered its health probe: `/node/state` is on
    // the same origin, so a vault that did not respond cannot serve it either,
    // and asking anyway spends a second connection timeout to learn nothing.
    let vault_is_up = probes.iter().any(|p| p.name == "vault" && p.status.is_ok());
    let node = if vault_is_up {
        crate::core::onboarding::action_node_state(client, cfg)
            .await
            .ok()
    } else {
        None
    };
    Ok(StatusReport {
        probes,
        containers,
        node,
    })
}

/// Probe the node's HTTP health endpoints (vault / identity / resolver).
async fn http_probes(client: &OdalClient, cfg: &Config) -> Result<Vec<ServiceHealth>> {
    #[allow(clippy::type_complexity)]
    let endpoints: &[(&'static str, fn(&Config) -> String)] = &[
        ("vault", |c| format!("{}/health", c.vault_url)),
        ("identity", |c| format!("{}/health", c.identity_url)),
        ("resolver", |c| format!("{}/health", c.resolver_url)),
    ];

    let mut probes = Vec::with_capacity(endpoints.len());
    for (name, url_fn) in endpoints {
        let url = url_fn(cfg);
        let start = Instant::now();
        let result = client.get_public(&url).await;
        let latency_ms = start.elapsed().as_millis() as u64;

        let status = match result {
            Ok((s, _)) if s.is_success() => ServiceStatus::Ok,
            Ok((s, _)) => ServiceStatus::HttpError(s.as_u16()),
            Err(e) => ServiceStatus::Failed(classify_error(&e.to_string()).to_owned()),
        };
        probes.push(ServiceHealth {
            name: (*name).to_owned(),
            url,
            status,
            latency_ms,
        });
    }

    Ok(probes)
}

/// Report Docker container health for the full-stack compose project.
pub(crate) fn infra_container_status() -> Result<Vec<ContainerHealth>> {
    let compose = compose_file()?;
    let output = compose_command(&compose)
        .args(["ps", "--format", "json"])
        .output()?;
    if !output.status.success() {
        anyhow::bail!(
            "docker compose ps failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    // `docker compose ps --format json` emits one JSON object per line.
    let mut services = Vec::new();
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let v: serde_json::Value = serde_json::from_str(line)?;
        let name = v.get("Service").and_then(|s| s.as_str()).unwrap_or("?");
        let container = v.get("Name").and_then(|s| s.as_str()).unwrap_or("");
        let state = v.get("State").and_then(|s| s.as_str()).unwrap_or("");
        let health = v.get("Health").and_then(|s| s.as_str()).unwrap_or("");
        let status_text = v.get("Status").and_then(|s| s.as_str()).unwrap_or(state);

        // Healthy, or running with no healthcheck defined, counts as OK.
        let status = if health == "healthy" || (health.is_empty() && state == "running") {
            ServiceStatus::Ok
        } else {
            ServiceStatus::Failed(status_text.to_owned())
        };
        services.push(ContainerHealth {
            service: name.to_owned(),
            container: container.to_owned(),
            status,
        });
    }

    if services.is_empty() {
        services.push(ContainerHealth {
            service: "infrastructure".to_owned(),
            container: String::new(),
            status: ServiceStatus::Failed("not running — run `odal up`".to_owned()),
        });
    }

    Ok(services)
}

/// Build a `docker compose -f <file>` command.
///
/// The deployment `.env` lives at the install root (the parent of `docker/`),
/// but `${VAR}` interpolation defaults to looking in the project directory,
/// which Compose derives from the compose file's own directory (`docker/`). We
/// point interpolation at the real `.env` with `--env-file` rather than
/// overriding `--project-directory`: the latter would also re-root the relative
/// bind mounts (`../ops/bootstrap/pg-init.sh` and its SQL), which resolve
/// against the compose file's dir (`docker/`), not the install root.
/// `--env-file` fixes `.env` discovery without touching mount resolution.
fn compose_command(compose_file: &Path) -> std::process::Command {
    let mut cmd = std::process::Command::new("docker");
    cmd.args(["compose", "-f"]).arg(compose_file);
    if let Some(root) = compose_file.parent().and_then(|p| p.parent()) {
        let env_path = root.join(".env");
        if env_path.exists() {
            cmd.args(["--env-file"]).arg(env_path);
        }
    }
    cmd
}

/// Start services via `docker compose up -d`.
///
/// When `build` is set, images are built from source first (`--build`) — used
/// for local self-host from the source tree, where no published node image
/// exists yet. Remote/prod deployments pull the published image instead.
pub async fn action_up(compose_file: &Path, build: bool) -> Result<()> {
    let mut cmd = compose_command(compose_file);
    cmd.args(["up", "-d"]);
    if build {
        cmd.arg("--build");
    }
    let status = cmd.status()?;
    if !status.success() {
        anyhow::bail!(
            "docker compose up failed with exit code: {:?}",
            status.code()
        );
    }
    Ok(())
}

/// Stop services via `docker compose down`.
pub async fn action_down(compose_file: &Path) -> Result<()> {
    let status = compose_command(compose_file).args(["down"]).status()?;
    if !status.success() {
        anyhow::bail!(
            "docker compose down failed with exit code: {:?}",
            status.code()
        );
    }
    Ok(())
}

/// Pull latest images via `docker compose pull`.
pub async fn action_update(compose_file: &Path) -> Result<()> {
    let status = compose_command(compose_file).args(["pull"]).status()?;
    if !status.success() {
        anyhow::bail!(
            "docker compose pull failed with exit code: {:?}",
            status.code()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The compose file bind-mounts the two `ops/bootstrap/` files, and Docker
    /// fabricates an empty directory for a missing mount source instead of
    /// failing. A scaffolder that writes only the compose file therefore
    /// produces an install that starts and then fails at role provisioning.
    #[test]
    fn scaffolding_writes_every_file_the_stack_mounts() {
        let root = tempfile::TempDir::new().unwrap();
        let created = scaffold_install(root.path()).unwrap();

        assert_eq!(created.len(), SCAFFOLD.len());
        for file in SCAFFOLD {
            let path = root.path().join(file.rel);
            assert!(path.is_file(), "{} was not written", file.rel);
            assert!(path.metadata().unwrap().len() > 0, "{} is empty", file.rel);
        }
        assert!(missing_scaffold_files(root.path()).is_empty());
    }

    /// Re-running `odal init` on a configured install must not overwrite an
    /// operator's edited compose file.
    #[test]
    fn scaffolding_leaves_existing_files_alone() {
        let root = tempfile::TempDir::new().unwrap();
        scaffold_install(root.path()).unwrap();

        let compose = root.path().join("docker").join(COMPOSE_FILE);
        std::fs::write(&compose, "# edited by the operator\n").unwrap();

        assert!(scaffold_install(root.path()).unwrap().is_empty());
        assert_eq!(
            std::fs::read_to_string(&compose).unwrap(),
            "# edited by the operator\n"
        );
    }

    /// What `odal up` checks before invoking compose. A mount source that is a
    /// *directory* is exactly what Docker leaves behind, so it must not count
    /// as present.
    #[test]
    fn a_fabricated_directory_does_not_count_as_a_scaffolded_file() {
        let root = tempfile::TempDir::new().unwrap();
        scaffold_install(root.path()).unwrap();

        let hook = root.path().join("ops/bootstrap/pg-init.sh");
        std::fs::remove_file(&hook).unwrap();
        std::fs::create_dir_all(&hook).unwrap();

        assert_eq!(
            missing_scaffold_files(root.path()),
            vec!["ops/bootstrap/pg-init.sh"]
        );
    }

    /// Whether to build is decided by the source tree being present, not by the
    /// profile kind — every self-hosted node is on localhost and so infers
    /// `dev`, which used to force a source build on installs with no source.
    #[test]
    fn source_tree_is_detected_from_the_build_context() {
        let parent = tempfile::TempDir::new().unwrap();

        // A packaged install: <root>/docker/docker-compose.yml, no sibling source.
        let packaged = parent.path().join("install");
        scaffold_install(&packaged).unwrap();
        let compose = packaged.join("docker").join(COMPOSE_FILE);
        assert!(!source_tree_present(&compose));

        // Now place the Dockerfile where the compose `build.context` expects it:
        // `../..` from the compose file's directory, then dpp-engine/docker/.
        let dockerfile = parent
            .path()
            .join("dpp-engine")
            .join("docker")
            .join("node.Dockerfile");
        std::fs::create_dir_all(dockerfile.parent().unwrap()).unwrap();
        std::fs::write(&dockerfile, "FROM scratch\n").unwrap();
        assert!(source_tree_present(&compose));
    }
    #[test]
    fn compose_file_is_the_full_stack() {
        assert_eq!(COMPOSE_FILE, "docker-compose.yml");
    }

    #[test]
    fn parse_env_handles_comments_quotes_and_blanks() {
        let content = "\
            # a comment\n\
            \n\
            DATABASE_APP_PASS=secret123\n\
            DID_WEB_BASE_URL=\"https://acme.example\"\n\
            ADMIN_USERNAME='admin'\n\
            EMPTY=\n";
        let vars = parse_env(content);
        assert_eq!(vars.get("DATABASE_APP_PASS").unwrap(), "secret123");
        assert_eq!(
            vars.get("DID_WEB_BASE_URL").unwrap(),
            "https://acme.example"
        );
        assert_eq!(vars.get("ADMIN_USERNAME").unwrap(), "admin");
        assert_eq!(vars.get("EMPTY").unwrap(), "");
        assert!(!vars.contains_key("# a comment"));
    }

    /// The cases were taken from running `docker compose --env-file` against a
    /// file containing each one, so this pins agreement with the other parser
    /// that reads the same file rather than a rule invented here.
    #[test]
    fn env_values_are_read_the_way_compose_reads_them() {
        let vars = parse_env(
            "SPACED=value  # trailing comment\n\
             TIGHT=value#nospace\n\
             QUOTED=\"value # inside quotes\"\n\
             SINGLE='value # inside singles'\n\
             PASSWORD=p@ss#word\n\
             TRAILING_WS=value   \n",
        );
        assert_eq!(vars["SPACED"], "value");
        assert_eq!(vars["TIGHT"], "value#nospace");
        assert_eq!(vars["QUOTED"], "value # inside quotes");
        assert_eq!(vars["SINGLE"], "value # inside singles");
        // Truncating at the first `#` would corrupt this, which is why the rule
        // requires whitespace in front of it.
        assert_eq!(vars["PASSWORD"], "p@ss#word");
        assert_eq!(vars["TRAILING_WS"], "value");
    }

    /// The reason this matters: an inline comment used to become part of the
    /// value, so the string the insecure-default check looks for never matched
    /// and a `prod` stack booted on the credential the guard exists to refuse.
    #[test]
    fn an_inline_comment_no_longer_hides_an_insecure_default() {
        let vars = parse_env("ADMIN_USERNAME=admin  # the operator login\n");
        assert_eq!(vars["ADMIN_USERNAME"], "admin");
    }
}
