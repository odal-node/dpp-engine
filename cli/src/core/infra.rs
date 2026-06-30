//! Docker Compose infrastructure actions (up/down/update/status) and install-root discovery.

use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    time::Instant,
};

use anyhow::Result;

use super::types::{ServiceHealth, ServiceStatus, StatusReport};
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
            let v = v.trim();
            let v = v
                .strip_prefix('"')
                .and_then(|s| s.strip_suffix('"'))
                .or_else(|| v.strip_prefix('\'').and_then(|s| s.strip_suffix('\'')))
                .unwrap_or(v);
            map.insert(k.trim().to_owned(), v.to_owned());
        }
    }
    map
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
    let mut services = http_status(client, cfg).await?.services;
    if cfg.is_localhost()
        && let Ok(report) = infra_container_status()
    {
        services.extend(report.services);
    }
    Ok(StatusReport { services })
}

/// Probe the node's HTTP health endpoints (vault / identity / resolver).
async fn http_status(client: &OdalClient, cfg: &Config) -> Result<StatusReport> {
    #[allow(clippy::type_complexity)]
    let endpoints: &[(&'static str, fn(&Config) -> String)] = &[
        ("vault", |c| format!("{}/health", c.vault_url)),
        ("identity", |c| format!("{}/health", c.identity_url)),
        ("resolver", |c| format!("{}/health", c.resolver_url)),
    ];

    let mut services = Vec::with_capacity(endpoints.len());
    for (name, url_fn) in endpoints {
        let url = url_fn(cfg);
        let start = Instant::now();
        let result = client.get_public(&url).await;
        let latency_ms = Some(start.elapsed().as_millis() as u64);

        let status = match result {
            Ok((s, _)) if s.is_success() => ServiceStatus::Ok,
            Ok((s, _)) => ServiceStatus::HttpError(s.as_u16()),
            Err(e) => ServiceStatus::Failed(classify_error(&e.to_string()).to_owned()),
        };
        services.push(ServiceHealth {
            name: (*name).to_owned(),
            url,
            status,
            latency_ms,
        });
    }

    Ok(StatusReport { services })
}

/// Report Docker container health for the full-stack compose project.
pub(crate) fn infra_container_status() -> Result<StatusReport> {
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
        services.push(ServiceHealth {
            name: name.to_owned(),
            url: container.to_owned(),
            status,
            latency_ms: None,
        });
    }

    if services.is_empty() {
        services.push(ServiceHealth {
            name: "infrastructure".to_owned(),
            url: String::new(),
            status: ServiceStatus::Failed("not running — run `odal up`".to_owned()),
            latency_ms: None,
        });
    }

    Ok(StatusReport { services })
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
}
