//! Guided first-run setup flow for the interactive console.

use std::{fs, time::Duration};

use anyhow::Result;
use console::style;
use inquire::{Confirm, Password, Text};
use tokio::time::sleep;

use crate::{
    config::{Config, EnvKind},
    core::{
        infra::{
            COMPOSE_FILE, COMPOSE_TEMPLATE, action_up, deployment_env_var, find_install_root,
            infra_container_status, preflight_prod_env,
        },
        onboarding::{action_bootstrap, action_node_state},
        types::ServiceStatus,
    },
    http::OdalClient,
};

use super::forms::prompt_bootstrap_params;

fn section(title: &str) {
    println!("\n  {} {}\n", style("──").dim(), style(title).bold());
}

// ── Step 1: Connect ───────────────────────────────────────────────────────────

fn step_connect() -> Result<()> {
    section("Connect");

    // The local node's URLs are determined by its `.env` (NODE_PORT /
    // RESOLVER_PORT) — there's nothing to ask the operator. We still write the
    // config so the rest of the CLI has a target to talk to; remote nodes are
    // configured separately via `odal profile create --vault-url …`.
    let mut cfg = Config::load().unwrap_or_default();
    let (vault, identity, resolver) = local_urls();
    cfg.vault_url = vault;
    cfg.identity_url = identity;
    cfg.resolver_url = resolver;
    cfg.kind = EnvKind::infer(&cfg.vault_url);
    cfg.save()?;

    println!(
        "  {} Using local node at {} ({} · {}).",
        style("✓").green(),
        style(&cfg.vault_url).cyan(),
        cfg.name,
        cfg.kind
    );
    Ok(())
}

/// Resolve an admin credential: an exported process env var (CI) takes
/// precedence, then the deployment `.env` file. `None` only if neither has it.
fn admin_cred(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .filter(|v| !v.is_empty())
        .or_else(|| deployment_env_var(key))
}

/// Build the local node URLs from the deployment `.env` ports, defaulting to the
/// standard 8001 (node: vault + identity) / 8003 (resolver) when unset.
fn local_urls() -> (String, String, String) {
    let node_port = deployment_env_var("NODE_PORT").unwrap_or_else(|| "8001".to_owned());
    let resolver_port = deployment_env_var("RESOLVER_PORT").unwrap_or_else(|| "8003".to_owned());
    (
        format!("http://localhost:{node_port}/vault"),
        format!("http://localhost:{node_port}/identity"),
        format!("http://localhost:{resolver_port}"),
    )
}

// ── Step 2: Infrastructure ────────────────────────────────────────────────────

async fn step_infrastructure(cfg: &Config) -> Result<()> {
    section("Infrastructure");

    // `odal` runs the full self-host stack (node + resolver + infra). Find the
    // compose file in the source tree, or scaffold it for a packaged install.
    let compose_path = match find_install_root() {
        Ok(root) => {
            let p = root.join("docker").join(COMPOSE_FILE);
            if p.exists() {
                println!("  {} Found {}.\n", style("✓").green(), p.display());
            } else {
                fs::write(&p, COMPOSE_TEMPLATE)?;
                println!("  {} Scaffolded {}.\n", style("✓").green(), p.display());
            }
            p
        }
        Err(_) => {
            let docker_dir = std::env::current_dir()?.join("docker");
            if !docker_dir.exists() {
                fs::create_dir_all(&docker_dir)?;
            }
            let p = docker_dir.join(COMPOSE_FILE);
            fs::write(&p, COMPOSE_TEMPLATE)?;
            println!("  {} Scaffolded {}.\n", style("✓").green(), p.display());
            p
        }
    };

    // The node container reads its secrets from the deployment `.env`. Confirm
    // it's there, or list what it must contain.
    if deployment_env_var("ADMIN_USERNAME").is_some() {
        println!(
            "  {} Found .env with your node configuration.\n",
            style("✓").green()
        );
    } else {
        println!(
            "  Create a {} file in your deployment root with these variables:\n",
            style(".env").cyan()
        );
        for var in &[
            "DATABASE_POSTGRES_PASS",
            "DATABASE_APP_PASS",
            "KEY_STORE_PASSPHRASE",
            "ADMIN_USERNAME",
            "ADMIN_PASSWORD",
        ] {
            println!("    {}", style(var).dim());
        }
        println!(
            "    {}  (e.g. https://your-domain.example)",
            style("DID_WEB_BASE_URL").dim()
        );
        println!();
    }

    // Local self-host builds the node image from source the first time.
    let build = matches!(cfg.kind, EnvKind::Dev);
    let start_now = Confirm::new(if build {
        "Build and start services now?"
    } else {
        "Start services now?"
    })
    .with_default(true)
    .with_help_message(if build {
        "Builds the node image from source — the first run can take a few minutes"
    } else {
        "Requires Docker and a .env file"
    })
    .prompt()?;

    if !start_now {
        println!(
            "\n  {} Run {} when ready, then return here to continue.\n",
            style("ℹ").cyan(),
            style("odal up").cyan()
        );
        return Ok(());
    }

    if matches!(cfg.kind, EnvKind::Prod)
        && let Err(e) = preflight_prod_env(&compose_path)
    {
        println!("\n  {} {}\n", style("⚠").yellow(), e);
        return Ok(());
    }

    println!(
        "\n  {}\n",
        if build {
            "Building and starting services (first run may take a few minutes)..."
        } else {
            "Starting services..."
        }
    );
    action_up(&compose_path, build).await?;

    println!(
        "\n  {} Services started. Waiting for health...",
        style("✓").green()
    );
    if wait_for_healthy().await {
        println!("  {} All services healthy.\n", style("✓").green());
    } else {
        println!(
            "  {} Services are still starting — check with {} before proceeding.\n",
            style("⚠").yellow(),
            style("odal status").cyan()
        );
    }

    Ok(())
}

async fn wait_for_healthy() -> bool {
    // Wait on the compose containers (postgres/nats/node/…) reaching health.
    // A fresh node runs DB migrations on first boot, so allow generous time.
    for _ in 0..60 {
        sleep(Duration::from_secs(2)).await;
        if let Ok(report) = infra_container_status()
            && !report.services.is_empty()
            && report
                .services
                .iter()
                .all(|s| matches!(s.status, ServiceStatus::Ok))
        {
            return true;
        }
    }
    false
}

// ── Step 3: Onboard ───────────────────────────────────────────────────────────

async fn step_onboard(cfg: &mut Config) -> Result<()> {
    section("Onboard");

    // The admin credentials authenticate the one-time bootstrap (the node's
    // local-admin auth that mints the first API key). They already live in the
    // deployment `.env`, so read them from there rather than asking the operator
    // to retype them. Prompt only as a fallback — e.g. a remote node with no
    // local `.env`.
    let env_user = admin_cred("ADMIN_USERNAME");
    let env_pass = admin_cred("ADMIN_PASSWORD");
    if env_user.is_some() && env_pass.is_some() {
        println!(
            "  {} Using admin credentials from .env.\n",
            style("✓").green()
        );
    }

    let user = match env_user {
        Some(v) => v,
        None => Text::new("Admin username:")
            .with_default("admin")
            .prompt()?,
    };
    let pass = match env_pass {
        Some(v) => v,
        None => Password::new("Admin password:")
            .without_confirmation()
            .prompt()?,
    };

    let admin = OdalClient::with_local_admin(&user, &pass);

    // Idempotency: if the node is already claimed, don't mint a second key —
    // offer to connect this machine with an existing key instead.
    let state = action_node_state(&admin, cfg).await?;
    if state.bootstrapped {
        println!(
            "  {} This node is already set up. Paste an existing API key to connect this\n     machine, or leave blank to skip and add one later from the API keys menu.\n",
            style("ℹ").cyan()
        );
        let key = Password::new("API key:")
            .without_confirmation()
            .with_help_message("Leave blank to skip")
            .prompt()?;
        if !key.trim().is_empty() {
            cfg.api_key = key.trim().to_owned();
            cfg.save()?;
            println!("  {} Connected.\n", style("✓").green());
        }
        return Ok(());
    }

    let params = prompt_bootstrap_params()?;
    let result = action_bootstrap(&params, &admin, cfg).await?;

    cfg.api_key = result.api_key.clone();
    cfg.save()?;

    println!();
    println!(
        "  {}  API key (shown once — save it somewhere safe):\n",
        style("⚠").yellow().bold()
    );
    println!("      {}\n", style(&result.api_key).cyan().bold());

    Ok(())
}

// ── Entry point ───────────────────────────────────────────────────────────────

pub async fn run_setup() -> Result<()> {
    println!();
    println!(
        "  {} {}  {}",
        style("⬢").cyan().bold(),
        style("Odal Node — Setup").bold(),
        style(env!("CARGO_PKG_VERSION")).dim()
    );
    println!(
        "\n  {}\n",
        style("Guided setup: connect → infrastructure → onboard.").dim()
    );

    step_connect()?;

    let cfg = Config::load()?;
    if cfg.is_localhost() {
        step_infrastructure(&cfg).await?;
    }

    let mut cfg = Config::load()?;
    step_onboard(&mut cfg).await?;

    println!(
        "  {} Setup complete. Welcome to Odal Node.\n",
        style("✓").green().bold()
    );
    Ok(())
}
