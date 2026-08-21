//! `odal up` — start the Odal Node Docker services.

use anyhow::{Result, bail};

use crate::{
    config::{Config, EnvKind},
    core::infra::{
        action_up, compose_file, missing_scaffold_files, preflight_prod_env, source_tree_present,
    },
};

pub async fn run_up() -> Result<()> {
    let cfg = Config::load()?;
    let compose = compose_file()?;
    // Production must not boot on missing or dev-default secrets.
    if matches!(cfg.kind, EnvKind::Prod) {
        preflight_prod_env(&compose)?;
    }

    // The compose file bind-mounts the database role-provisioning hook. Docker
    // fabricates an empty directory for a missing mount source rather than
    // failing, so without this check the stack starts, reports success, and the
    // node then retries authentication forever against a role whose password
    // was never set. Refuse up front instead, and say what to do about it.
    let root = compose.parent().and_then(std::path::Path::parent);
    if let Some(root) = root {
        let missing = missing_scaffold_files(root);
        if !missing.is_empty() {
            bail!(
                "this install is missing files the stack needs:\n{}\n\
                 Run `odal init` to scaffold them, then try again.",
                missing
                    .iter()
                    .map(|f| format!("  • {f}"))
                    .collect::<Vec<_>>()
                    .join("\n")
            );
        }
    }

    // Build from source only when this install actually carries it; otherwise
    // use the published image. See `source_tree_present`.
    let build = source_tree_present(&compose);
    println!(
        "Starting Odal Node services ({} · {} env, {})...",
        compose.display(),
        cfg.kind,
        if build {
            "building from source"
        } else {
            "using the published image"
        }
    );
    action_up(&compose, build).await?;
    println!("Services started. Run `odal status` to check health.");
    Ok(())
}
