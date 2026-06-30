//! `odal profile …` — manage named connection profiles (dev / prod / …).
//!
//! Profiles let one machine hold several node targets side by side without
//! overwriting each other. The active profile is chosen by, in order:
//! `--profile <name>` → `ODAL_PROFILE` → the file's `current_profile` →
//! `default`. Mirrors `kubectl config` / `aws configure`.

use anyhow::{Result, bail};
use console::style;

use crate::config::{self, EnvKind, Profile};
use crate::credentials;

/// `odal profile list` — show all profiles, marking the active one.
pub fn run_profile_list() -> Result<()> {
    let entries = config::list_profiles()?;
    if entries.is_empty() {
        println!("No profiles configured yet. Run `odal` to set one up, or");
        println!("`odal profile create <name> --vault-url <url>`.");
        return Ok(());
    }
    println!("{:<3} {:<16} {:<6} URL", "", "NAME", "KIND");
    for e in entries {
        let marker = if e.is_active { "*" } else { " " };
        let name = if e.is_active {
            style(&e.name).bold().to_string()
        } else {
            e.name.clone()
        };
        println!(
            "{:<3} {:<16} {:<6} {}",
            marker,
            name,
            e.profile.kind.to_string(),
            e.profile.vault_url,
        );
    }
    Ok(())
}

/// `odal profile show [name]` — print one profile (active if omitted), secret masked.
pub fn run_profile_show(name: Option<String>) -> Result<()> {
    let target = match name {
        Some(n) => n,
        None => config::active_profile_name()?,
    };
    let entry = config::list_profiles()?
        .into_iter()
        .find(|e| e.name == target)
        .ok_or_else(|| anyhow::anyhow!("profile '{target}' not found."))?;
    let p = &entry.profile;
    // Prefer the credentials store; fall back to any legacy inline key still in
    // config.toml (pre-secret-split), so migration is visible rather than "(none)".
    let api_key = credentials::load_key(&target).unwrap_or_else(|| entry.profile.api_key.clone());
    println!(
        "profile      : {}{}",
        target,
        if entry.is_active { " (active)" } else { "" }
    );
    println!("kind         : {}", p.kind);
    println!("vault_url    : {}", p.vault_url);
    println!("identity_url : {}", p.identity_url);
    println!("resolver_url : {}", p.resolver_url);
    println!("api_key      : {}", config::mask_secret(&api_key));
    Ok(())
}

/// `odal profile use <name>` — make `name` the active profile.
pub fn run_profile_use(name: &str) -> Result<()> {
    config::use_profile(name)?;
    println!("{} Active profile is now '{name}'.", style("✓").green());
    Ok(())
}

/// `odal profile create <name>` — add a new profile (refuses overwrite without --force).
pub fn run_profile_create(
    name: &str,
    vault_url: Option<String>,
    kind: Option<String>,
    force: bool,
) -> Result<()> {
    let mut profile = Profile::default();
    if let Some(url) = vault_url {
        profile.vault_url = url;
    }
    profile.kind = match kind.as_deref() {
        Some("dev") => EnvKind::Dev,
        Some("prod") => EnvKind::Prod,
        Some(other) => bail!("unknown kind '{other}' (expected 'dev' or 'prod')"),
        None => EnvKind::infer(&profile.vault_url),
    };
    config::create_profile(name, profile, force)?;
    println!(
        "{} Created profile '{name}'. Switch to it with `odal profile use {name}`.",
        style("✓").green()
    );
    Ok(())
}

/// `odal profile remove <name>` — delete a profile.
pub fn run_profile_remove(name: &str) -> Result<()> {
    config::remove_profile(name)?;
    println!("{} Removed profile '{name}'.", style("✓").green());
    Ok(())
}

/// `odal profile rename <old> <new>` — rename a profile.
pub fn run_profile_rename(old: &str, new: &str) -> Result<()> {
    config::rename_profile(old, new)?;
    println!("{} Renamed profile '{old}' → '{new}'.", style("✓").green());
    Ok(())
}
