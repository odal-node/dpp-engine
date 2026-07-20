//! `odal bootstrap` — onboard the operator and mint the first API key (scripting/CI).
//!
//! All fields must be provided via flags or environment variables.
//! Interactive operators should run `odal` instead.

use anyhow::{Context, Result, bail};

use crate::{
    config::Config,
    core::{
        onboarding::{action_bootstrap, action_node_state},
        types::BootstrapParams,
    },
    http::OdalClient,
    stateless::render::render_bootstrap_result,
};

#[allow(clippy::too_many_arguments)]
pub async fn run_bootstrap(
    legal_name: Option<String>,
    country: Option<String>,
    address: Option<String>,
    contact_email: Option<String>,
    did_web_url: Option<String>,
    admin_user: Option<String>,
    admin_pass: Option<String>,
    force: bool,
) -> Result<()> {
    let mut cfg = Config::load()?;

    let user = from_flag_or_env(admin_user, "ADMIN_USERNAME", "Admin username")?;
    // `--admin-pass -` reads the password from stdin; a literal value warns.
    let admin_pass = crate::credentials::resolve_secret_arg(admin_pass, "set `$ADMIN_PASSWORD`")?;
    let pass = from_flag_or_env(admin_pass, "ADMIN_PASSWORD", "Admin password")?;
    let admin = OdalClient::with_local_admin(&user, &pass);

    // Idempotency guard: refuse to re-bootstrap a node that is already claimed.
    let state = action_node_state(&admin, &cfg).await.context(
        "could not reach the node to check its setup state — is it running? (`odal up`)",
    )?;
    if state.bootstrapped && !force {
        bail!(
            "this node is already bootstrapped (an active API key exists).\n\
             • add another key:      odal key create <name>\n\
             • connect this machine: save an existing key to the active profile\n\
             • re-bootstrap anyway:  re-run with --force (mints an additional key)"
        );
    }

    let params = BootstrapParams {
        legal_name,
        country,
        address,
        contact_email,
        did_web_url,
    };
    let result = action_bootstrap(&params, &admin, &cfg).await?;

    cfg.api_key = result.api_key.clone();
    cfg.save()?;

    // Re-read state so the completeness warning reflects any identity we just set.
    let operator_complete = action_node_state(&admin, &cfg)
        .await
        .map(|s| s.operator_complete)
        .unwrap_or(false);
    render_bootstrap_result(
        &result,
        params.legal_name.as_deref(),
        params.country.as_deref(),
        operator_complete,
    );
    Ok(())
}

fn from_flag_or_env(flag: Option<String>, env_var: &str, what: &str) -> Result<String> {
    if let Some(v) = flag {
        return Ok(v);
    }
    if let Ok(v) = std::env::var(env_var)
        && !v.is_empty()
    {
        return Ok(v);
    }
    anyhow::bail!("{what} is required — set ${env_var} or pass the corresponding flag")
}
