//! `odal bootstrap` — onboard the operator and mint the first API key (scripting/CI).
//!
//! All fields must be provided via flags or environment variables.
//! Interactive operators should run `odal` instead.

use anyhow::{Result, bail};
use reqwest::StatusCode;

use crate::{
    config::Config,
    core::{
        onboarding::{NodeStateRejected, action_bootstrap, action_node_state},
        types::BootstrapParams,
    },
    http::local_admin_client,
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
    let admin = local_admin_client(&cfg.vault_url, &user, &pass)?;

    // Idempotency guard: refuse to re-bootstrap a node that is already claimed.
    let state = action_node_state(&admin, &cfg).await.map_err(|err| {
        if credential_refused(&err) {
            err.context(
                "the node refused the admin credential — check ADMIN_USERNAME and ADMIN_PASSWORD against the node's",
            )
        } else {
            err.context("could not reach the node to check its setup state — is it running? (`odal up`)")
        }
    })?;
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

/// Whether the node answered and turned the admin credential down. A node that
/// did not answer at all carries no status, so it is not this.
fn credential_refused(err: &anyhow::Error) -> bool {
    err.downcast_ref::<NodeStateRejected>()
        .is_some_and(|rejected| {
            rejected.status == StatusCode::UNAUTHORIZED || rejected.status == StatusCode::FORBIDDEN
        })
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
