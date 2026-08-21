//! `odal whoami` — what the presented credential actually is.

use anyhow::Result;

use crate::{core::onboarding::action_whoami, stateless::render::render_whoami};

/// `odal whoami` — report the caller's own identity and scope.
///
/// The one authenticated route a `read`-scoped credential can always reach:
/// `odal key list` requires `admin`, so without this a least-privilege key has
/// no way to discover that it is read-only short of having a write rejected.
pub async fn run_whoami() -> Result<()> {
    let (client, cfg) = crate::http::load_client()?;
    let who = action_whoami(&client, &cfg).await?;
    render_whoami(&who);
    Ok(())
}
