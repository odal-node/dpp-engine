//! `odal operator show | set` — view and update the operator's configuration.

use anyhow::Result;

use crate::{
    core::{
        onboarding::{action_operator_set, action_operator_show},
        types::OperatorUpdateParams,
    },
    stateless::render::render_operator,
};

pub async fn run_operator_show() -> Result<()> {
    let (client, cfg) = crate::http::load_client()?;
    let v = action_operator_show(&client, &cfg).await?;
    render_operator(&v)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn run_operator_set(
    legal_name: Option<String>,
    trade_name: Option<String>,
    address: Option<String>,
    country: Option<String>,
    contact_email: Option<String>,
    did_web_url: Option<String>,
    retention_policy_days: Option<i64>,
) -> Result<()> {
    let (client, cfg) = crate::http::load_client()?;
    let params = OperatorUpdateParams {
        legal_name,
        trade_name,
        address,
        country,
        contact_email,
        did_web_url,
        retention_policy_days,
    };
    if params.is_empty() {
        anyhow::bail!("nothing to update — pass at least one field (e.g. --legal-name)");
    }
    action_operator_set(&params, &client, &cfg).await?;
    println!("Operator updated.");
    Ok(())
}
