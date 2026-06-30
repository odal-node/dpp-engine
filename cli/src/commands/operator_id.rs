//! `odal operator-id list | add | set-primary | remove` — manage economic-
//! operator identifiers (ESPR Art. 13) via the node API.

use anyhow::Result;

use crate::{
    config::Config,
    core::registry_identity::{
        OperatorIdCreateParams, action_operator_id_add, action_operator_id_list,
        action_operator_id_remove, action_operator_id_set_primary,
    },
    http::OdalClient,
};

pub async fn run_operator_id_list() -> Result<()> {
    let cfg = Config::load()?;
    let client = OdalClient::new(&cfg.api_key);
    let ids = action_operator_id_list(&client, &cfg).await?;
    if ids.is_empty() {
        println!("No operator identifiers configured. Add one with `odal operator-id add`.");
        return Ok(());
    }
    println!("{:<38}  {:<7}  {:<24}  PRIMARY", "ID", "SCHEME", "VALUE");
    for o in &ids {
        println!(
            "{:<38}  {:<7}  {:<24}  {}",
            o.id,
            o.scheme,
            o.value,
            if o.is_primary { "  *" } else { "" },
        );
    }
    Ok(())
}

pub async fn run_operator_id_add(
    scheme: String,
    value: String,
    label: Option<String>,
    primary: bool,
) -> Result<()> {
    let cfg = Config::load()?;
    let client = OdalClient::new(&cfg.api_key);
    let o = action_operator_id_add(
        &OperatorIdCreateParams {
            scheme,
            value,
            label,
            primary,
        },
        &client,
        &cfg,
    )
    .await?;
    println!(
        "Added operator identifier {} ({} {}){}",
        o.id,
        o.scheme,
        o.value,
        if o.is_primary { " — now primary" } else { "" }
    );
    Ok(())
}

pub async fn run_operator_id_set_primary(id: &str) -> Result<()> {
    let cfg = Config::load()?;
    let client = OdalClient::new(&cfg.api_key);
    action_operator_id_set_primary(id, &client, &cfg).await?;
    println!("Operator identifier {id} is now primary.");
    Ok(())
}

pub async fn run_operator_id_remove(id: &str) -> Result<()> {
    let cfg = Config::load()?;
    let client = OdalClient::new(&cfg.api_key);
    action_operator_id_remove(id, &client, &cfg).await?;
    println!("Operator identifier {id} removed.");
    Ok(())
}
