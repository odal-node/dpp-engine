//! `odal operator-id list | add | set-primary | remove` — manage economic-
//! operator identifiers (ESPR Art. 13) via the node API.

use anyhow::Result;

use crate::core::registry_identity::{
    OperatorIdCreateParams, action_operator_id_add, action_operator_id_list,
    action_operator_id_remove, action_operator_id_set_primary,
};

pub async fn run_operator_id_list() -> Result<()> {
    let (client, cfg) = crate::http::load_client()?;
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
    let (client, cfg) = crate::http::load_client()?;
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
    let (client, cfg) = crate::http::load_client()?;
    action_operator_id_set_primary(id, &client, &cfg).await?;
    println!("Operator identifier {id} is now primary.");
    Ok(())
}

pub async fn run_operator_id_remove(id: &str) -> Result<()> {
    let (client, cfg) = crate::http::load_client()?;
    action_operator_id_remove(id, &client, &cfg).await?;
    println!("Operator identifier {id} removed.");
    Ok(())
}
