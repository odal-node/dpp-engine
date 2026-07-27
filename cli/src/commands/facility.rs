//! `odal facility list | add | set-default | remove` — manage facilities
//! (ESPR Annex III) via the node API.

use anyhow::Result;

use crate::core::registry_identity::{
    FacilityCreateParams, action_facility_add, action_facility_list, action_facility_remove,
    action_facility_set_default,
};

pub async fn run_facility_list() -> Result<()> {
    let (client, cfg) = crate::http::load_client()?;
    let facilities = action_facility_list(&client, &cfg).await?;
    if facilities.is_empty() {
        println!("No facilities configured. Add one with `odal facility add`.");
        return Ok(());
    }
    println!(
        "{:<38}  {:<7}  {:<16}  {:<3}  DEFAULT  NAME",
        "ID", "SCHEME", "VALUE", "CC"
    );
    for f in &facilities {
        println!(
            "{:<38}  {:<7}  {:<16}  {:<3}  {:<7}  {}",
            f.id,
            f.scheme,
            f.value,
            f.country,
            if f.is_default { "  *" } else { "" },
            f.name,
        );
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn run_facility_add(
    name: String,
    scheme: String,
    value: String,
    country: String,
    address: Option<String>,
    default: bool,
) -> Result<()> {
    let (client, cfg) = crate::http::load_client()?;
    let f = action_facility_add(
        &FacilityCreateParams {
            name,
            scheme,
            value,
            country,
            address,
            default,
        },
        &client,
        &cfg,
    )
    .await?;
    println!(
        "Added facility {} ({} {}){}",
        f.id,
        f.scheme,
        f.value,
        if f.is_default { " — now default" } else { "" }
    );
    Ok(())
}

pub async fn run_facility_set_default(id: &str) -> Result<()> {
    let (client, cfg) = crate::http::load_client()?;
    action_facility_set_default(id, &client, &cfg).await?;
    println!("Facility {id} is now the default.");
    Ok(())
}

pub async fn run_facility_remove(id: &str) -> Result<()> {
    let (client, cfg) = crate::http::load_client()?;
    action_facility_remove(id, &client, &cfg).await?;
    println!("Facility {id} removed.");
    Ok(())
}
