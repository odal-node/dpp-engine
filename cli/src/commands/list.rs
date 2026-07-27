//! `odal list` — list and search passports.

use anyhow::Result;

use crate::{
    core::{passport::action_list, types::ListParams},
    stateless::render::render_passport_list,
};

/// `odal passport list` — list/search passports without handling any UUID.
pub async fn run_passport_list(
    status: Option<&str>,
    q: Option<&str>,
    facility_id: Option<&str>,
    limit: u32,
    json: bool,
) -> Result<()> {
    let (client, cfg) = crate::http::load_client()?;
    let params = ListParams {
        status: status.map(str::to_owned),
        q: q.map(str::to_owned),
        facility_id: facility_id.map(str::to_owned),
        limit,
        skip: 0,
    };
    let page = action_list(&params, &client, &cfg).await?;
    if json {
        println!("{}", serde_json::to_string_pretty(&page)?);
    } else {
        render_passport_list(&page);
    }
    Ok(())
}
