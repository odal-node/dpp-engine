//! `odal list` — list and search passports.

use anyhow::Result;

use crate::{
    config::Config,
    core::{passport::action_list, types::ListParams},
    http::OdalClient,
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
    let cfg = Config::load()?;
    let client = OdalClient::new(&cfg.api_key);
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
