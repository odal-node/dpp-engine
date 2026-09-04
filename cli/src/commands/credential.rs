//! `odal credential issue` — mint a DPP access credential via the node API.

use anyhow::Result;

use crate::core::credential::{IssueRequest, action_credential_issue};

pub async fn run_credential_issue(req: IssueRequest) -> Result<()> {
    let (client, cfg) = crate::http::load_client()?;
    let issued = action_credential_issue(req, &client, &cfg).await?;

    println!("Issued an access credential.");
    println!("  Holder:      {}", issued.holder);
    println!("  Issuer:      {}", issued.issuer);
    println!("  Valid until: {}", issued.valid_until);
    println!();
    println!("Credential (the holder sends this as the X-DPP-Credential header):");
    println!("  {}", issued.jws);
    println!();
    // Said here rather than only in the API description, because this is where
    // an operator learns it: there is no revoke command to look for later.
    println!("This cannot be withdrawn before it expires — the node publishes no");
    println!("revocation status list. Re-issue a shorter one if it needs replacing.");
    Ok(())
}
