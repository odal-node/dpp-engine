//! `odal passport transfer …` — hand responsibility for a passport to another
//! economic operator.

use anyhow::Result;

use crate::{
    cli_args::TransferInitiateArgs,
    core::{
        passport::{action_transfer_initiate, action_transfer_resolve},
        types::{TransferInitiateParams, TransferOutcome},
    },
};

pub async fn run_transfer_initiate(args: &TransferInitiateArgs) -> Result<()> {
    let (client, cfg) = crate::http::load_client()?;
    let params = TransferInitiateParams {
        id: args.id.clone(),
        from_did: args.from_did.clone(),
        from_name: args.from_name.clone(),
        from_role: args.from_role.clone(),
        from_country: args.from_country.clone(),
        to_did: args.to_did.clone(),
        to_name: args.to_name.clone(),
        to_role: args.to_role.clone(),
        to_country: args.to_country.clone(),
        reason: args.reason.clone(),
        notes: args.notes.clone(),
    };
    let outcome = action_transfer_initiate(&params, &client, &cfg).await?;
    render(&outcome, &args.id, "Transfer initiated");
    println!(
        "\nThe incoming operator completes it with:\n  odal passport transfer accept {}",
        args.id
    );
    Ok(())
}

pub async fn run_transfer_resolve(id: &str, verb: &str) -> Result<()> {
    let (client, cfg) = crate::http::load_client()?;
    let outcome = action_transfer_resolve(id, verb, &client, &cfg).await?;
    let headline = match verb {
        "accept" => "Transfer accepted",
        "reject" => "Transfer rejected",
        "cancel" => "Transfer cancelled",
        other => other,
    };
    render(&outcome, id, headline);
    Ok(())
}

fn render(outcome: &TransferOutcome, id: &str, headline: &str) {
    println!("{headline}: {id}");
    if let (Some(from), Some(to)) = (&outcome.from, &outcome.to) {
        println!("  {from} → {to}");
    }
    if let Some(reason) = &outcome.reason {
        println!("  Reason: {reason}");
    }
    if let Some(status) = &outcome.status {
        println!("  Chain:  {status}");
    }
}
