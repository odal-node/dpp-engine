//! `odal suspend | archive | history <id>` — passport lifecycle operations.

use anyhow::Result;

use crate::{
    core::{
        passport::{
            Supersession, action_amend, action_archive, action_history, action_supersede,
            action_suspend,
        },
        types::{ArchiveParams, HistoryParams, SuspendParams},
    },
    stateless::render::render_history,
};

/// Report a supersession the same way whichever route produced it.
///
/// The two routes return opposite halves of the pair — `amend` answers with the
/// successor it minted, `supersede` with the predecessor it retired — and an
/// operator who has to remember which is which will eventually act on the wrong
/// id. Naming both, in the same order, every time removes the question.
fn render_supersession(result: &Supersession, verb: &str) {
    println!("Passport {} {verb}.", result.retired);
    println!(
        "  Retired:   {}  (terminal — it accepts no further transitions)",
        result.retired
    );
    println!("  Successor: {}", result.successor);
    println!();
    println!("The retired record keeps its signatures and stays readable, and its public");
    println!("URL keeps serving — a carrier already in the field still resolves.");
}

/// `odal passport amend` — correct a published passport by issuing a successor.
///
/// The patch is read from a file rather than an argument because it is a JSON
/// document: a shell-quoted object is where the quoting mistakes live, and a
/// file is also the thing an operator can keep alongside the change as a record
/// of what was corrected.
///
/// It is parsed here only to fail early and name the file — the node decides
/// what is amendable, and the parsed value is passed through untouched.
pub async fn run_amend(id: &str, patch_file: &str, reason: Option<&str>, json: bool) -> Result<()> {
    let (client, cfg) = crate::http::load_client()?;
    let raw = std::fs::read_to_string(patch_file)
        .map_err(|e| anyhow::anyhow!("Failed to read {patch_file}: {e}"))?;
    let patch: serde_json::Value = serde_json::from_str(&raw)
        .map_err(|e| anyhow::anyhow!("{patch_file} is not valid JSON: {e}"))?;

    let result = action_amend(id, patch, reason, &client, &cfg).await?;
    if json {
        println!(
            "{}",
            serde_json::json!({ "retired": result.retired, "successor": result.successor })
        );
        return Ok(());
    }
    render_supersession(&result, "amended");
    Ok(())
}

/// `odal passport supersede` — retire a passport in favour of one that already
/// exists.
///
/// The sibling of `run_amend` and not a variant of it: amend *mints* the
/// successor, this one *names* an existing passport that must already carry
/// `supersedesId` back to the id being retired. Use it when the replacement was
/// created independently — a newer schema version, an imported record, or a
/// successor issued after a transfer.
pub async fn run_supersede(
    id: &str,
    superseded_by: &str,
    reason: Option<&str>,
    json: bool,
) -> Result<()> {
    let (client, cfg) = crate::http::load_client()?;
    let result = action_supersede(id, superseded_by, reason, &client, &cfg).await?;
    if json {
        println!(
            "{}",
            serde_json::json!({ "retired": result.retired, "successor": result.successor })
        );
        return Ok(());
    }
    render_supersession(&result, "superseded");
    Ok(())
}

pub async fn run_suspend(id: &str) -> Result<()> {
    let (client, cfg) = crate::http::load_client()?;
    action_suspend(&SuspendParams { id: id.to_owned() }, &client, &cfg).await?;
    println!("Passport {id} suspended.");
    Ok(())
}

pub async fn run_archive(id: &str) -> Result<()> {
    let (client, cfg) = crate::http::load_client()?;
    action_archive(&ArchiveParams { id: id.to_owned() }, &client, &cfg).await?;
    println!("Passport {id} archived.");
    Ok(())
}

pub async fn run_history(id: &str) -> Result<()> {
    let (client, cfg) = crate::http::load_client()?;
    let entries = action_history(&HistoryParams { id: id.to_owned() }, &client, &cfg).await?;
    render_history(&entries, id);
    Ok(())
}
