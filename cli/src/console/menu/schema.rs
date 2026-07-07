//! Schema menu: check the local schema version against upstream.

use anyhow::Result;
use inquire::{InquireError, Select};

use crate::{core::schema::action_schema_check, stateless::render::render_schema_check};

use super::{MenuItem, client, hint, print_err};

const SCHEMA: &[MenuItem] = &[
    MenuItem::new(
        "Check for updates",
        "compare local schema version with upstream",
    ),
    MenuItem::new("← Back", ""),
];

pub(super) async fn schema() -> Result<()> {
    loop {
        match Select::new("Schema — what would you like to do?", SCHEMA.to_vec())
            .with_help_message("↑↓ to move · ⏎ select · Esc to go back")
            .prompt()
        {
            Ok(item) => match item.label {
                "Check for updates" => match client() {
                    Ok((client, cfg)) => match action_schema_check(&client, &cfg).await {
                        Ok(result) => {
                            println!();
                            render_schema_check(&result);
                            hint("odal schema check");
                            println!();
                        }
                        Err(e) => print_err(e),
                    },
                    Err(e) => print_err(e),
                },
                "← Back" => break,
                _ => {}
            },
            Err(InquireError::OperationCanceled | InquireError::OperationInterrupted) => break,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}
