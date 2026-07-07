//! Registry identity menu: dispatch to facilities / operator identifiers.

use anyhow::Result;
use inquire::{InquireError, Select};

use super::MenuItem;
use super::facilities::facilities_menu;
use super::operator_ids::operator_ids_menu;

const REGISTRY_IDENTITY: &[MenuItem] = &[
    MenuItem::new("Facilities", "ESPR Annex III — manufacturing sites"),
    MenuItem::new("Operator identifiers", "ESPR Art. 13 — EORI/VAT/LEI/DUNS"),
    MenuItem::new("← Back", ""),
];

pub(super) async fn registry_identity() -> Result<()> {
    loop {
        match Select::new(
            "Registry identity — what would you like to do?",
            REGISTRY_IDENTITY.to_vec(),
        )
        .with_help_message("↑↓ to move · ⏎ select · Esc to go back")
        .prompt()
        {
            Ok(item) => match item.label {
                "Facilities" => facilities_menu().await?,
                "Operator identifiers" => operator_ids_menu().await?,
                "← Back" => break,
                _ => {}
            },
            Err(InquireError::OperationCanceled | InquireError::OperationInterrupted) => break,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}
