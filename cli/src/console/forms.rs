//! `inquire` prompt forms for the interactive console.

use anyhow::Result;
use inquire::Text;

use super::validators::{Required, valid_country, valid_email, valid_optional_url};
use crate::core::types::BootstrapParams;

/// Collect operator identity fields via `inquire` prompts. Used only by the
/// console's guided setup; the stateless `odal bootstrap` builds
/// `BootstrapParams` directly from flags/env.
pub fn prompt_bootstrap_params() -> Result<BootstrapParams> {
    println!("Operator onboarding — fill in your organisation's details.\n");

    let legal_name = Text::new("Legal name:")
        .with_validator(Required("Legal name"))
        .prompt()?;
    let country = Text::new("Country (ISO 3166-1 alpha-2, e.g. DE):")
        .with_validator(valid_country)
        .prompt()
        .map(|s| s.trim().to_ascii_uppercase())?;
    let address = Text::new("Registered address:")
        .with_validator(Required("Registered address"))
        .prompt()?;
    let contact_email = Text::new("Contact email:")
        .with_validator(valid_email)
        .prompt()?;
    let did_web_url = {
        let s = Text::new("did:web URL:")
            .with_help_message("Optional — press Enter to skip")
            .with_validator(valid_optional_url)
            .prompt()?;
        if s.trim().is_empty() {
            None
        } else {
            Some(s.trim().to_owned())
        }
    };

    Ok(BootstrapParams {
        legal_name: Some(legal_name),
        country: Some(country),
        address: Some(address),
        contact_email: Some(contact_email),
        did_web_url,
    })
}
