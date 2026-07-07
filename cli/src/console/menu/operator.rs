//! Operator menu: view and edit the operator configuration.

use anyhow::Result;
use console::style;
use inquire::{InquireError, Select, Text};

use crate::{
    core::{
        onboarding::{action_operator_set, action_operator_show},
        types::OperatorUpdateParams,
    },
    stateless::render::render_operator,
};

use super::super::validators::{
    valid_optional_country, valid_optional_days, valid_optional_email, valid_optional_url,
};
use super::{MenuItem, ask, client, hint, print_err, skip_msg};

const OPERATOR: &[MenuItem] = &[
    MenuItem::new("View configuration", "show current operator details"),
    MenuItem::new(
        "Edit configuration",
        "update legal name, country, contact, etc.",
    ),
    MenuItem::new("← Back", ""),
];

pub(super) async fn operator() -> Result<()> {
    loop {
        match Select::new("Operator — what would you like to do?", OPERATOR.to_vec())
            .with_help_message("↑↓ to move · ⏎ select · Esc to go back")
            .prompt()
        {
            Ok(item) => match item.label {
                "View configuration" => match client() {
                    Ok((client, cfg)) => match action_operator_show(&client, &cfg).await {
                        Ok(v) => {
                            println!();
                            if let Err(e) = render_operator(&v) {
                                print_err(e);
                            } else {
                                hint("odal operator show");
                                println!();
                            }
                        }
                        Err(e) => print_err(e),
                    },
                    Err(e) => print_err(e),
                },
                "Edit configuration" => {
                    println!(
                        "\n  {} Leave fields blank to keep the current value.\n",
                        style("ℹ").cyan()
                    );

                    let legal_name = match ask(Text::new("Legal name:")
                        .with_help_message(skip_msg())
                        .prompt())?
                    {
                        Some(s) if !s.trim().is_empty() => Some(s.trim().to_owned()),
                        Some(_) => None,
                        None => continue,
                    };
                    let trade_name = match ask(Text::new("Trade name:")
                        .with_help_message(skip_msg())
                        .prompt())?
                    {
                        Some(s) if !s.trim().is_empty() => Some(s.trim().to_owned()),
                        Some(_) => None,
                        None => continue,
                    };
                    let address = match ask(Text::new("Registered address:")
                        .with_help_message(skip_msg())
                        .prompt())?
                    {
                        Some(s) if !s.trim().is_empty() => Some(s.trim().to_owned()),
                        Some(_) => None,
                        None => continue,
                    };
                    let country = match ask(Text::new("Country (ISO 3166-1 alpha-2, e.g. DE):")
                        .with_help_message(skip_msg())
                        .with_validator(valid_optional_country)
                        .prompt())?
                    {
                        Some(s) if !s.trim().is_empty() => Some(s.trim().to_ascii_uppercase()),
                        Some(_) => None,
                        None => continue,
                    };
                    let contact_email = match ask(Text::new("Contact email:")
                        .with_help_message(skip_msg())
                        .with_validator(valid_optional_email)
                        .prompt())?
                    {
                        Some(s) if !s.trim().is_empty() => Some(s.trim().to_owned()),
                        Some(_) => None,
                        None => continue,
                    };
                    let did_web_url = match ask(Text::new("did:web URL:")
                        .with_help_message(skip_msg())
                        .with_validator(valid_optional_url)
                        .prompt())?
                    {
                        Some(s) if !s.trim().is_empty() => Some(s.trim().to_owned()),
                        Some(_) => None,
                        None => continue,
                    };
                    // validator guarantees non-empty input parses successfully
                    let retention_policy_days = match ask(Text::new("Retention policy (days):")
                        .with_help_message(skip_msg())
                        .with_validator(valid_optional_days)
                        .prompt())?
                    {
                        Some(s) if !s.trim().is_empty() => Some(s.trim().parse::<i64>().unwrap()),
                        Some(_) => None,
                        None => continue,
                    };

                    let params = OperatorUpdateParams {
                        legal_name,
                        trade_name,
                        address,
                        country,
                        contact_email,
                        did_web_url,
                        retention_policy_days,
                    };
                    if params.is_empty() {
                        println!(
                            "\n  {} Nothing to update — all fields were left blank.\n",
                            style("ℹ").cyan()
                        );
                        continue;
                    }
                    match client() {
                        Ok((client, cfg)) => {
                            match action_operator_set(&params, &client, &cfg).await {
                                Ok(_) => {
                                    println!("\n  {} Operator updated.", style("✓").green());
                                    hint("odal operator set ...");
                                    println!();
                                }
                                Err(e) => print_err(e),
                            }
                        }
                        Err(e) => print_err(e),
                    }
                }
                "← Back" => break,
                _ => {}
            },
            Err(InquireError::OperationCanceled | InquireError::OperationInterrupted) => break,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}
