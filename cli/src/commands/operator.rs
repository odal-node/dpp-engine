//! `odal operator show | set` — view and update the operator's configuration.

use anyhow::{Result, anyhow, bail};
use dpp_domain::{OperatorRole, ResponsibilityBasis};
use dpp_types::operator::OperatorResponsibility;
use serde::{Serialize, de::DeserializeOwned};

use crate::{
    core::{
        onboarding::{action_operator_set, action_operator_show},
        types::OperatorUpdateParams,
    },
    stateless::render::render_operator,
};

pub async fn run_operator_show() -> Result<()> {
    let (client, cfg) = crate::http::load_client()?;
    let v = action_operator_show(&client, &cfg).await?;
    render_operator(&v)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn run_operator_set(
    legal_name: Option<String>,
    trade_name: Option<String>,
    address: Option<String>,
    country: Option<String>,
    contact_email: Option<String>,
    did_web_url: Option<String>,
    retention_policy_days: Option<i64>,
    responsible: (Option<String>, Option<String>, Option<String>),
) -> Result<()> {
    let (role, basis, law) = responsible;
    // Read before the node is reached, so a misspelt role is named here and not
    // as a `400` from a node the caller may not be able to read the reason of.
    let responsibility = responsibility_from(role, basis, law)?;
    let (client, cfg) = crate::http::load_client()?;
    let params = OperatorUpdateParams {
        legal_name,
        trade_name,
        address,
        country,
        contact_email,
        did_web_url,
        retention_policy_days,
        responsibility,
    };
    if params.is_empty() {
        anyhow::bail!("nothing to update — pass at least one field (e.g. --legal-name)");
    }
    action_operator_set(&params, &client, &cfg).await?;
    println!("Operator updated.");
    Ok(())
}

/// The three `--responsible-*` flags as the one statement they make, or `None`
/// when none was given.
///
/// The role and the basis are read as core spells them, from the types the node
/// reads them into, so this keeps no list of its own that could fall behind. The
/// law is one of two flags because a named basis and a cited law are different
/// kinds of answer, and clap has already refused both at once.
fn responsibility_from(
    role: Option<String>,
    basis: Option<String>,
    law: Option<String>,
) -> Result<Option<OperatorResponsibility>> {
    let Some(role) = role else {
        return Ok(None);
    };
    let role: OperatorRole = from_wire(&role, "--responsible-role", OperatorRole::ALL)?;
    let basis = match (basis, law) {
        (Some(basis), None) => {
            from_wire(&basis, "--responsible-basis", &ResponsibilityBasis::all())?
        }
        (None, Some(citation)) if !citation.trim().is_empty() => {
            ResponsibilityBasis::OtherUnionLaw { citation }
        }
        (None, Some(_)) => bail!(
            "--responsible-law is empty: cite the law, for example \"Article 7 of Regulation (EU) 2017/745\""
        ),
        _ => bail!("state the law with --responsible-basis or --responsible-law"),
    };
    Ok(Some(OperatorResponsibility { role, basis }))
}

/// `text` as the wire spelling of a `T`, or an error naming the spellings it can
/// be.
fn from_wire<T: Serialize + DeserializeOwned>(text: &str, flag: &str, known: &[T]) -> Result<T> {
    serde_json::from_value(serde_json::Value::String(text.to_owned())).map_err(|_| {
        let spellings: Vec<String> = known
            .iter()
            .filter_map(|value| match serde_json::to_value(value) {
                Ok(serde_json::Value::String(name)) => Some(name),
                _ => None,
            })
            .collect();
        anyhow!(
            "{flag} takes one of: {} (got `{text}`)",
            spellings.join(", ")
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn some(text: &str) -> Option<String> {
        Some(text.to_owned())
    }

    #[test]
    fn no_flag_states_nothing() {
        assert!(matches!(responsibility_from(None, None, None), Ok(None)));
    }

    #[test]
    fn a_role_and_a_named_basis_are_read_as_core_spells_them() {
        let stated = responsibility_from(some("importer"), some("generalProductSafety"), None)
            .expect("a statement")
            .expect("one was given");
        assert_eq!(stated.role, OperatorRole::Importer);
        assert_eq!(stated.basis, ResponsibilityBasis::GeneralProductSafety);
    }

    #[test]
    fn a_cited_law_is_the_other_union_law_basis() {
        let stated = responsibility_from(
            some("distributor"),
            None,
            some("Article 7 of Regulation (EU) 2017/745"),
        )
        .expect("a statement")
        .expect("one was given");
        assert_eq!(
            stated.basis,
            ResponsibilityBasis::OtherUnionLaw {
                citation: "Article 7 of Regulation (EU) 2017/745".to_owned()
            }
        );
    }

    #[test]
    fn a_misspelt_role_is_named_with_the_spellings_it_could_have_been() {
        let refusal = responsibility_from(some("Importer"), some("generalProductSafety"), None)
            .expect_err("the node spells it importer");
        let sentence = refusal.to_string();
        assert!(
            sentence.contains("--responsible-role") && sentence.contains("importer"),
            "{sentence}"
        );
    }

    /// `otherUnionLaw` is a basis that needs its citation, so naming it with the
    /// flag that takes none is refused and points to the one that does.
    #[test]
    fn the_other_law_cannot_be_named_without_citing_it() {
        let refusal = responsibility_from(some("importer"), some("otherUnionLaw"), None)
            .expect_err("a citation is part of that basis");
        assert!(refusal.to_string().contains("--responsible-basis"));
        assert!(
            responsibility_from(some("importer"), None, some("  ")).is_err(),
            "a blank citation cites nothing"
        );
    }
}
