//! The responsible operator a passport states under ESPR Annex III point (k),
//! and the one place the statement is put together.
//!
//! Point (k) asks the passport to carry "the name, contact details and unique
//! operator identifier of the economic operator established in the Union
//! responsible for carrying out" the tasks of Art. 4 of Regulation (EU)
//! 2019/1020, Art. 15 of Regulation (EU) 2023/988, or "similar tasks pursuant to
//! other Union law applicable to the product".
//!
//! # What the node knows and what it is told
//!
//! The name, the contact details, the country and the identifier are the
//! operator's own and are held on the node: `operator_config` and the primary
//! operator identifier. The DID is the node's. What the node cannot know is the
//! **role** the operator answers in for the product and the **law** that makes it
//! answerable, and those are stated, once for the node or for one passport on its
//! create request ([`OperatorResponsibility`]).
//!
//! # Never defaulted
//!
//! A statement is made from what was stated or not at all. Core says a guessed
//! basis "is a false claim rather than a missing one", and a published passport is
//! corrected by a successor, not by an edit. So with nothing stated this module
//! answers [`Statement::Missing`], and what a caller does with that is its own
//! rule: create carries on, and publish refuses where the passport obligation is
//! live.
//!
//! # When it is made
//!
//! At create, so a draft shows what it will say, and again at publish, so a draft
//! takes the operator as it stands then and not as it stood when it was created —
//! the same rule the operator identifier follows. What a draft was *told* (the role
//! and basis) is kept across the two; what the node *knows* is read again.

use dpp_domain::{DppError, ResponsibleOperator, ResponsibleOperatorSnapshot};
use dpp_types::{
    STANDALONE_OPERATOR_ID,
    operator::{OperatorConfig, OperatorResponsibility},
};

use super::PassportService;

/// What the node can say about its responsible operator, for one passport.
#[derive(Debug, Clone, PartialEq)]
pub(super) enum Statement {
    /// The statement, complete.
    Made(Box<ResponsibleOperatorSnapshot>),
    /// What is missing for one to be made, each named as the operator would
    /// look for it.
    Missing(Vec<&'static str>),
}

/// What is missing when no role and basis were stated.
pub(super) const NO_RESPONSIBILITY: &str = "responsibility (the role and legal basis)";

/// What is missing for a statement to be made, each named as the operator would
/// look for it. Empty when nothing is.
fn gaps(
    responsibility: Option<&OperatorResponsibility>,
    config: Option<&OperatorConfig>,
) -> Vec<&'static str> {
    let mut missing = Vec::new();
    if responsibility.is_none() {
        missing.push(NO_RESPONSIBILITY);
    }
    match config {
        Some(config) => missing.extend(config_gaps(config)),
        None => missing.push("operator configuration"),
    }
    missing
}

/// The refusal of a statement that was asked for and cannot be made, the same
/// words wherever it is raised: a create, and the dry run that previews one.
pub(super) fn cannot_be_stated(missing: &[&str]) -> DppError {
    DppError::Validation(
        format!(
            "the responsible operator cannot be stated: this node lacks {}",
            missing.join(", ")
        )
        .into(),
    )
}

impl PassportService {
    /// The statement the node makes about its responsible operator.
    ///
    /// `kept` is what this passport was already told, which wins over the node's
    /// default, and `sent` is what a create request just told it, which wins
    /// over both. Only the role and the basis come from either: everything else is
    /// read here, from the node.
    ///
    /// `primary` is the primary operator identifier **as the caller already read
    /// it**, and it is read nowhere else. The passport's own `operatorIdentifier`
    /// is stamped from that same read, so the two cannot name different
    /// identifiers if an admin changes the primary while the node's DID is being
    /// fetched, which is a mismatch a retention-locked passport cannot correct.
    ///
    /// # Errors
    /// The node's DID cannot be read from the identity service. That is not
    /// "nothing was stated": the statement could have been made, and the caller
    /// decides whether it can do without.
    pub(super) async fn responsible_operator_statement(
        &self,
        kept: Option<OperatorResponsibility>,
        sent: Option<&OperatorResponsibility>,
        primary: Option<&(String, String)>,
    ) -> Result<Statement, DppError> {
        let Some(reader) = &self.registry_reader else {
            return Ok(Statement::Missing(vec!["operator configuration"]));
        };
        let config = reader.get(STANDALONE_OPERATOR_ID).await?;

        let responsibility = sent
            .cloned()
            .or(kept)
            .or_else(|| config.as_ref().and_then(|c| c.responsibility.clone()));

        // Everything the statement cannot be made without, named at once, so an
        // operator fixes the lot and not one thing per refusal.
        let missing = gaps(responsibility.as_ref(), config.as_ref());
        let (Some(responsibility), Some(config), true) =
            (responsibility, config, missing.is_empty())
        else {
            return Ok(Statement::Missing(missing));
        };

        let did = self.own_did().await?;
        Ok(Statement::Made(Box::new(assemble(
            &config,
            &responsibility,
            &did,
            primary,
        ))))
    }

    /// Whether a statement sent with a create request can be made, for the dry
    /// run that previews one. The same refusal, in the same words, that create
    /// raises: a preview that passed a body create refuses would send a caller
    /// into a draft that cannot be stored.
    ///
    /// Reads the operator configuration and nothing else. Whether the identity
    /// service can say who the node is is the node's availability and not a fact
    /// about the body, so it is left to create.
    ///
    /// # Errors
    /// [`DppError::Validation`] naming what the node lacks.
    pub async fn check_responsibility_statable(
        &self,
        sent: &OperatorResponsibility,
    ) -> Result<(), DppError> {
        let Some(reader) = &self.registry_reader else {
            return Err(cannot_be_stated(&["operator configuration"]));
        };
        let config = reader.get(STANDALONE_OPERATOR_ID).await?;
        let missing = gaps(Some(sent), config.as_ref());
        if missing.is_empty() {
            Ok(())
        } else {
            Err(cannot_be_stated(&missing))
        }
    }

    /// The node's own DID, from its DID document.
    ///
    /// A failure is [`DppError::Signing`], like every other way the identity
    /// service fails to answer: it is the signer being unable to say who the node
    /// is, a step before it is unable to sign, and publish records both as a
    /// signing failure so an outage reads the same however far the publish got.
    async fn own_did(&self) -> Result<String, DppError> {
        let document = self
            .identity
            .own_did_document()
            .await
            .map_err(|e| DppError::Signing(e.to_string()))?;
        document
            .get("id")
            .and_then(|id| id.as_str())
            .map(str::to_owned)
            .ok_or_else(|| {
                DppError::Signing("identity service's DID document has no \"id\"".into())
            })
    }
}

/// What the operator's configuration lacks that the statement needs: the name
/// and the country are not optional on [`ResponsibleOperator`], and a statement
/// with either blank would say nothing about who is answerable.
fn config_gaps(config: &OperatorConfig) -> Vec<&'static str> {
    let mut gaps = Vec::new();
    if config.legal_name.trim().is_empty() {
        gaps.push("operator legalName");
    }
    if config.country.trim().is_empty() {
        gaps.push("operator country");
    }
    gaps
}

/// Put the statement together from what the node holds and what it was told.
///
/// The contact details are stated when the operator has them, each in its own
/// field, because the four provisions point (k) draws on all ask for a postal
/// address and an electronic means of communication apart from a name. The
/// trade name is stated only when it differs from the legal name, which is what
/// they ask a second name for. The identifier is the primary one with its scheme:
/// a value without its scheme cannot be stated truthfully.
fn assemble(
    config: &OperatorConfig,
    responsibility: &OperatorResponsibility,
    did: &str,
    primary: Option<&(String, String)>,
) -> ResponsibleOperatorSnapshot {
    let stated = |text: &str| (!text.trim().is_empty()).then(|| text.to_owned());
    responsibility.of(ResponsibleOperator {
        did: did.to_owned(),
        name: config.legal_name.clone(),
        role: responsibility.role.clone(),
        eu_operator_id: primary.map(|(_, value)| value.clone()),
        eu_operator_id_scheme: primary.map(|(scheme, _)| scheme.clone()),
        // Not typed here: the legacy pair above carries the scheme, and leaving
        // this unset is what `actor_identifier()` reads it from.
        identifier: None,
        country: config.country.clone(),
        registered_trade_name: config
            .trade_name
            .as_deref()
            .filter(|trade| trade.trim() != config.legal_name.trim())
            .and_then(stated),
        postal_address: stated(&config.address),
        electronic_address: stated(&config.contact_email),
    })
}

#[cfg(test)]
mod tests {
    //! What the statement holds, and what it will not be made without.

    use dpp_domain::{OperatorRole, ResponsibilityBasis};

    use super::*;

    fn configured() -> OperatorConfig {
        let mut config = OperatorConfig::empty(STANDALONE_OPERATOR_ID);
        config.legal_name = "Acme Cells GmbH".into();
        config.trade_name = Some("Acme".into());
        config.address = "Hafenstrasse 1, 20457 Hamburg".into();
        config.country = "DE".into();
        config.contact_email = "compliance@acme.example".into();
        config
    }

    fn manufacturer_under_art_4() -> OperatorResponsibility {
        OperatorResponsibility {
            role: OperatorRole::Manufacturer,
            basis: ResponsibilityBasis::MarketSurveillanceArt4,
        }
    }

    #[test]
    fn the_operator_is_stated_from_what_the_node_holds() {
        let primary = ("lei".to_owned(), "529900T8BM49AURSDO55".to_owned());
        let statement = assemble(
            &configured(),
            &manufacturer_under_art_4(),
            "did:web:acme.example",
            Some(&primary),
        );

        let operator = &statement.operator;
        assert_eq!(operator.did, "did:web:acme.example");
        assert_eq!(operator.name, "Acme Cells GmbH");
        assert_eq!(operator.registered_trade_name.as_deref(), Some("Acme"));
        assert_eq!(operator.country, "DE");
        assert_eq!(
            operator.postal_address.as_deref(),
            Some("Hafenstrasse 1, 20457 Hamburg")
        );
        assert_eq!(
            operator.electronic_address.as_deref(),
            Some("compliance@acme.example")
        );
        assert_eq!(
            operator.eu_operator_id.as_deref(),
            Some("529900T8BM49AURSDO55")
        );
        assert_eq!(operator.eu_operator_id_scheme.as_deref(), Some("lei"));
        assert_eq!(operator.role, OperatorRole::Manufacturer);
        assert_eq!(statement.basis, ResponsibilityBasis::MarketSurveillanceArt4);
    }

    #[test]
    fn a_trade_name_is_stated_only_where_it_differs_from_the_legal_name() {
        let mut config = configured();
        config.trade_name = Some("  Acme Cells GmbH ".into());
        let statement = assemble(
            &config,
            &manufacturer_under_art_4(),
            "did:web:a.example",
            None,
        );
        assert_eq!(statement.operator.registered_trade_name, None);
    }

    #[test]
    fn a_contact_the_operator_has_not_given_is_left_out_and_not_stated_blank() {
        let mut config = configured();
        config.address = "  ".into();
        config.contact_email = String::new();
        let statement = assemble(
            &config,
            &manufacturer_under_art_4(),
            "did:web:a.example",
            None,
        );
        assert_eq!(statement.operator.postal_address, None);
        assert_eq!(statement.operator.electronic_address, None);
    }

    #[test]
    fn an_operator_with_no_identifier_states_none_and_does_not_invent_one() {
        let statement = assemble(
            &configured(),
            &manufacturer_under_art_4(),
            "did:web:a.example",
            None,
        );
        assert_eq!(statement.operator.eu_operator_id, None);
        assert_eq!(statement.operator.eu_operator_id_scheme, None);
    }

    #[test]
    fn a_statement_needs_a_name_and_a_country() {
        assert!(config_gaps(&configured()).is_empty());

        let mut nameless = configured();
        nameless.legal_name = " ".into();
        nameless.country = String::new();
        assert_eq!(
            config_gaps(&nameless),
            vec!["operator legalName", "operator country"]
        );
    }
}
