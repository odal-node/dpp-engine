//! `POST /api/v1/credentials` — mint an access credential with this node's key.
//!
//! # What was missing
//!
//! `CREDENTIAL_ISSUERS_SELF=true` made the node trust its own DID and report the
//! credential port `live`, while nothing in the product could produce a
//! credential: no route, no command, and `dpp_vc::sign_access_credential` had
//! zero callers in this repo. The node advertised a capability its operator had
//! no supported way to exercise, and the credential-verified read path could
//! only ever be exercised by a test that hand-rolled the JWS.
//!
//! # Only a legitimate interest, never an authority
//!
//! `dpp-vc` states at the signing helper that issuing is "an **authority's**
//! act, not a node's", and that "a node signing its own access credentials has
//! attested nothing to anyone". That is right about authority roles and wrong
//! about the rest, and the two halves need separating rather than choosing
//! between.
//!
//! An operator naming its own authorised repairer attests something no one else
//! can: membership of that network is a fact the operator alone holds, and no EU
//! register of authorised repairers exists to hold it instead. An operator
//! naming itself a market surveillance authority attests nothing, because the
//! standing it is claiming is conferred by a member state and not by assertion.
//!
//! So this route mints roles in [`Audience::LegitimateInterest`] and refuses the
//! three that map to [`Audience::Authority`]. The mapping is core's
//! (`CredentialRole::audience`), not restated here, so a role added there lands
//! on the correct side of this gate without anything being edited.
//!
//! # Revocation is expiry
//!
//! A credential can declare a W3C status list, and the verifier here is
//! fail-closed about one: a credential naming a list the node cannot fetch is
//! treated as revoked. This node has no status list to name — it fetches them
//! and does not publish one — so a credential minted here carries no
//! `credentialStatus` and cannot be withdrawn before it expires.
//!
//! That makes the lifetime the only control, which is why there is a ceiling on
//! it rather than a free-form date. [`MAX_VALID_DAYS`] is the bound; the default
//! is deliberately shorter. Re-issuing is cheap and a short credential is the
//! thing that limits the damage of one going astray.
//!
//! # A category list is checked before anything is signed
//!
//! An operator that places both EV and LMT batteries can vouch for a repairer
//! of one and not the other, by naming product categories as well as product
//! groups. The reader at `GET /credential/dpp/{dppId}` enforces both axes, and
//! a credential that covers nothing there is not refused but downgraded to the
//! public view. So a category list that cannot be satisfied would be found by
//! the holder, as reads that quietly come back public, rather than by the
//! operator who minted it. [`category_scope_problem`] refuses such a list with
//! a `422` instead.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse as _, Response};
use chrono::{Duration, Utc};
use dpp_domain::product_group::ProductGroup;
use dpp_vc::{Audience, CredentialBuilder, CredentialRole, DppCredentialSubject};
use serde::{Deserialize, Serialize};

use crate::extract::Json;
use crate::handlers::error::{api_error, internal_error, validation_error};
use crate::middleware::scope::RequireAdmin;
use crate::state::AppState;

/// The longest credential this route will mint.
///
/// Nothing here can withdraw a credential once issued, so the expiry is the
/// whole of the revocation story and a year-long credential is a year-long
/// liability. Ninety days is short enough that a leak has a horizon and long
/// enough not to become a weekly chore.
pub const MAX_VALID_DAYS: i64 = 90;

/// Lifetime used when the caller does not ask for one.
pub const DEFAULT_VALID_DAYS: i64 = 30;

/// A default above the ceiling would make every unqualified request fail its own
/// bound. Asserted at compile time rather than in a test, because both values
/// are constants and a test comparing them can only ever restate them.
const _: () = assert!(DEFAULT_VALID_DAYS >= 1 && DEFAULT_VALID_DAYS <= MAX_VALID_DAYS);

/// Ask this node to vouch for a holder.
///
/// `Serialize` as well as `Deserialize` so the OpenAPI contract test can build
/// a fixture from the type itself and compare its property list to the
/// published schema. Nothing in the service serialises a request.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IssueCredentialRequest {
    /// DID of the party being vouched for.
    pub holder_did: String,
    /// Legal name of the holder, carried in the credential for an auditor.
    pub holder_name: String,
    /// The role granted. Must map to a legitimate interest.
    pub role: CredentialRole,
    /// ISO 3166-1 alpha-2 country of the holder's registration.
    pub country: String,
    /// Product groups the credential covers. Empty means every product group
    /// this operator publishes.
    #[serde(default)]
    pub product_groups: Vec<String>,
    /// Product categories the credential covers within `product_groups`.
    /// Empty means every category. See [`category_scope_problem`] for what a
    /// non-empty list must satisfy.
    #[serde(default)]
    pub product_categories: Vec<String>,
    /// Lifetime in days. Defaults to [`DEFAULT_VALID_DAYS`], capped at
    /// [`MAX_VALID_DAYS`].
    #[serde(default)]
    pub valid_for_days: Option<i64>,
}

/// The minted credential, in both the forms a caller needs.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IssuedCredential {
    /// Compact VC-JWT — the value the holder sends as `X-DPP-Credential`. This
    /// is the credential; the document below is the same claims, readable.
    pub credential_jws: String,
    /// The credential document, so a caller can show the holder what it says
    /// without decoding the JWS.
    pub credential: dpp_vc::DppAccessCredential,
}

/// Mint an access credential signed with this node's own key.
pub async fn issue_credential_handler(
    State(state): State<AppState>,
    RequireAdmin(_auth): RequireAdmin,
    Json(body): Json<IssueCredentialRequest>,
) -> Response {
    let Some(issuer) = state.credential_issuer.clone() else {
        return api_error(
            StatusCode::NOT_IMPLEMENTED,
            "NOT_IMPLEMENTED",
            "This deployment has no signing key in reach, so it cannot issue credentials.",
        );
    };

    if body.role.audience() == Audience::Authority {
        return validation_error(
            "This node cannot issue an authority credential. Authority status is conferred by a \
             member state, not asserted by an operator — a node signing itself one attests \
             nothing. Issue a legitimate-interest role, or have the authority present a \
             credential from its own issuer.",
        );
    }

    if body.holder_did.trim().is_empty() || !body.holder_did.starts_with("did:") {
        return validation_error(
            "holderDid must be a DID. The credential is bound to it and a verifier matches it \
             exactly, so a name or a URL here would produce a credential nothing can present.",
        );
    }
    if body.holder_name.trim().is_empty() {
        return validation_error("holderName is required.");
    }
    if body.country.len() != 2 || !body.country.chars().all(|c| c.is_ascii_alphabetic()) {
        return validation_error("country must be an ISO 3166-1 alpha-2 code.");
    }
    if let Some(problem) = category_scope_problem(&body.product_groups, &body.product_categories) {
        return validation_error(&problem);
    }

    let days = body.valid_for_days.unwrap_or(DEFAULT_VALID_DAYS);
    if !(1..=MAX_VALID_DAYS).contains(&days) {
        return validation_error(&format!(
            "validForDays must be between 1 and {MAX_VALID_DAYS}. Nothing can withdraw a \
             credential once issued — this node publishes no status list — so the expiry is the \
             only limit there is."
        ));
    }

    let issuer_did = match issuer.issuer_did().await {
        Ok(did) => did,
        Err(e) => return internal_error(e),
    };

    let credential = CredentialBuilder::new(
        issuer_did,
        DppCredentialSubject {
            id: body.holder_did,
            name: body.holder_name,
            role: body.role,
            country: body.country.to_uppercase(),
            product_groups: body.product_groups,
            product_categories: body.product_categories,
        },
    )
    .expires_at(Utc::now() + Duration::days(days))
    .build();

    let credential_jws = match issuer.sign(&credential).await {
        Ok(jws) => jws,
        Err(e) => return internal_error(e),
    };

    tracing::info!(
        holder = %credential.credential_subject.id,
        role = ?credential.credential_subject.role,
        valid_until = %credential.valid_until,
        "issued an access credential"
    );

    (
        StatusCode::CREATED,
        Json(IssuedCredential {
            credential_jws,
            credential,
        }),
    )
        .into_response()
}

/// Why `categories` cannot narrow a credential over `groups`, or `None` when
/// it can.
///
/// A credential's category list is flat: it narrows every product group the
/// credential names, and a read is admitted only where the passport states one
/// of the listed categories. So a list that a named group cannot satisfy does
/// not narrow that group, it shuts the group out. Three rules refuse a list
/// that would be signed and could never work as written:
///
/// - **A category list needs named groups.** An empty `productGroups` means
///   every group, and the list would shut out each group whose passports state
///   no category.
/// - **Every category is one a named group's passports can state.** Anything
///   else narrows nothing, and is most likely a typo.
/// - **Every named group admits at least one listed category.** Otherwise the
///   credential names the group and can read none of its passports.
///
/// What a group's passports can state is core's answer,
/// [`ProductGroup::product_category_values`], read from the group's current
/// schema; nothing here lists a vocabulary. Spelling is compared exactly,
/// because the reader compares it exactly.
fn category_scope_problem(groups: &[String], categories: &[String]) -> Option<String> {
    if categories.is_empty() {
        return None;
    }
    if groups.is_empty() {
        return Some(
            "productCategories needs productGroups. An empty productGroups means every product \
             group, and a category list would shut out each one whose passports state no \
             category, such as textile and toy."
                .to_owned(),
        );
    }

    let legal: Vec<(&str, Option<&'static [String]>)> = groups
        .iter()
        .map(|g| {
            let values = ProductGroup::from_wire_tag(g).product_category_values();
            (g.as_str(), values)
        })
        .collect();
    let admits = |values: Option<&[String]>, category: &String| {
        values.is_some_and(|values| values.contains(category))
    };
    let describe = |groups: &[(&str, Option<&'static [String]>)]| {
        groups
            .iter()
            .map(|(group, values)| match values {
                Some(values) => format!("{group}: {}", values.join(", ")),
                None => format!("{group}: no category"),
            })
            .collect::<Vec<_>>()
            .join("; ")
    };

    let unknown: Vec<&str> = categories
        .iter()
        .filter(|category| !legal.iter().any(|(_, values)| admits(*values, category)))
        .map(String::as_str)
        .collect();
    if !unknown.is_empty() {
        return Some(format!(
            "No passport in the named product groups can state '{}'. A value none of them can \
             state narrows nothing. What each group's passports can state: {}.",
            unknown.join("', '"),
            describe(&legal)
        ));
    }

    let shut_out: Vec<(&str, Option<&'static [String]>)> = legal
        .iter()
        .filter(|(_, values)| !categories.iter().any(|category| admits(*values, category)))
        .copied()
        .collect();
    if !shut_out.is_empty() {
        return Some(format!(
            "This credential could read no passport in some of its product groups, because \
             none of their passports can state any of productCategories. Drop those groups \
             from productGroups, or give them a credential of their own. {}.",
            describe(&shut_out)
        ));
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The audience split this route is built on, stated as a test so a role
    /// added to core lands on a side deliberately rather than by default.
    #[test]
    fn the_three_authority_roles_are_the_ones_refused() {
        for role in [
            CredentialRole::MarketSurveillanceAuthority,
            CredentialRole::CustomsAuthority,
            CredentialRole::NotifiedBody,
        ] {
            assert_eq!(
                role.audience(),
                Audience::Authority,
                "{role:?} must stay on the refused side"
            );
        }
        for role in [
            CredentialRole::AuthorisedRepairer,
            CredentialRole::Recycler,
            CredentialRole::Remanufacturer,
            CredentialRole::PreparerForReuse,
            CredentialRole::Distributor,
            CredentialRole::Custom("scrap-dealer".to_owned()),
        ] {
            assert_eq!(
                role.audience(),
                Audience::LegitimateInterest,
                "{role:?} must stay issuable"
            );
        }
    }

    /// The wire form of every issuable role, pinned because the published API
    /// description enumerates them and nothing mechanical compares an enum in
    /// YAML to a Rust one. `Custom` is the shape that catches a reader out: it
    /// is externally tagged, so it is an object where the rest are strings.
    #[test]
    fn the_issuable_roles_serialise_as_documented() {
        let wire = |r: CredentialRole| serde_json::to_value(r).expect("role to json");
        assert_eq!(
            wire(CredentialRole::AuthorisedRepairer),
            "authorised_repairer"
        );
        assert_eq!(wire(CredentialRole::Recycler), "recycler");
        assert_eq!(wire(CredentialRole::Remanufacturer), "remanufacturer");
        assert_eq!(wire(CredentialRole::PreparerForReuse), "preparer_for_reuse");
        assert_eq!(wire(CredentialRole::Distributor), "distributor");
        assert_eq!(
            wire(CredentialRole::Custom("scrap-dealer".to_owned())),
            serde_json::json!({"custom": "scrap-dealer"})
        );
    }

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(|&v| v.to_owned()).collect()
    }

    fn problem(groups: &[&str], categories: &[&str]) -> Option<String> {
        category_scope_problem(&strings(groups), &strings(categories))
    }

    /// No category list claims no narrowing, so there is nothing to check,
    /// whichever groups are named and whether or not they have a category axis.
    #[test]
    fn a_credential_naming_no_category_is_never_refused_for_scope() {
        assert_eq!(problem(&[], &[]), None);
        assert_eq!(problem(&["textile", "battery"], &[]), None);
    }

    /// A list that every named group can satisfy is accepted, including one
    /// value that two groups share.
    #[test]
    fn categories_each_named_group_can_state_are_accepted() {
        assert_eq!(problem(&["battery"], &["ev", "lmt"]), None);
        assert_eq!(problem(&["battery", "steel"], &["ev", "flat"]), None);
        assert_eq!(problem(&["steel", "furniture"], &["other"]), None);
    }

    /// The values are the schema's legal domain, not the catalog's curated
    /// list: furniture's catalog entry does not name `bed`, and a bed is still
    /// a furniture passport a repairer may be scoped to.
    #[test]
    fn a_category_outside_the_catalog_list_but_in_the_schema_is_accepted() {
        assert_eq!(problem(&["furniture"], &["bed"]), None);
    }

    /// Without named groups the list would narrow every group, and shut out
    /// each one with no category axis.
    #[test]
    fn a_category_list_needs_named_groups() {
        let refusal = problem(&[], &["ev"]).expect("refused");
        assert!(refusal.contains("needs productGroups"), "{refusal}");
    }

    /// A value no named group's passports can state is refused and named,
    /// with what the groups can state, so a typo is fixed at issuance rather
    /// than found by the holder. Spelling is exact because the reader's
    /// comparison is.
    #[test]
    fn a_category_no_named_group_can_state_is_refused() {
        let refusal = problem(&["battery"], &["ev", "evv"]).expect("refused");
        assert!(refusal.contains("'evv'"), "names the value: {refusal}");
        assert!(
            refusal.contains("battery: portable, industrial, ev, lmt"),
            "says what battery can state: {refusal}"
        );

        assert!(problem(&["battery"], &["EV"]).is_some(), "case is exact");
        assert!(
            problem(&["battery"], &["flat"]).is_some(),
            "a value of an unnamed group does not count"
        );
    }

    /// A named group that admits none of the categories is refused, whether it
    /// has no category axis at all or simply none of these.
    #[test]
    fn a_named_group_no_category_reaches_is_refused() {
        let no_axis = problem(&["battery", "textile"], &["ev"]).expect("refused");
        assert!(no_axis.contains("textile: no category"), "{no_axis}");
        assert!(!no_axis.contains("battery:"), "battery is fine: {no_axis}");

        let none_listed = problem(&["battery", "steel"], &["ev"]).expect("refused");
        assert!(none_listed.contains("steel: flat"), "{none_listed}");
    }

    /// A group this build has no typed variant for answers no category values,
    /// so a category list cannot reach it. That includes a misspelt key, which
    /// is refused rather than minted into a credential nothing matches.
    #[test]
    fn a_group_this_node_does_not_model_admits_no_category() {
        let refusal = problem(&["Battery"], &["ev"]).expect("refused");
        assert!(refusal.contains("'ev'"), "{refusal}");
    }
}
