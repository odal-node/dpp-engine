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

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse as _, Response};
use chrono::{Duration, Utc};
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
            // Never set. A product category restriction is unevaluable on a
            // read — a passport has no category — and the verifier here
            // downgrades any credential carrying one to public access. Minting
            // one would produce a credential that unlocks nothing.
            product_categories: Vec::new(),
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
}
