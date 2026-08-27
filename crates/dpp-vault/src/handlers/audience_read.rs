//! Audience-scoped read — the same passport, filtered to what the caller may see.
//!
//! # Why this is not `/public/dpp/{id}`
//!
//! A public URL whose body varies by caller is a caching hazard and breaks the
//! meaning of `publicJwsSignature`, which signs *the* public view. This route is
//! separate so the public one keeps a single, cacheable, signed representation.
//!
//! # Why it is not under `/api/v1`
//!
//! `/api/v1` is API-key territory — the operator's own machine access. A
//! repairer or a market surveillance authority holds a credential and no API
//! key, and requiring one would gate lawful access behind a commercial
//! relationship with us.
//!
//! # What it serves
//!
//! - **No credential** — the signed public view, byte-identical to
//!   `/public/dpp/{id}`. Public access is free of charge and needs no
//!   registration (ESPR Art. 11(b); the toy and detergent regulations forbid
//!   requiring a password), so this must work anonymously.
//! - **A verified credential** — the passport filtered to that audience's
//!   disclosure classes, carrying the proof computed over *that* view and a
//!   `disclosureSet` naming the classes it contains.
//!
//! # Every view is verifiable, and every credentialed read is recorded
//!
//! A non-public view used to be served with `publicJwsSignature` — a proof over
//! a strictly smaller payload — or, for an authority, `jwsSignature` over a
//! strictly larger one. Both fail against the body they arrive with, which to a
//! verifier is indistinguishable from tampering. Each disclosure set now carries
//! its own publish-time proof, so the audiences most likely to be making a
//! safety or resale call on the data are the ones who can check it.
//!
//! Credentialed reads append to the passport's hash-chained audit trail, keyed
//! by disclosure classes rather than audience name. Anonymous reads are not
//! audited: they are the free, unregistered baseline, and recording them would
//! turn a public right into a tracked event.
//!
//! # What this route still does not do
//!
//! Product-category scope is not *evaluated*, and a credential that claims one
//! therefore unlocks nothing here. ProductGroup scope is enforced; category has no
//! counterpart to be enforced against, because a passport carries no product
//! category — the field that once did was renamed `product_group`, and category is now
//! a per-product group concept with a different shape in each.
//!
//! Rather than reading an unevaluable restriction as no restriction, which
//! granted a narrowed credential its full audience over every product in its
//! product groups, such a credential is downgraded to `Audience::Public`. See
//! [`crate::middleware::credential::VerifiedCredential::audience_for_product_group`].

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use serde_json::Value;

use dpp_domain::Audience;
use dpp_domain::status::PassportStatus;

use dpp_types::audit::AuditEntry;

use crate::middleware::credential::{CredentialOutcome, VerifiedCredential, read_and_verify};
use crate::public_view::{audience_view, signed_audience_view, signed_public_view};
use crate::state::AppState;

use super::error::{api_error, internal_error, not_found_error, parse_passport_id};

/// Read a published passport, filtered to the caller's audience.
pub async fn audience_read_handler(
    State(state): State<AppState>,
    Path(dpp_id): Path<String>,
    headers: HeaderMap,
) -> axum::response::Response {
    let passport_id = match parse_passport_id(&dpp_id) {
        Ok(id) => id,
        Err(e) => return e.into_response(),
    };

    // Authenticate the caller *before* touching the database: a rejected
    // credential gets the same answer whether or not the passport exists, so
    // this route cannot be used to probe for passport ids. The credential is
    // only held here — what it *grants* depends on the passport's product group, which
    // is not known until the row is loaded.
    let credential = match (&state.credential_directory, &state.trusted_issuers) {
        (Some(directory), Some(trust)) => {
            match read_and_verify(&headers, directory.as_ref(), trust.as_ref()).await {
                CredentialOutcome::Absent => None,
                CredentialOutcome::Verified(c) => Some(c),
                CredentialOutcome::Rejected(resp) => return resp,
            }
        }
        // Credential verification is not configured. Serving the public view is
        // the honest answer: the node reports the capability as absent in its
        // trust report, and a caller presenting a credential gets public data
        // rather than a misleading success.
        _ => None,
    };

    match state.service.find_by_id_any_status(passport_id).await {
        Ok(Some(p)) if p.status == PassportStatus::Published => {
            // Scope the credential to *this* passport's product group. A credential
            // issued for batteries grants nothing extra on a textile passport.
            let audience = match (&credential, &state.trusted_issuers) {
                (Some(c), Some(trust)) => {
                    c.audience_for_product_group(p.product_group.catalog_key(), trust.as_ref())
                }
                _ => Audience::Public,
            };

            // Record the access before serving it. A credentialed read is the
            // operator's evidence that it honoured — and bounded — a lawful
            // access request, so serving without recording is the one outcome
            // that must not happen. If the trail cannot be written the request
            // fails; the caller can still retry without a credential and
            // receive the public view, which is never audited and never gated.
            //
            // Recorded for *every* credentialed read, including one scoped down
            // to public: a credential presented against a product it does not
            // cover is exactly the event an operator wants to find later, and
            // it is invisible if only elevated reads are logged.
            if let Some(c) = &credential
                && let Err(e) = record_access(&state, &p, c, audience).await
            {
                return internal_error(e).into_response();
            }

            if audience == Audience::Public {
                // Byte-identical to the public route: the payload the public
                // proof was computed over, not the live row.
                return match signed_public_view(&p) {
                    Ok(v) => (StatusCode::OK, axum::Json(v)).into_response(),
                    Err(e) => internal_error(e).into_response(),
                };
            }

            // Serve the payload this audience's proof was computed over, with
            // that proof attached — the non-public counterpart of the public
            // route's behaviour, so body and signature agree by construction
            // for every caller rather than only the anonymous one.
            match signed_audience_view(&p, audience) {
                Ok(v) => (StatusCode::OK, axum::Json(v)).into_response(),
                Err(e) => internal_error(e).into_response(),
            }
        }
        Ok(Some(p)) if p.status == PassportStatus::Suspended => api_error(
            StatusCode::GONE,
            "SUSPENDED",
            "This passport has been suspended.",
        )
        .into_response(),
        Ok(_) => not_found_error("DPP not found or not published.").into_response(),
        Err(dpp_domain::DppError::NotFound(_)) => not_found_error("DPP not found.").into_response(),
        Err(e) => internal_error(e.to_string()).into_response(),
    }
}

/// Action code for a read performed against a verified access credential.
pub const CREDENTIALED_READ: &str = "credentialed_read";

/// Append a credentialed read to the passport's hash-chained audit trail.
///
/// Recorded because a read is where an access regime is actually honoured or
/// breached — the write-side trail says what the operator published, and says
/// nothing about who was given the restricted view of it.
///
/// # What is stored, and what deliberately is not
///
/// The grant is recorded as **`disclosureClasses`** — the Annex XIII classes the
/// caller received — and never as an audience name. The same rule that keys the
/// signatures: ESPR's actor vocabulary is not battery Art. 77(2)'s, and the
/// delegated act mapping actors to data is unadopted, so a trail keyed
/// `"legitimateInterest"` would need rewriting the day that mapping lands. A
/// trail naming the data classes stays true and maps forward.
///
/// Issuer and holder DIDs are stored because they are the accountability chain:
/// who vouched, and for whom. Nothing else about the caller is — no IP, no user
/// agent, no session. This is a lawful-access record, not analytics, and the
/// scan-telemetry schema next door deliberately has no such column either.
///
/// An **out-of-scope** credential is still recorded, with the public classes it
/// was reduced to. A credential presented against a product it does not cover is
/// exactly the event an operator wants to be able to find later.
async fn record_access(
    state: &AppState,
    passport: &dpp_domain::passport::Passport,
    credential: &VerifiedCredential,
    granted: Audience,
) -> Result<(), dpp_domain::DppError> {
    let subject = &credential.credential().credential_subject;
    let classes: Vec<&str> = granted
        .disclosure_set()
        .into_iter()
        .map(dpp_domain::Disclosure::token)
        .collect();

    let entry = AuditEntry::new(
        &passport.id.to_string(),
        CREDENTIALED_READ,
        subject.id.clone(),
        None,
        None,
    )
    .with_metadata(serde_json::json!({
        "issuerDid": credential.credential().issuer,
        "holderDid": subject.id,
        "holderName": subject.name,
        "disclosureSet": granted.disclosure_key(),
        "disclosureClasses": classes,
        "productGroup": passport.product_group.catalog_key(),
    }));

    state.service.audit.append(entry).await
}

/// Strip the fields a given audience may not see. Exposed for tests and for the
/// snapshot path; the route above is the only production caller.
#[must_use]
pub fn view_for(
    full: &Value,
    product_group_key: &str,
    schema_version: &str,
    audience: Audience,
) -> Value {
    audience_view(full, product_group_key, schema_version, audience)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// The battery schema version these fixtures are written against.
    ///
    /// A real version, not a placeholder: disclosure classes are now resolved
    /// from the passport's own schema version, so an invented one resolves to no
    /// policy and the fail-closed path strips `productGroupData` entirely — every
    /// assertion below would then pass or fail for the wrong reason.
    const BATTERY_SCHEMA: &str = "2.6.0";

    /// A battery passport carrying one field of each disclosure class that
    /// matters: `stateOfHealthPct` is `individual` (Annex XIII point 4),
    /// `cathodeMaterial` is `restricted` (point 2), and `retentionLocked` is
    /// `conformity` (point 3) at passport level.
    ///
    /// `retentionLocked` rather than `jwsSignature` is the conformity witness
    /// here deliberately: proof fields are stripped from every view (they are
    /// attached by the serving layer, which knows which one covers the body), so
    /// a signature can no longer stand in for a disclosure class.
    fn battery() -> Value {
        json!({
            "id": "0190a9f0-1234-7abc-8def-0123456789ab",
            "productName": "Cell",
            "retentionLocked": true,
            "jwsSignature": "eyJ.signed.value",
            "publicJwsSignature": "eyJ.public.proof",
            "productGroupData": {
                "productGroup": "battery",
                "gtin": "09506000134352",
                "stateOfHealthPct": 87.5,
                "cathodeMaterial": "LFP"
            }
        })
    }

    fn product_group_data(v: &Value) -> &serde_json::Map<String, Value> {
        v.get("productGroupData")
            .and_then(Value::as_object)
            .expect("productGroupData")
    }

    /// Art. 77(2)(c): individual-item data goes to legitimate-interest holders.
    #[test]
    fn legitimate_interest_sees_individual_item_data() {
        let v = view_for(
            &battery(),
            "battery",
            BATTERY_SCHEMA,
            Audience::LegitimateInterest,
        );
        assert!(product_group_data(&v).contains_key("stateOfHealthPct"));
        assert!(product_group_data(&v).contains_key("cathodeMaterial"));
    }

    /// Art. 77(2)(b) assigns authorities Annex XIII points 2 and 3 — **not**
    /// point 4. An authority must not receive individual-item data, and this is
    /// the case an ordered tier model gets wrong.
    #[test]
    fn an_authority_does_not_see_individual_item_data() {
        let v = view_for(&battery(), "battery", BATTERY_SCHEMA, Audience::Authority);
        assert!(
            !product_group_data(&v).contains_key("stateOfHealthPct"),
            "Art. 77(2)(b) withholds point 4 from authorities"
        );
        assert!(
            product_group_data(&v).contains_key("cathodeMaterial"),
            "point 2 is shared"
        );
    }

    /// Conformity evidence is authority-only: Annex XIII point 3 under
    /// Art. 77(2)(b), and explicitly withheld from legitimate interest.
    #[test]
    fn conformity_evidence_is_authority_only() {
        let authority = view_for(&battery(), "battery", BATTERY_SCHEMA, Audience::Authority);
        let interest = view_for(
            &battery(),
            "battery",
            BATTERY_SCHEMA,
            Audience::LegitimateInterest,
        );
        assert_eq!(authority.get("retentionLocked"), Some(&json!(true)));
        assert!(interest.get("retentionLocked").is_none());
    }

    /// No view carries a proof — of any kind, for any audience.
    ///
    /// A signature covers one specific redaction, so a view that ships someone
    /// else's proof hands the reader something that cannot verify against the
    /// bytes it arrived with. Both fields reached audiences they did not cover:
    /// `publicJwsSignature` has no disclosure-table entry, so it defaulted to
    /// `Public` and went to everyone; `jwsSignature` is `Conformity`, so it went
    /// to authorities attached to a body with individual-item data removed.
    /// Attaching the matching proof is the serving layer's job.
    #[test]
    fn no_view_carries_a_proof_it_does_not_cover() {
        for audience in [
            Audience::Public,
            Audience::LegitimateInterest,
            Audience::Authority,
        ] {
            let v = view_for(&battery(), "battery", BATTERY_SCHEMA, audience);
            for proof in ["publicJwsSignature", "jwsSignature", "disclosureSignatures"] {
                assert!(
                    v.get(proof).is_none(),
                    "{audience:?} received {proof}, which does not cover this body"
                );
            }
        }
    }

    /// The public view is the floor: neither restricted nor individual data.
    #[test]
    fn the_public_view_carries_neither() {
        let v = view_for(&battery(), "battery", BATTERY_SCHEMA, Audience::Public);
        assert!(!product_group_data(&v).contains_key("stateOfHealthPct"));
        assert!(!product_group_data(&v).contains_key("cathodeMaterial"));
        assert!(v.get("jwsSignature").is_none());
    }

    /// An unmodelled product group has no field policy for *any* audience, so a
    /// credentialed reader must not get more from it than an anonymous one.
    #[test]
    fn an_unknown_product_group_fails_closed_for_every_audience() {
        let unknown = json!({
            "id": "0190a9f0-1234-7abc-8def-0123456789ab",
            "productGroupData": { "productGroup": "not-a-product_group", "secret": "value" }
        });
        for audience in [
            Audience::Public,
            Audience::LegitimateInterest,
            Audience::Authority,
        ] {
            let v = view_for(&unknown, "not-a-product_group", BATTERY_SCHEMA, audience);
            assert!(
                !product_group_data(&v).contains_key("secret"),
                "{audience:?} must not receive unmodelled product_group data"
            );
        }
    }
}
