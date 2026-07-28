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
//!   disclosure classes.
//!
//! # The honest gap
//!
//! A non-public view is served **unsigned**. `publicJwsSignature` covers only
//! the public view, and `jwsSignature` over the full payload is classified
//! `Conformity`, so an authority can verify but a legitimate-interest holder
//! receives no verifiable artefact at all. That is a known defect, tracked in
//! the campaign plan; it is not introduced here, but this route is where it
//! becomes visible to a caller.

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use serde_json::Value;

use dpp_domain::Audience;
use dpp_domain::domain::status::PassportStatus;

use crate::middleware::credential::{CredentialOutcome, read_and_verify};
use crate::public_view::{audience_view, signed_public_view};
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

    // Resolve the caller *before* touching the database: a rejected credential
    // gets the same answer whether or not the passport exists, so this route
    // cannot be used to probe for passport ids.
    let audience = match (&state.credential_directory, &state.trusted_issuers) {
        (Some(directory), Some(trust)) => {
            match read_and_verify(&headers, directory.as_ref(), trust.as_ref()).await {
                CredentialOutcome::Absent => Audience::Public,
                CredentialOutcome::Verified(c) => c.audience(),
                CredentialOutcome::Rejected(resp) => return resp,
            }
        }
        // Credential verification is not configured. Serving the public view is
        // the honest answer: the node reports the capability as absent in its
        // trust report, and a caller presenting a credential gets public data
        // rather than a misleading success.
        _ => Audience::Public,
    };

    match state.service.find_by_id_any_status(passport_id).await {
        Ok(Some(p)) if p.status == PassportStatus::Published => {
            if audience == Audience::Public {
                // Byte-identical to the public route: the payload the public
                // proof was computed over, not the live row.
                return match signed_public_view(&p) {
                    Ok(v) => (StatusCode::OK, axum::Json(v)).into_response(),
                    Err(e) => internal_error(e).into_response(),
                };
            }
            let full = match serde_json::to_value(&p) {
                Ok(v) => v,
                Err(e) => return internal_error(e.to_string()).into_response(),
            };
            let view = audience_view(&full, p.sector.catalog_key(), audience);
            (StatusCode::OK, axum::Json(view)).into_response()
        }
        Ok(Some(p)) if p.status == PassportStatus::Suspended => api_error(
            StatusCode::GONE,
            "SUSPENDED",
            "This passport has been suspended.",
        )
        .into_response(),
        Ok(_) => not_found_error(&dpp_id).into_response(),
        Err(e) => internal_error(e.to_string()).into_response(),
    }
}

/// Strip the fields a given audience may not see. Exposed for tests and for the
/// snapshot path; the route above is the only production caller.
#[must_use]
pub fn view_for(full: &Value, sector_key: &str, audience: Audience) -> Value {
    audience_view(full, sector_key, audience)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A battery passport carrying one field of each disclosure class that
    /// matters: `stateOfHealthPct` is `individual` (Annex XIII point 4),
    /// `cathodeMaterial` is `restricted` (point 2), and `jwsSignature` is
    /// `conformity` (point 3) at passport level.
    fn battery() -> Value {
        json!({
            "id": "0190a9f0-1234-7abc-8def-0123456789ab",
            "productName": "Cell",
            "jwsSignature": "eyJ.signed.value",
            "sectorData": {
                "sector": "battery",
                "gtin": "09506000134352",
                "stateOfHealthPct": 87.5,
                "cathodeMaterial": "LFP"
            }
        })
    }

    fn sector_data(v: &Value) -> &serde_json::Map<String, Value> {
        v.get("sectorData")
            .and_then(Value::as_object)
            .expect("sectorData")
    }

    /// Art. 77(2)(c): individual-item data goes to legitimate-interest holders.
    #[test]
    fn legitimate_interest_sees_individual_item_data() {
        let v = view_for(&battery(), "battery", Audience::LegitimateInterest);
        assert!(sector_data(&v).contains_key("stateOfHealthPct"));
        assert!(sector_data(&v).contains_key("cathodeMaterial"));
    }

    /// Art. 77(2)(b) assigns authorities Annex XIII points 2 and 3 — **not**
    /// point 4. An authority must not receive individual-item data, and this is
    /// the case an ordered tier model gets wrong.
    #[test]
    fn an_authority_does_not_see_individual_item_data() {
        let v = view_for(&battery(), "battery", Audience::Authority);
        assert!(
            !sector_data(&v).contains_key("stateOfHealthPct"),
            "Art. 77(2)(b) withholds point 4 from authorities"
        );
        assert!(
            sector_data(&v).contains_key("cathodeMaterial"),
            "point 2 is shared"
        );
    }

    /// Conformity evidence is authority-only, so a legitimate-interest holder
    /// gets no `jwsSignature` — which is also why that audience currently has no
    /// verifiable artefact at all. See the module docs.
    #[test]
    fn conformity_evidence_is_authority_only() {
        let authority = view_for(&battery(), "battery", Audience::Authority);
        let interest = view_for(&battery(), "battery", Audience::LegitimateInterest);
        assert!(authority.get("jwsSignature").is_some());
        assert!(interest.get("jwsSignature").is_none());
    }

    /// The public view is the floor: neither restricted nor individual data.
    #[test]
    fn the_public_view_carries_neither() {
        let v = view_for(&battery(), "battery", Audience::Public);
        assert!(!sector_data(&v).contains_key("stateOfHealthPct"));
        assert!(!sector_data(&v).contains_key("cathodeMaterial"));
        assert!(v.get("jwsSignature").is_none());
    }

    /// An unmodelled sector has no field policy for *any* audience, so a
    /// credentialed reader must not get more from it than an anonymous one.
    #[test]
    fn an_unknown_sector_fails_closed_for_every_audience() {
        let unknown = json!({
            "id": "0190a9f0-1234-7abc-8def-0123456789ab",
            "sectorData": { "sector": "not-a-sector", "secret": "value" }
        });
        for audience in [
            Audience::Public,
            Audience::LegitimateInterest,
            Audience::Authority,
        ] {
            let v = view_for(&unknown, "not-a-sector", audience);
            assert!(
                !sector_data(&v).contains_key("secret"),
                "{audience:?} must not receive unmodelled sector data"
            );
        }
    }
}
