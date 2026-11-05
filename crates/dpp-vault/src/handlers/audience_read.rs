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
//! # Scope: product group and product category
//!
//! A credential may narrow itself to product groups and to product categories,
//! and both are enforced against the passport being read: the group against its
//! `product_group`, the category against what its data states through
//! `ProductGroupData::product_category` — a battery's `batteryType`, an
//! electronics `DeviceType`, and so on per group.
//!
//! Some groups have no category axis a passport can state. A credential naming
//! a category is downgraded to `Audience::Public` on such a passport, exactly
//! as on one whose category it does not name: a restriction that cannot be
//! evaluated has not been met. See
//! [`crate::middleware::credential::VerifiedCredential::audience_for`].
//!
//! A downgraded read says why in the
//! [`X-DPP-Credential-Out-Of-Scope`](crate::middleware::credential::OUT_OF_SCOPE_HEADER)
//! header (`product-group`, `product-category` or `no-product-category`),
//! because the body cannot: it is the public view byte for byte. Without the
//! header, a holder whose reads came back public could not tell a credential
//! for the wrong group from one for the wrong category.
//!
//! # Reading a past version: `?asOf=`
//!
//! ✅ COMPLIANCE-PIN: EN 18221:2026 clause 4.2 — the version of a passport at a
//! past moment is retrievable by authenticated, authorised actors, and an
//! archived attribute is limited exactly as the live one is.
//!
//! The archive is read through `GET /api/v1/dpp/{id}/versions`, which is the
//! operator's own machine access. The readers the clause is for — an authority,
//! a notified body, a person with a legitimate interest — hold a credential and
//! no API key, for the reason given above, so `asOf` answers here for them.
//!
//! **What is served.** The version that was current at that instant, as that
//! audience's publish-time proof covers it: the decoded payload of the version's
//! *own* `disclosureSignatures` entry, with that proof attached, exactly as a live
//! read serves it. Not a redaction run over the archived document under today's
//! policy, which would be a body no proof covers. A published passport's views are
//! frozen when it is signed, so a version carries the classes it was published
//! with — the same bytes the live read serves — and nothing can be released from
//! one that the passport's own signed views withhold.
//!
//! **Who may ask: a credential that grants more than the public view.** Clause 4.2
//! speaks of *authenticated, authorised* actors, so an anonymous request is
//! refused `401` and a credential that does not cover the passport `403`. That is
//! the opposite of the live read, which answers both with the public view, and
//! deliberately so: there is no public view of a past instant worth giving. The
//! public proof is frozen at publish, so it is the same bytes for every version of
//! a published record, and serving it for `asOf` would answer a question about the
//! past with the present passport — and open an unauthenticated way to read when a
//! record was published. Both refusals are made before any version is read, and a
//! credential presented against a passport it does not cover is recorded like any
//! other.
//!
//! **Which moment answers.** A moment inside the archive is answered by the
//! version current then; one after the last change, by the live record, which is
//! the state at that time. Before the passport existed, or in the future, nothing
//! was its state: `404` and `422`. A version is served on the terms the live read
//! serves a passport on: one that was never published is `404` and one that was
//! suspended at that moment `410`.

use axum::{
    extract::{Path, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::IntoResponse,
};
use chrono::{DateTime, SecondsFormat, Utc};

use dpp_domain::Audience;
use dpp_domain::passport::{Passport, PassportId};
use dpp_domain::product_group::ProductGroupData;
use dpp_domain::status::PassportStatus;

use dpp_types::audit::PassportAuditEntry;

use crate::domain::service::{VersionAt, archived_passport};
use crate::extract::Query;
use crate::middleware::credential::{
    CredentialOutcome, OutOfScope, VerifiedCredential, credential_required,
    out_of_scope_header_name, read_and_verify,
};
use crate::public_view::{never_published, signed_audience_view, signed_public_view};
use crate::state::AppState;

use super::error::{
    api_error, internal_error, not_found_error, parse_passport_id, validation_error,
};
use super::versions::AsOf;

/// Read a published passport, filtered to the caller's audience.
pub async fn audience_read_handler(
    State(state): State<AppState>,
    Path(dpp_id): Path<String>,
    Query(query): Query<AsOf>,
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
    let credential = match resolve_credential(&state, &headers).await {
        Ok(credential) => credential,
        Err(resp) => return resp,
    };

    if let Some(raw) = query.as_of {
        return read_as_of(&state, passport_id, &raw, credential.as_deref()).await;
    }

    match state.service.find_by_id_any_status(passport_id).await {
        Ok(Some(p)) if p.status == PassportStatus::Published => {
            // Scope the credential to *this* passport's product group and
            // category. A credential issued for batteries grants nothing extra on
            // a textile passport, nor one issued for EV batteries on an LMT one.
            let scope = scope_of(&state, credential.as_deref(), &p);
            let audience = scope.unwrap_or(Audience::Public);

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
                && let Err(e) = record_access(&state, &p, c, audience, None).await
            {
                return internal_error(e).into_response();
            }

            if audience == Audience::Public {
                // Byte-identical to the public route: the payload the public
                // proof was computed over, not the live row. Why a credential
                // got no more than this goes in a header, which leaves the body
                // and its proof untouched.
                let view = match signed_public_view(&p) {
                    Ok(v) => v,
                    Err(e) => return internal_error(e).into_response(),
                };
                return match scope {
                    Err(miss) => (
                        StatusCode::OK,
                        [(out_of_scope_header_name(), miss.header_value())],
                        axum::Json(view),
                    )
                        .into_response(),
                    Ok(_) => (StatusCode::OK, axum::Json(view)).into_response(),
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

/// The credential on a request, if there is one and it holds.
///
/// `Err` is the refusal to send: a presented credential that does not verify.
#[allow(clippy::result_large_err)]
async fn resolve_credential(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<Option<Box<VerifiedCredential>>, axum::response::Response> {
    match (&state.credential_directory, &state.trusted_issuers) {
        (Some(directory), Some(trust)) => {
            match read_and_verify(headers, directory.as_ref(), trust.as_ref()).await {
                CredentialOutcome::Absent => Ok(None),
                CredentialOutcome::Verified(c) => Ok(Some(c)),
                CredentialOutcome::Rejected(resp) => Err(resp),
            }
        }
        // Credential verification is not configured. Serving the public view is
        // the honest answer: the node reports the capability as absent in its
        // trust report, and a caller presenting a credential gets public data
        // rather than a misleading success.
        _ => Ok(None),
    }
}

/// The audience `credential` grants over `passport`, or the reason it grants
/// nothing beyond the public view there.
fn scope_of(
    state: &AppState,
    credential: Option<&VerifiedCredential>,
    passport: &Passport,
) -> Result<Audience, OutOfScope> {
    match (credential, &state.trusted_issuers) {
        (Some(c), Some(trust)) => c.audience_for(
            passport.product_group.catalog_key(),
            passport
                .product_group_data
                .as_ref()
                .and_then(ProductGroupData::product_category),
            trust.as_ref(),
        ),
        _ => Ok(Audience::Public),
    }
}

/// Read the passport as it stood at `raw_as_of`. See "Reading a past version" in
/// the module documentation for what is served and to whom.
///
/// The order is the design. A caller is refused before any version is read, and
/// the live record is checked before the credential's scope is, so a reader whose
/// credential does not cover a passport learns nothing about a draft that a
/// reader with no credential at all would not.
async fn read_as_of(
    state: &AppState,
    passport_id: PassportId,
    raw_as_of: &str,
    credential: Option<&VerifiedCredential>,
) -> axum::response::Response {
    let Some(credential) = credential else {
        return credential_required(
            if state.credential_directory.is_some() && state.trusted_issuers.is_some() {
                "A past version is read with an access credential in the X-DPP-Credential header."
            } else {
                "This node does not verify access credentials, so it cannot serve a past version."
            },
        );
    };

    let Ok(at) = DateTime::parse_from_rfc3339(raw_as_of) else {
        return validation_error("asOf must be an RFC 3339 timestamp.");
    };
    let at = at.with_timezone(&Utc);
    if at > Utc::now() {
        return validation_error("asOf must not be in the future: nothing is yet its state then.");
    }

    // The live record decides whether there is anything here to ask about. A draft
    // is told apart from a missing passport by neither status nor sentence.
    let live = match state.service.find_by_id_any_status(passport_id).await {
        Ok(Some(p)) if !never_published(&p) => p,
        Ok(_) | Err(dpp_domain::DppError::NotFound(_)) => {
            return not_found_error("DPP not found or not published.");
        }
        Err(e) => return internal_error(e),
    };

    // Scoped against the live record, which is the passport whose restrictions
    // the clause applies to an archived attribute. A published record's group and
    // category cannot change, so this is also the version's own.
    let scope = scope_of(state, Some(credential), &live);
    let audience = scope.unwrap_or(Audience::Public);
    if audience == Audience::Public {
        // Recorded as a live out-of-scope read is: a credential presented against
        // a passport it does not cover is what an operator wants to find later.
        let past = PastRead {
            as_of: at,
            version: None,
        };
        if let Err(e) = record_access(state, &live, credential, audience, Some(&past)).await {
            return internal_error(e);
        }
        let mut refusal = api_error(
            StatusCode::FORBIDDEN,
            "FORBIDDEN",
            "This credential grants no access to this passport beyond the public view, and a \
             past version is read only with one that does.",
        );
        if let Err(miss) = scope {
            refusal.headers_mut().insert(
                out_of_scope_header_name(),
                HeaderValue::from_static(miss.header_value()),
            );
        }
        return refusal;
    }

    let (record, version) = match state.service.version_at(passport_id, at).await {
        Ok(VersionAt::Found(v)) => match archived_passport(&v) {
            Ok(p) => (p, Some(v.id)),
            Err(e) => return internal_error(e),
        },
        // Nothing archived covers it, so the live record is the state then.
        Ok(VersionAt::Live) => (live, None),
        Ok(VersionAt::BeforeItExisted) => {
            return not_found_error(
                "That moment is before this passport was created, so nothing was its state then.",
            );
        }
        Err(dpp_domain::DppError::NotFound(_)) => return not_found_error("DPP not found."),
        Err(e) => return internal_error(e),
    };

    match record.status {
        PassportStatus::Published => {}
        PassportStatus::Suspended => {
            return api_error(
                StatusCode::GONE,
                "SUSPENDED",
                "This passport was suspended at that moment.",
            );
        }
        _ => {
            return not_found_error("No published version of this passport covers that moment.");
        }
    }

    // Recorded before it is served, for the reason a live read is.
    let past = PastRead { as_of: at, version };
    if let Err(e) = record_access(state, &record, credential, audience, Some(&past)).await {
        return internal_error(e);
    }
    match signed_audience_view(&record, audience) {
        Ok(v) => (StatusCode::OK, axum::Json(v)).into_response(),
        Err(e) => internal_error(e).into_response(),
    }
}

/// What a read of a past version adds to its audit entry.
struct PastRead {
    /// The instant asked for.
    as_of: DateTime<Utc>,
    /// The archived version that answered, or `None` when the live record did, or
    /// when the read was refused before any version was looked up.
    version: Option<uuid::Uuid>,
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
///
/// A read of a past version also records the instant asked for (`asOf`) and the
/// archived version that answered it (`archivedVersionId`, `null` when the live
/// record did): the grant says what was released, and these say of which moment.
async fn record_access(
    state: &AppState,
    passport: &Passport,
    credential: &VerifiedCredential,
    granted: Audience,
    past: Option<&PastRead>,
) -> Result<(), dpp_domain::DppError> {
    let subject = &credential.credential().credential_subject;
    let classes: Vec<&str> = granted
        .disclosure_set()
        .into_iter()
        .map(dpp_domain::Disclosure::token)
        .collect();

    let mut metadata = serde_json::json!({
        "issuerDid": credential.credential().issuer,
        "holderDid": subject.id,
        "holderName": subject.name,
        "disclosureSet": granted.disclosure_key(),
        "disclosureClasses": classes,
        "productGroup": passport.product_group.catalog_key(),
    });
    if let Some(past) = past {
        metadata["asOf"] =
            serde_json::json!(past.as_of.to_rfc3339_opts(SecondsFormat::Micros, true));
        metadata["archivedVersionId"] = serde_json::json!(past.version);
    }

    let entry = PassportAuditEntry::new(
        &passport.id.to_string(),
        CREDENTIALED_READ,
        subject.id.clone(),
        None,
        None,
    )
    .with_metadata(metadata);

    state.service.audit.append(entry).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::public_view::audience_view;
    use serde_json::{Value, json};

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
    /// A published battery, typed.
    ///
    /// Typed rather than a JSON literal because the redaction now reads the
    /// product group and schema version off the record — the two things this
    /// fixture used to pass separately, and the two a caller could previously
    /// get wrong.
    fn battery() -> dpp_domain::passport::Passport {
        let mut p = crate::public_view::tests::stub_passport();
        p.schema_version = BATTERY_SCHEMA.into();
        p.product_name = "Cell".into();
        p.jws_signature = Some("eyJ.signed.value".into());
        p.public_jws_signature = Some("eyJ.public.proof".into());
        p.product_group_data = Some(
            serde_json::from_value(json!({
                "productGroup": "battery",
                "productIdentifier": { "scheme": "gs1", "gtin": "09506000134352" },
                "batteryChemistry": "LFP",
                "batteryType": "ev",
                "nominalVoltageV": 3.2,
                "nominalCapacityAh": 100.0,
                "co2ePerUnitKg": 85.4,
                "stateOfHealthPct": 87.5,
                "cathodeMaterial": [{ "name": "LFP", "weightPct": 100.0 }],
            }))
            .expect("battery data"),
        );
        p
    }

    fn product_group_data(v: &Value) -> &serde_json::Map<String, Value> {
        v.get("productGroupData")
            .and_then(Value::as_object)
            .expect("productGroupData")
    }

    /// Art. 77(2)(c): individual-item data goes to legitimate-interest holders.
    #[test]
    fn legitimate_interest_sees_individual_item_data() {
        let v = audience_view(&battery(), Audience::LegitimateInterest);
        assert!(product_group_data(&v).contains_key("stateOfHealthPct"));
        assert!(product_group_data(&v).contains_key("cathodeMaterial"));
    }

    /// Art. 77(2)(b) assigns authorities Annex XIII points 2 and 3 — **not**
    /// point 4. An authority must not receive individual-item data, and this is
    /// the case an ordered tier model gets wrong.
    #[test]
    fn an_authority_does_not_see_individual_item_data() {
        let v = audience_view(&battery(), Audience::Authority);
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
        let authority = audience_view(&battery(), Audience::Authority);
        let interest = audience_view(&battery(), Audience::LegitimateInterest);
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
            let v = audience_view(&battery(), audience);
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
        let v = audience_view(&battery(), Audience::Public);
        assert!(!product_group_data(&v).contains_key("stateOfHealthPct"));
        assert!(!product_group_data(&v).contains_key("cathodeMaterial"));
        assert!(v.get("jwsSignature").is_none());
    }

    /// An unmodelled product group has no field policy for *any* audience, so a
    /// credentialed reader must not get more from it than an anonymous one.
    #[test]
    fn an_unknown_product_group_fails_closed_for_every_audience() {
        let mut unknown = crate::public_view::tests::stub_passport();
        unknown.product_group =
            dpp_domain::product_group::ProductGroup::Other("not-a-product-group".into());
        unknown.product_group_data = Some(
            serde_json::from_value(json!({
                "productGroup": "not-a-product-group",
                "secret": "value",
            }))
            .expect("unmodelled product group data"),
        );
        for audience in [
            Audience::Public,
            Audience::LegitimateInterest,
            Audience::Authority,
        ] {
            let v = audience_view(&unknown, audience);
            assert!(
                !product_group_data(&v).contains_key("secret"),
                "{audience:?} must not receive unmodelled product_group data"
            );
        }
    }
}
