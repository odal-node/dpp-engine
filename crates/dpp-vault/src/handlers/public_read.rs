use std::sync::OnceLock;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use dpp_domain::DppError;
use dpp_domain::schemas::{LensRegistry, UpcastError};
use dpp_domain::status::PassportStatus;

use crate::public_view::{serves_publicly, signed_public_view};
use crate::state::AppState;

use super::error::{api_error, internal_error, not_found_error, parse_passport_id};
use crate::extract::{Json, Query};

/// Query params for the public read. `schema_view` requests a read-time upcast
/// of the product group data to a newer schema version, served *alongside* the
/// canonical (signed) passport — never re-signed as if original.
#[derive(Deserialize, Serialize)]
pub struct PublicReadQuery {
    #[serde(rename = "schema_view")]
    pub schema_view: Option<String>,
}

/// Shared upcast-lens registry, built once.
fn lens_registry() -> &'static LensRegistry {
    static REGISTRY: OnceLock<LensRegistry> = OnceLock::new();
    REGISTRY.get_or_init(LensRegistry::new)
}

/// Public, unauthenticated read of a **published** passport.
///
/// Used by the resolver service to serve the public passport page. Returns 404
/// for any passport that is not in `Published` / `active` state. The payload is
/// **redacted to the Public access tier** — professional/confidential fields are
/// never served on this unauthenticated route.
///
/// With `?schema_view=<version>`, the response also carries a `schemaView`: the
/// product group data upcast to that version via read-time lenses, with honest lens
/// provenance. The canonical `passport` (and its signature) is unchanged.
pub async fn public_read_handler(
    State(state): State<AppState>,
    Path(dpp_id): Path<String>,
    Query(query): Query<PublicReadQuery>,
) -> impl IntoResponse {
    let passport_id = match parse_passport_id(&dpp_id) {
        Ok(id) => id,
        Err(e) => return e,
    };

    // We look up by ID only (no operator filter) and check status afterwards.
    match state.service.find_by_id_any_status(passport_id).await {
        // 🚨 A superseded passport resolves on to the record that replaced it.
        //
        // The carrier is printed on a product and cannot be recalled, so the
        // question a scan asks is "what is this product's passport now", not
        // "what does record X say". For a passport carrying a GTIN the Digital
        // Link carrier already answers it that way — every `/01/{gtin}` route
        // resolves on the GTIN alone and lands on whichever record is published.
        // A passport with no GTIN falls back to `/dpp/{id}`, and until now that
        // door answered differently from the one beside it.
        //
        // **Why the successor's body rather than a status field.** The body
        // served here is the decoded payload of `publicJwsSignature`, verbatim,
        // so every field in it was frozen at publish — including `status`, which
        // therefore reads `active` however the passport was later retired. A
        // plain `currentStatus` beside it could not be trusted (unauthenticated,
        // on a page whose whole value is that it verifies, behind a resolver
        // cache) and could not be reached (the resolver re-attaches exactly one
        // named field). Serving the successor needs none of that: it is a
        // different record, published, signed, and current, and its own
        // `supersedesId` names the passport that was asked for — so the reader
        // gets the pointer as part of a document they can verify.
        Ok(Some(p)) if p.status == PassportStatus::Superseded => {
            match successor_view(&state, &p).await {
                Ok(Some(s)) => {
                    let id = s.id;
                    let mut response = respond_public_view(
                        s.view,
                        s.product_group.catalog_key(),
                        &s.schema_version,
                        query.schema_view.as_deref(),
                    );
                    say_where_the_record_lives(&mut response, id);
                    response
                }
                // Nothing published supersedes it. Its own frozen view is then
                // the best thing there is, and it is what this route served
                // before — see the residue noted on `successor_view`.
                Ok(None) => match signed_public_view(&p) {
                    Ok(v) => respond_public_view(
                        v,
                        p.product_group.catalog_key(),
                        &p.schema_version,
                        query.schema_view.as_deref(),
                    ),
                    Err(e) => internal_error(e),
                },
                Err(e) => internal_error(e),
            }
        }
        Ok(Some(p)) if serves_publicly(&p.status) => {
            // Serve the payload the public proof was computed over, not the live
            // row: the two diverge for any Public field that changes after
            // publish, and only the former verifies against the attached
            // signature. See `signed_public_view`.
            let view = match signed_public_view(&p) {
                Ok(v) => v,
                Err(e) => return internal_error(e),
            };
            respond_public_view(
                view,
                p.product_group.catalog_key(),
                &p.schema_version,
                query.schema_view.as_deref(),
            )
        }
        Ok(Some(p)) if p.status == PassportStatus::Suspended => api_error(
            StatusCode::GONE,
            "SUSPENDED",
            "This passport has been suspended.",
        ),
        Ok(_) => not_found_error("DPP not found or not published."),
        Err(dpp_domain::DppError::NotFound(_)) => not_found_error("DPP not found."),
        Err(e) => internal_error(e),
    }
}

/// The signed public view of whatever replaced `retired`, if anything published
/// has.
///
/// Returns the view together with the successor's own product group and schema
/// version, because both drive `?schema_view` and taking either from the
/// predecessor would upcast one record's data against another's version.
///
/// # What this does not reach
///
/// A passport retired **without** a successor — `archived` at the end of its
/// retention, or `deactivated` at end of life. Those keep serving their own
/// frozen view, whose `status` still reads as it did at publish. There is no
/// successor to send a reader to and no authenticated way to say "this is over"
/// inside a payload that was signed before it was, so that half is left as it
/// was rather than papered over with a claim a consumer could not check.
async fn successor_view(
    state: &AppState,
    retired: &dpp_domain::passport::Passport,
) -> Result<Option<SuccessorView>, DppError> {
    let Some(lookup) = state.service.successors.as_ref() else {
        return Ok(None);
    };
    let Some(successor) = lookup.successor_of(retired.id).await? else {
        return Ok(None);
    };
    let view = signed_public_view(&successor)?;
    Ok(Some(SuccessorView {
        view,
        product_group: successor.product_group,
        schema_version: successor.schema_version,
        id: successor.id,
    }))
}

/// Name the record this response actually carries, in `Content-Location`.
///
/// 🚨 **Set only when the body is a different record from the one asked for.**
/// An ordinary read carries no such header, so its presence is the signal: a
/// client that sent `dppId` and gets this back has a mechanical way to tell
/// "this is your record" from "this is the record that replaced it", without
/// diffing `id` against what it sent.
///
/// RFC 9110 §8.7 is exactly this case — the representation is available at
/// another URI and the response is still a `200` for the one requested, which is
/// what a printed carrier needs. A redirect would say the same thing and cost
/// more: four doors sit in front of this route, and `/01/{gtin}` beside it does
/// not redirect either, so redirecting here would make the two disagree again in
/// the opposite direction.
///
/// **A relative reference, deliberately.** This router is mounted at `/vault` by
/// the node and at the root when the vault runs alone, so no absolute path is
/// correct in both. `./{id}` resolves against the request URI — `…/public/dpp/X`
/// + `./Y` → `…/public/dpp/Y` — and is right wherever it is mounted.
fn say_where_the_record_lives(
    response: &mut axum::response::Response,
    id: dpp_domain::passport::PassportId,
) {
    // A passport id is a UUID, so this cannot fail — but a header value that
    // refused to build is not a reason to withhold the body a reader came for.
    if let Ok(value) = axum::http::HeaderValue::from_str(&format!("./{id}")) {
        response
            .headers_mut()
            .insert(axum::http::header::CONTENT_LOCATION, value);
    }
}

/// The successor's signed public view, and what serving it takes.
///
/// A struct rather than a tuple because it grew a fourth member: the id is what
/// `Content-Location` names, and `view.0`/`view.1`/`view.2` at the call site was
/// already at the edge of readable.
struct SuccessorView {
    /// The successor's own signed public payload — not the predecessor's.
    view: Value,
    /// The successor's product group and schema version. Both drive
    /// `?schema_view`, and taking either from the predecessor would upcast one
    /// record's data against another record's version.
    product_group: dpp_domain::product_group::ProductGroup,
    schema_version: String,
    /// Where the record being served actually lives.
    id: dpp_domain::passport::PassportId,
}

/// Serve the plain public `view`, or — when `target` is `Some` — the view
/// alongside a schema-upcast `schemaView`. Shared by the by-id and by-gtin
/// public reads so both expose `?schema_view` identically.
pub(crate) fn respond_public_view(
    view: Value,
    product_group_key: &str,
    from: &str,
    target: Option<&str>,
) -> axum::response::Response {
    let Some(target) = target else {
        return (StatusCode::OK, Json(view)).into_response();
    };
    match build_schema_view(&view, product_group_key, from, target) {
        Ok(body) => (StatusCode::OK, Json(body)).into_response(),
        Err(SchemaViewError::NoProductGroupData) => api_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "NO_SECTOR_DATA",
            "This passport has no product_group data to re-view.",
        ),
        Err(SchemaViewError::Upcast(UpcastError::Transform(e))) => {
            internal_error(dpp_domain::DppError::Internal(e.to_string()))
        }
        Err(SchemaViewError::Upcast(e)) => api_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "SCHEMA_VIEW_UNAVAILABLE",
            &e.to_string(),
        ),
    }
}

#[derive(Debug)]
enum SchemaViewError {
    NoProductGroupData,
    Upcast(UpcastError),
}

/// Build the alongside body: the canonical public `view` plus a `schemaView`
/// derived by upcasting its product group data from `from` to `target`. The canonical
/// view is passed through untouched.
fn build_schema_view(
    view: &Value,
    product_group_key: &str,
    from: &str,
    target: &str,
) -> Result<Value, SchemaViewError> {
    let product_group_data = view
        .get("productGroupData")
        .ok_or(SchemaViewError::NoProductGroupData)?;
    let derived = lens_registry()
        .upcast_str(product_group_key, product_group_data, from, target)
        .map_err(SchemaViewError::Upcast)?;
    Ok(serde_json::json!({ "passport": view, "schemaView": derived }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn battery_view() -> Value {
        serde_json::json!({
            "productName": "Test Pack",
            "productGroupData": {
                "productGroup": "battery",
                "gtin": "09506000134352",
                "batteryChemistry": "LFP",
                "nominalVoltageV": 48.0,
                "nominalCapacityAh": 100.0,
                "expectedLifetimeCycles": 3000,
                "co2ePerUnitKg": 45.2,
                "ratedCapacityKwh": 4.8
            }
        })
    }

    #[test]
    fn schema_view_upcasts_battery_and_keeps_original() {
        let view = battery_view();
        let out = build_schema_view(&view, "battery", "1.0.0", "2.0.0").unwrap();

        assert_eq!(out["schemaView"]["derived"], true);
        assert_eq!(out["schemaView"]["to"], "2.0.0");
        assert_eq!(
            out["schemaView"]["data"]["ratedEnergyWh"].as_f64(),
            Some(4800.0)
        );
        // Canonical passport is untouched — no derived field leaks into it.
        assert!(out["passport"]["productGroupData"]["ratedEnergyWh"].is_null());
    }

    #[test]
    fn schema_view_refuses_unbridged_version() {
        let view = battery_view();
        assert!(matches!(
            build_schema_view(&view, "battery", "1.0.0", "3.0.0"),
            Err(SchemaViewError::Upcast(UpcastError::NoPath { .. }))
        ));
    }

    #[test]
    fn schema_view_refuses_downcast() {
        let view = battery_view();
        assert!(matches!(
            build_schema_view(&view, "battery", "2.0.0", "1.0.0"),
            Err(SchemaViewError::Upcast(UpcastError::NotAnUpcast { .. }))
        ));
    }
}
