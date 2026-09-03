use std::sync::OnceLock;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use dpp_domain::schemas::{LensRegistry, UpcastError};
use dpp_domain::status::PassportStatus;

use crate::public_view::signed_public_view;
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
        // Served for a **deactivated** passport as well as a published one.
        //
        // Deactivation is end of life for the *product*, not for the passport:
        // core's own status doc says the record "is retained (the DPP outlives
        // the product, EN 18221)", and this node enforces that on the write
        // side — it refuses to archive before `retention_until`, which for a
        // battery is ten years out. Answering `404` meanwhile made the retained
        // record unreachable and indistinguishable from one that never existed,
        // which is the opposite of retaining it.
        //
        // ESPR Art. 10(4)(i) is the basis: the passport is to "remain
        // available" for a period corresponding to "at least the expected
        // lifetime of a specific product". A recycler or authority scanning the
        // carrier on an end-of-life product is precisely the reader that
        // requirement exists for.
        //
        // Only the public-facing surface is served — the same
        // `signed_public_view` a published passport gets, filtered by the same
        // disclosure lens. End of life widens nothing.
        Ok(Some(p))
            if p.status == PassportStatus::Published || p.status == PassportStatus::Deactivated =>
        {
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
