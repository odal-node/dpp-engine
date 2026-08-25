//! Handler for `GET /dpp/{dppId}` — serves a DPP as JSON-LD with access-tier filtering.

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header},
    response::IntoResponse,
};
use dpp_common::http_problem;
use serde_json::Value;

use dpp_domain::Audience;
use dpp_domain::access::{
    DocumentScope, ProductGroupAccessPolicy, filter_by_audience, filter_by_audience_in_scope,
};

use crate::{infra::did, state::AppState};

/// Serve a DPP as JSON-LD.
///
/// Returns the passport augmented with `@context` when the client sends
/// `Accept: application/json` or `Accept: application/ld+json`.
pub async fn resolve_json_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(dpp_id): Path<String>,
) -> impl IntoResponse {
    // Validate the id at the resolver's own edge before it touches a cache
    // key or a server-to-server URL — do not rely on the vault for output safety.
    if !crate::domain::is_valid_dpp_id(&dpp_id) {
        return fetch_problem(StatusCode::NOT_FOUND);
    }

    let caller_tier = parse_access_tier(&headers);

    let cache_key = format!("resolver:json:{dpp_id}:{caller_tier:?}");

    // Try cache first (tier-aware key so each view is cached separately).
    if let Some(cached) = state.cache.get(&cache_key).await {
        return (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/ld+json")],
            cached,
        )
            .into_response();
    }

    let passport = match fetch_passport(&state, &dpp_id).await {
        Ok(v) => v,
        Err(status) => return fetch_problem(status),
    };

    // Verify the public signature against the operator DID. We serve the
    // *verified* payload (the signed public view), then re-attach the proof so a
    // third party can independently re-verify it. Fails closed.
    let verified = match did::verify_passport_jws(&state.http, &state.operator_did_url, &passport)
        .await
    {
        Ok(v) => v,
        Err(status) => {
            let detail = if status == StatusCode::SERVICE_UNAVAILABLE {
                "The passport could not be verified right now; try again later."
            } else {
                "The passport's digital signature could not be verified."
            };
            let problem =
                http_problem::Problem::new(status, status.canonical_reason().unwrap_or("Error"))
                    .with_detail(detail);
            return (
                status,
                [(header::CONTENT_TYPE, "application/ld+json")],
                serde_json::to_string(&problem).unwrap_or_default(),
            )
                .into_response();
        }
    };

    // ── Access-tier filtering ───────────────────────────────────────────
    let mut doc = apply_access_tier_filter(verified, caller_tier);

    // Re-attach the public proof so consumers can verify independently.
    if let (Some(obj), Some(sig)) = (doc.as_object_mut(), passport.get("publicJwsSignature")) {
        obj.insert("publicJwsSignature".into(), sig.clone());
    }

    // Inject the JSON-LD context from `dpp-vc`, never a literal built here.
    // This handler used to construct its own, referencing a URL that returned
    // 404 — a remote context is fetched by the consumer at expansion time, so a
    // dead one makes this door convey no linked data at all. One definition,
    // one place to check.
    if let Some(obj) = doc.as_object_mut() {
        obj.insert("@context".into(), dpp_vc::context_value());
    }

    let body = serde_json::to_string(&doc).unwrap_or_default();
    state.cache.set(&cache_key, &body).await;

    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/ld+json")],
        body,
    )
        .into_response()
}

/// The access tier granted to an (unauthenticated) public resolver request.
///
/// The public resolver serves the **Public** tier only. A consumer-supplied
/// `X-Access-Tier` header is deliberately ignored — granting a tier on a
/// self-declared header is an authorization bypass (anyone could read
/// professional/confidential fields). Elevated tiers require an authenticated
/// channel: the operator-authenticated vault API, or (future) an
/// operator-signed tier token verified against the operator DID.
fn parse_access_tier(_headers: &HeaderMap) -> Audience {
    Audience::Public
}

/// Apply two-level access tier filtering:
/// 1. Top-level passport fields (jws, batchId, retentionLocked).
/// 2. ProductGroup-specific fields within `productGroupData` (e.g. battery supply chain data).
fn apply_access_tier_filter(passport: Value, tier: Audience) -> Value {
    // Read before filtering: the version that governs this passport's disclosure
    // is the one it was validated against, and it must be taken from the document
    // rather than assumed current. Absent, it stays empty and resolves to no
    // policy — which fails closed for any tagged record.
    let schema_version = passport
        .get("schemaVersion")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();

    let passport_policy = ProductGroupAccessPolicy::passport_default();
    let decision = filter_by_audience(&passport, &passport_policy, tier);
    let mut doc = decision.filtered_data;

    // Also filter product group data sub-object if present.
    if let Some(obj) = doc.as_object_mut()
        && let Some(sd) = obj.remove("productGroupData")
    {
        let product_group_policy = detect_product_group_policy(&sd, &schema_version);
        if let Some(policy) = product_group_policy {
            // The sub-object was removed from the envelope above, so it is now
            // its own root document — and its root is already inside the
            // product group. Filtering it as an envelope would apply none of
            // this product group's classes and serve every restricted field.
            let inner =
                filter_by_audience_in_scope(&sd, &policy, tier, DocumentScope::ProductGroupData);
            obj.insert("productGroupData".into(), inner.filtered_data);
        } else if is_tagged_unknown_product_group(&sd) {
            // Fail closed (RT2-1 / RT2-5): the sub-object carries a `product_group`
            // tag the catalog doesn't recognise, so we have no policy telling
            // us which fields are public. Rather than leak professional /
            // confidential fields, drop everything except the product group
            // identifier at non-elevated tiers.
            if tier == Audience::Public {
                obj.insert(
                    "productGroupData".into(),
                    redacted_unknown_product_group(&sd),
                );
            } else {
                obj.insert("productGroupData".into(), sd);
            }
        } else {
            // Genuinely untagged/legacy record: no product group tag and no shape
            // match. Preserve existing passthrough behaviour.
            obj.insert("productGroupData".into(), sd);
        }
    }

    doc
}

/// True when `productGroupData` carries a non-empty `product_group` tag (i.e. it is a tagged
/// record, as opposed to a legacy untagged one). Used to decide whether an
/// unrecognised product group should fail closed.
fn is_tagged_unknown_product_group(product_group_data: &Value) -> bool {
    product_group_data
        .as_object()
        .and_then(|o| o.get("productGroup"))
        .and_then(Value::as_str)
        .is_some_and(|s| !s.is_empty())
}

/// Minimal, fail-closed `productGroupData` for an unrecognised product group at the Public
/// tier: keep only the `product_group` identifier, drop every other (potentially
/// professional/confidential) field.
fn redacted_unknown_product_group(product_group_data: &Value) -> Value {
    let mut out = serde_json::Map::new();
    if let Some(tag) = product_group_data.get("productGroup") {
        out.insert("productGroup".into(), tag.clone());
    }
    Value::Object(out)
}

/// Select the product group-specific access policy from the catalog.
///
/// The stored `productGroupData` carries a `"product group"` discriminant; the policy and its
/// field tiers come from the catalog, so this covers every product group — not just
/// battery/textile. Falls back to field-shape detection for legacy records that
/// predate the tagged `productGroupData` format.
fn detect_product_group_policy(
    product_group_data: &Value,
    schema_version: &str,
) -> Option<ProductGroupAccessPolicy> {
    let obj = product_group_data.as_object()?;
    let key = match obj.get("productGroup").and_then(Value::as_str) {
        Some("unsoldGoods") => "unsold-goods",
        Some(tag) => tag,
        None if obj.contains_key("batteryChemistry") || obj.contains_key("battery_chemistry") => {
            "battery"
        }
        None if obj.contains_key("fibreComposition") || obj.contains_key("fibre_composition") => {
            "textile"
        }
        None => return None,
    };
    // Versioned deliberately: a published passport must be filtered by the
    // disclosure classes in force when its signature was frozen, not by whatever
    // the catalog says today. `None` here — unknown product group *or* unknown version —
    // lands on the fail-closed branch above, which only needs a `product_group` tag to
    // redact, so a known product group at an unrecognised version is covered too.
    ProductGroupAccessPolicy::for_schema_version(key, schema_version)
}

pub(crate) async fn fetch_passport(state: &AppState, dpp_id: &str) -> Result<Value, StatusCode> {
    let url = format!("{}/public/dpp/{dpp_id}", state.vault_base_url);
    let resp = state
        .http
        .get(&url)
        .send()
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?;

    // A malformed/unknown id (vault 400/404) is "not found" to a consumer, not
    // an upstream failure.
    if matches!(
        resp.status(),
        reqwest::StatusCode::NOT_FOUND | reqwest::StatusCode::BAD_REQUEST
    ) {
        return Err(StatusCode::NOT_FOUND);
    }
    if resp.status() == reqwest::StatusCode::GONE {
        return Err(StatusCode::GONE);
    }
    if !resp.status().is_success() {
        return Err(StatusCode::BAD_GATEWAY);
    }

    resp.json::<Value>()
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)
}

/// Render a passport-fetch failure as a problem document whose body agrees with
/// its own status line.
///
/// The status comes from [`fetch_passport`] — 404 for an unknown id, 410 for a
/// withdrawn passport, 502/503 for an upstream failure. The body used to be
/// hardcoded to a 404 "DPP not found" whatever the status was, so a withdrawn
/// passport arrived as `410 Gone` carrying a body that said it had never
/// existed. That is the one distinction 410 exists to draw, and a consumer
/// reading the structured half — which RFC 9457 says mirrors the status line —
/// got the opposite answer from the one in the headers.
pub(crate) fn fetch_problem(status: StatusCode) -> axum::response::Response {
    let detail = match status {
        StatusCode::GONE => "This passport has been withdrawn and is no longer served.",
        StatusCode::NOT_FOUND => "DPP not found",
        StatusCode::SERVICE_UNAVAILABLE => {
            "The passport could not be read right now; try again later."
        }
        _ => "The passport could not be read.",
    };
    let problem = http_problem::Problem::new(status, status.canonical_reason().unwrap_or("Error"))
        .with_detail(detail);
    (
        status,
        [(header::CONTENT_TYPE, "application/problem+json")],
        serde_json::to_string(&problem).unwrap_or_default(),
    )
        .into_response()
}

#[cfg(test)]
mod security_regression {
    //! **RT2-5**: access-tier redaction must fail *closed* for an unrecognised
    //! product group tag — it must not pass professional/confidential `productGroupData`
    //! fields through verbatim at the Public tier.
    use super::*;
    use serde_json::json;

    #[test]
    fn unknown_product_group_tag_fails_closed_at_public_tier() {
        let passport = json!({
            "id": "x",
            "productName": "Widget",
            "productGroupData": {
                "productGroup": "totallyMadeUpProductGroup",
                "supplierCostEur": 12.50,
                "internalNotes": "trade secret"
            }
        });
        let out = apply_access_tier_filter(passport, Audience::Public);
        let sd = out.get("productGroupData").expect("productGroupData kept");
        // Only the product group identifier survives; the unknown sensitive fields drop.
        assert_eq!(
            sd.get("productGroup").and_then(Value::as_str),
            Some("totallyMadeUpProductGroup")
        );
        assert!(sd.get("supplierCostEur").is_none(), "leaked: {sd}");
        assert!(sd.get("internalNotes").is_none(), "leaked: {sd}");
    }

    #[test]
    fn untagged_legacy_product_group_data_passes_through() {
        // No `product_group` tag and no recognised shape → legacy passthrough preserved.
        let passport = json!({
            "id": "x",
            "productGroupData": { "someLegacyField": "value" }
        });
        let out = apply_access_tier_filter(passport, Audience::Public);
        let sd = out.get("productGroupData").expect("productGroupData kept");
        assert_eq!(
            sd.get("someLegacyField").and_then(Value::as_str),
            Some("value")
        );
    }
}
