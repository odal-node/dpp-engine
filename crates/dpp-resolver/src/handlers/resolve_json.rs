//! Handler for `GET /dpp/{dppId}` — serves a DPP as JSON-LD with access-tier filtering.

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header},
    response::IntoResponse,
};
use dpp_common::http_problem;
use serde_json::Value;

use dpp_crypto::access::{SectorAccessPolicy, filter_by_access_tier};
use dpp_domain::AccessTier;
use dpp_domain::SectorCatalog;

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
    // N-4: validate the id at the resolver's own edge before it touches a cache
    // key or a server-to-server URL — do not rely on the vault for output safety.
    if !crate::domain::is_valid_dpp_id(&dpp_id) {
        return (
            StatusCode::NOT_FOUND,
            axum::Json(http_problem::not_found("DPP not found")),
        )
            .into_response();
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
        Err(status) => {
            return (status, axum::Json(http_problem::not_found("DPP not found"))).into_response();
        }
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

    // Inject JSON-LD context
    if let Some(obj) = doc.as_object_mut() {
        obj.insert(
            "@context".into(),
            serde_json::json!([
                "https://www.w3.org/ns/did/v1",
                "https://odal-node.io/schemas/dpp/v1"
            ]),
        );
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
fn parse_access_tier(_headers: &HeaderMap) -> AccessTier {
    AccessTier::Public
}

/// Apply two-level access tier filtering:
/// 1. Top-level passport fields (jws, batchId, retentionLocked).
/// 2. Sector-specific fields within `sectorData` (e.g. battery supply chain data).
fn apply_access_tier_filter(passport: Value, tier: AccessTier) -> Value {
    let passport_policy = SectorAccessPolicy::passport_default();
    let decision = filter_by_access_tier(&passport, &passport_policy, tier);
    let mut doc = decision.filtered_data;

    // Also filter sector data sub-object if present.
    if let Some(obj) = doc.as_object_mut()
        && let Some(sd) = obj.remove("sectorData")
    {
        let sector_policy = detect_sector_policy(&sd);
        if let Some(policy) = sector_policy {
            let inner = filter_by_access_tier(&sd, &policy, tier);
            obj.insert("sectorData".into(), inner.filtered_data);
        } else if is_tagged_unknown_sector(&sd) {
            // Fail closed (RT2-1 / RT2-5): the sub-object carries a `sector`
            // tag the catalog doesn't recognise, so we have no policy telling
            // us which fields are public. Rather than leak professional /
            // confidential fields, drop everything except the sector
            // identifier at non-elevated tiers.
            if tier == AccessTier::Public {
                obj.insert("sectorData".into(), redacted_unknown_sector(&sd));
            } else {
                obj.insert("sectorData".into(), sd);
            }
        } else {
            // Genuinely untagged/legacy record: no sector tag and no shape
            // match. Preserve existing passthrough behaviour.
            obj.insert("sectorData".into(), sd);
        }
    }

    doc
}

/// True when `sectorData` carries a non-empty `sector` tag (i.e. it is a tagged
/// record, as opposed to a legacy untagged one). Used to decide whether an
/// unrecognised sector should fail closed.
fn is_tagged_unknown_sector(sector_data: &Value) -> bool {
    sector_data
        .as_object()
        .and_then(|o| o.get("sector"))
        .and_then(Value::as_str)
        .is_some_and(|s| !s.is_empty())
}

/// Minimal, fail-closed `sectorData` for an unrecognised sector at the Public
/// tier: keep only the `sector` identifier, drop every other (potentially
/// professional/confidential) field.
fn redacted_unknown_sector(sector_data: &Value) -> Value {
    let mut out = serde_json::Map::new();
    if let Some(tag) = sector_data.get("sector") {
        out.insert("sector".into(), tag.clone());
    }
    Value::Object(out)
}

/// Process-wide sector catalog (manifests parsed once).
fn catalog() -> &'static SectorCatalog {
    static CATALOG: std::sync::OnceLock<SectorCatalog> = std::sync::OnceLock::new();
    CATALOG.get_or_init(SectorCatalog::new)
}

/// Select the sector-specific access policy from the catalog.
///
/// The stored `sectorData` carries a `"sector"` discriminant; the policy and its
/// field tiers come from the catalog, so this covers every sector — not just
/// battery/textile. Falls back to field-shape detection for legacy records that
/// predate the tagged `sectorData` format.
fn detect_sector_policy(sector_data: &Value) -> Option<SectorAccessPolicy> {
    let obj = sector_data.as_object()?;
    let key = match obj.get("sector").and_then(Value::as_str) {
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
    SectorAccessPolicy::from_catalog(catalog(), key)
}

async fn fetch_passport(state: &AppState, dpp_id: &str) -> Result<Value, StatusCode> {
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

#[cfg(test)]
mod security_regression {
    //! **RT2-5**: access-tier redaction must fail *closed* for an unrecognised
    //! sector tag — it must not pass professional/confidential `sectorData`
    //! fields through verbatim at the Public tier.
    use super::*;
    use serde_json::json;

    #[test]
    fn unknown_sector_tag_fails_closed_at_public_tier() {
        let passport = json!({
            "id": "x",
            "productName": "Widget",
            "sectorData": {
                "sector": "totallyMadeUpSector",
                "supplierCostEur": 12.50,
                "internalNotes": "trade secret"
            }
        });
        let out = apply_access_tier_filter(passport, AccessTier::Public);
        let sd = out.get("sectorData").expect("sectorData kept");
        // Only the sector identifier survives; the unknown sensitive fields drop.
        assert_eq!(
            sd.get("sector").and_then(Value::as_str),
            Some("totallyMadeUpSector")
        );
        assert!(sd.get("supplierCostEur").is_none(), "leaked: {sd}");
        assert!(sd.get("internalNotes").is_none(), "leaked: {sd}");
    }

    #[test]
    fn untagged_legacy_sector_data_passes_through() {
        // No `sector` tag and no recognised shape → legacy passthrough preserved.
        let passport = json!({
            "id": "x",
            "sectorData": { "someLegacyField": "value" }
        });
        let out = apply_access_tier_filter(passport, AccessTier::Public);
        let sd = out.get("sectorData").expect("sectorData kept");
        assert_eq!(
            sd.get("someLegacyField").and_then(Value::as_str),
            Some("value")
        );
    }
}
