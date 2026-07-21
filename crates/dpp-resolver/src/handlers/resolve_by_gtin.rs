//! Handlers for the GS1 Digital Link routes, conforming to GS1-CRSV1.
//!
//! A printed carrier may carry more than the GTIN. This node's own publisher
//! emits `/01/{gtin}[/10/{batch}]/21/{serial}`, and a scanner reading any
//! conformant label may present the same shape, so every AI combination the
//! carrier can produce is mounted here.
//!
//! **Resolution is keyed on the GTIN alone.** The batch (AI 10) and serial
//! (AI 21) segments are accepted and ignored: the serial this node prints is
//! derived from the passport id for uniqueness on the label, not a lookup key,
//! and no route may 404 merely because a label carried more precision than the
//! resolver indexes.

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::IntoResponse,
};
use dpp_digital_link::Gs1LinkType;
use serde::Deserialize;
use serde_json::Value;

use crate::{infra::did, state::AppState};

/// Query parameters for the GS1 Digital Link resolver endpoint (`/01/{gtin}`).
#[derive(Deserialize)]
pub struct ByGtinQuery {
    /// GS1 link type qualifier. `"linkset"` returns an RFC 9264 linkset;
    /// `"gs1:pip"` / `"gs1:dpp"` redirect to the DPP page. Omit for the
    /// default HTML redirect.
    #[serde(rename = "linkType")]
    pub link_type: Option<String>,
}

/// GS1 Digital Link resolver — `GET /01/{gtin}[?linkType=…]`
///
/// Conforms to the GS1 Conformant Resolver Standard (GS1-CRSV1):
/// - `?linkType=linkset` or `Accept: application/linkset+json` → RFC 9264 linkset
/// - `?linkType=gs1:pip` / `?linkType=gs1:dpp` → 307 redirect to DPP page
/// - Default (no qualifier) → 307 redirect to the HTML product page
pub async fn resolve_by_gtin_handler(
    state: State<AppState>,
    Path(gtin): Path<String>,
    query: Query<ByGtinQuery>,
    headers: HeaderMap,
) -> impl IntoResponse {
    resolve_gtin(state, gtin, query, headers).await
}

/// `GET /01/{gtin}/21/{serial}` — GTIN + serial. Resolves on the GTIN.
pub async fn resolve_by_gtin_serial_handler(
    state: State<AppState>,
    Path((gtin, _serial)): Path<(String, String)>,
    query: Query<ByGtinQuery>,
    headers: HeaderMap,
) -> impl IntoResponse {
    resolve_gtin(state, gtin, query, headers).await
}

/// `GET /01/{gtin}/10/{batch}` — GTIN + batch/lot. Resolves on the GTIN.
pub async fn resolve_by_gtin_batch_handler(
    state: State<AppState>,
    Path((gtin, _batch)): Path<(String, String)>,
    query: Query<ByGtinQuery>,
    headers: HeaderMap,
) -> impl IntoResponse {
    resolve_gtin(state, gtin, query, headers).await
}

/// `GET /01/{gtin}/10/{batch}/21/{serial}` — the full shape this node's own
/// carrier emits for a batched product. Resolves on the GTIN.
pub async fn resolve_by_gtin_batch_serial_handler(
    state: State<AppState>,
    Path((gtin, _batch, _serial)): Path<(String, String, String)>,
    query: Query<ByGtinQuery>,
    headers: HeaderMap,
) -> impl IntoResponse {
    resolve_gtin(state, gtin, query, headers).await
}

/// Shared implementation: every GS1 Digital Link route resolves on the GTIN.
async fn resolve_gtin(
    State(state): State<AppState>,
    gtin: String,
    Query(query): Query<ByGtinQuery>,
    headers: HeaderMap,
) -> axum::response::Response {
    // Validate the GTIN at the edge before it reaches the server-to-server vault
    // URL — a percent-decoded `../admin` must not path-traverse/SSRF the vault.
    if !crate::domain::is_valid_gtin(&gtin) {
        return (
            StatusCode::NOT_FOUND,
            [(header::CONTENT_TYPE, "application/json")],
            r#"{"error":"NOT_FOUND","message":"No published DPP for this GTIN"}"#.to_owned(),
        )
            .into_response();
    }

    let passport = match fetch_by_gtin(&state, &gtin).await {
        Ok(v) => v,
        Err(status) => {
            return (
                status,
                [(header::CONTENT_TYPE, "application/json")],
                r#"{"error":"NOT_FOUND","message":"No published DPP for this GTIN"}"#.to_owned(),
            )
                .into_response();
        }
    };

    // Verify the public signature against the operator DID before trusting
    // anything the vault returned — every other resolver route (by id) does
    // this; resolving by GTIN must not be a second, unverified path to the
    // same passport data. Fails closed, same as `resolve_json`/`resolve_html`.
    let passport =
        match did::verify_passport_jws(&state.http, &state.operator_did_url, &passport).await {
            Ok(v) => v,
            Err(status) => {
                return (
                status,
                [(header::CONTENT_TYPE, "application/json")],
                r#"{"error":"UNVERIFIED","message":"Passport signature could not be verified"}"#
                    .to_owned(),
            )
                .into_response();
            }
        };

    let passport_id = match passport.get("id").and_then(Value::as_str) {
        Some(id) => id.to_owned(),
        None => {
            return (StatusCode::BAD_GATEWAY, "").into_response();
        }
    };

    // The resolver's own trusted base URL. It is NOT derived from the passport's
    // `qrCodeUrl`: that field is mutable and content-binding-exempt (tamperable),
    // so trusting it would let an altered value 307-redirect the scan to an
    // attacker host — the exact open redirect the QR-code handler hardcodes
    // against.
    let base_url = state.resolver_base_url.as_str();

    // Linkset request: ?linkType=linkset OR Accept: application/linkset+json
    let wants_linkset = query.link_type.as_deref() == Some("linkset")
        || headers
            .get(header::ACCEPT)
            .and_then(|v| v.to_str().ok())
            .map(|a| a.contains("application/linkset+json"))
            .unwrap_or(false);

    if wants_linkset {
        let body = serde_json::to_string(&build_linkset(base_url, &gtin, &passport_id, &passport))
            .unwrap_or_default();
        return (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/linkset+json")],
            body,
        )
            .into_response();
    }

    // Named link type redirect
    if let Some(ref lt) = query.link_type {
        let parsed = Gs1LinkType::parse(lt);
        match parsed {
            Gs1LinkType::ProductInformationPage
            | Gs1LinkType::DigitalProductPassport
            | Gs1LinkType::ElectronicLeaflet
            | Gs1LinkType::SustainabilityInfo
            | Gs1LinkType::RecyclingInfo
            | Gs1LinkType::CertificationInfo => {
                return redirect(&format!("{base_url}/dpp/{passport_id}"));
            }
            _ => {
                return (
                    StatusCode::NOT_FOUND,
                    [(header::CONTENT_TYPE, "application/json")],
                    format!(r#"{{"error":"LINK_TYPE_NOT_FOUND","linkType":{lt:?}}}"#),
                )
                    .into_response();
            }
        }
    }

    // Default: redirect to the DPP page (HTML)
    redirect(&format!("{base_url}/dpp/{passport_id}"))
}

fn redirect(location: &str) -> axum::response::Response {
    (
        StatusCode::TEMPORARY_REDIRECT,
        [(header::LOCATION, location.to_owned())],
        "",
    )
        .into_response()
}

/// Build a GS1 linkset per RFC 9264 / GS1 Digital Link standard. When the
/// passport cites a predecessor (second-life successor linkage), the linkset
/// also advertises an Odal `predecessor` relation pointing at the source
/// passport, so a scanner can walk up the lineage.
fn build_linkset(
    base_url: &str,
    gtin: &str,
    passport_id: &str,
    passport: &serde_json::Value,
) -> serde_json::Value {
    let anchor = format!("{base_url}/01/{gtin}");
    let dpp_url = format!("{base_url}/dpp/{passport_id}");
    let mut linkset = serde_json::json!({
        "anchor": anchor,
        "linkset": [{
            "anchor": anchor,
            "https://ref.gs1.org/voc/pip": [
                {"href": dpp_url, "type": "text/html"}
            ],
            "https://ref.gs1.org/voc/dpp": [
                {"href": dpp_url, "type": "application/ld+json"}
            ]
        }]
    });
    if let Some(parent_uri) = passport
        .get("parentPassportRef")
        .and_then(|r| r.get("uri"))
        .and_then(serde_json::Value::as_str)
        && let Some(inner) = linkset["linkset"][0].as_object_mut()
    {
        inner.insert(
            Gs1LinkType::Predecessor.as_gs1_uri().to_owned(),
            serde_json::json!([{ "href": parent_uri, "type": "application/ld+json" }]),
        );
    }
    // Bill of materials: one `hasComponent` relation per constituent passport, so
    // a scanner can walk down into the assembly.
    let component_links: Vec<serde_json::Value> = passport
        .get("componentRefs")
        .and_then(serde_json::Value::as_array)
        .map(|refs| {
            refs.iter()
                .filter_map(|c| c.get("uri").and_then(serde_json::Value::as_str))
                .map(|uri| serde_json::json!({ "href": uri, "type": "application/ld+json" }))
                .collect()
        })
        .unwrap_or_default();
    if !component_links.is_empty()
        && let Some(inner) = linkset["linkset"][0].as_object_mut()
    {
        inner.insert(
            Gs1LinkType::HasComponent.as_gs1_uri().to_owned(),
            serde_json::Value::Array(component_links),
        );
    }
    linkset
}

async fn fetch_by_gtin(state: &AppState, gtin: &str) -> Result<Value, StatusCode> {
    let url = format!("{}/public/dpp/by-gtin/{gtin}", state.vault_base_url);
    let resp = state
        .http
        .get(&url)
        .send()
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?;

    if matches!(
        resp.status(),
        reqwest::StatusCode::NOT_FOUND | reqwest::StatusCode::BAD_REQUEST
    ) {
        return Err(StatusCode::NOT_FOUND);
    }
    if !resp.status().is_success() {
        return Err(StatusCode::BAD_GATEWAY);
    }

    resp.json::<Value>()
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_linkset_has_correct_structure() {
        let ls = build_linkset(
            "https://id.odal-node.io",
            "09506000134352",
            "abc-123",
            &serde_json::json!({}),
        );
        assert_eq!(
            ls["anchor"].as_str().unwrap(),
            "https://id.odal-node.io/01/09506000134352"
        );
        let inner = &ls["linkset"][0];
        assert!(inner.get("https://ref.gs1.org/voc/pip").is_some());
        assert!(inner.get("https://ref.gs1.org/voc/dpp").is_some());
        // No lineage relation for a passport that cites no predecessor.
        assert!(
            inner
                .get("https://ref.odal-node.io/voc/predecessor")
                .is_none()
        );
    }

    #[test]
    fn build_linkset_advertises_predecessor_when_cited() {
        let passport = serde_json::json!({
            "parentPassportRef": {
                "uri": "https://id.other-op.example/dpp/parent-xyz",
                "publicJwsHash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            }
        });
        let ls = build_linkset(
            "https://id.odal-node.io",
            "09506000134352",
            "abc-123",
            &passport,
        );
        let predecessor = &ls["linkset"][0]["https://ref.odal-node.io/voc/predecessor"];
        assert_eq!(
            predecessor[0]["href"].as_str().unwrap(),
            "https://id.other-op.example/dpp/parent-xyz"
        );
    }

    #[test]
    fn build_linkset_advertises_each_component() {
        let passport = serde_json::json!({
            "componentRefs": [
                { "uri": "https://id.a.example/dpp/mod-1", "publicJwsHash": "aa" },
                { "uri": "https://id.b.example/dpp/mod-2", "publicJwsHash": "bb" }
            ]
        });
        let ls = build_linkset(
            "https://id.odal-node.io",
            "09506000134352",
            "pack-1",
            &passport,
        );
        let components = ls["linkset"][0]["https://ref.odal-node.io/voc/hasComponent"]
            .as_array()
            .expect("hasComponent relation present");
        let hrefs: Vec<&str> = components
            .iter()
            .filter_map(|c| c["href"].as_str())
            .collect();
        assert_eq!(
            hrefs,
            [
                "https://id.a.example/dpp/mod-1",
                "https://id.b.example/dpp/mod-2"
            ]
        );
    }
}
