//! Handler for `GET /01/{gtin}` — GS1 Digital Link resolver conforming to GS1-CRSV1.

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::IntoResponse,
};
use dpp_digital_link::Gs1LinkType;
use serde::Deserialize;
use serde_json::Value;

use crate::state::AppState;

/// The resolver's own public base URL (its GS1 Digital Link host). Hardcoded
/// rather than derived from mutable passport data, matching the QR-code handler
/// — this is what closes the open-redirect surface.
const RESOLVER_BASE_URL: &str = "https://id.odal-node.io";

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
    State(state): State<AppState>,
    Path(gtin): Path<String>,
    Query(query): Query<ByGtinQuery>,
    headers: HeaderMap,
) -> impl IntoResponse {
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
    let base_url = RESOLVER_BASE_URL;

    // Linkset request: ?linkType=linkset OR Accept: application/linkset+json
    let wants_linkset = query.link_type.as_deref() == Some("linkset")
        || headers
            .get(header::ACCEPT)
            .and_then(|v| v.to_str().ok())
            .map(|a| a.contains("application/linkset+json"))
            .unwrap_or(false);

    if wants_linkset {
        let body = serde_json::to_string(&build_linkset(base_url, &gtin, &passport_id))
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

/// Build a GS1 linkset per RFC 9264 / GS1 Digital Link standard.
fn build_linkset(base_url: &str, gtin: &str, passport_id: &str) -> serde_json::Value {
    let anchor = format!("{base_url}/01/{gtin}");
    let dpp_url = format!("{base_url}/dpp/{passport_id}");
    serde_json::json!({
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
    })
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
        let ls = build_linkset("https://id.odal-node.io", "09506000134352", "abc-123");
        assert_eq!(
            ls["anchor"].as_str().unwrap(),
            "https://id.odal-node.io/01/09506000134352"
        );
        let inner = &ls["linkset"][0];
        assert!(inner.get("https://ref.gs1.org/voc/pip").is_some());
        assert!(inner.get("https://ref.gs1.org/voc/dpp").is_some());
    }
}
