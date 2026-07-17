//! Handler for `GET /dpp/{dppId}` when `Accept: text/html` — renders a self-contained
//! HTML passport page with sector-specific tables and an inline SVG QR code.

mod esc;
mod sections;

use axum::{
    extract::{Path, State},
    http::{HeaderValue, StatusCode, header},
    response::IntoResponse,
};
use qrcode::QrCode;

use esc::esc;

use crate::{infra::did, state::AppState};

/// Serve a DPP as a human-readable HTML page.
///
/// Invoked when the `Accept` header contains `text/html`.
/// Intentionally self-contained — no external CSS/JS — for WASM/edge compatibility.
pub async fn resolve_html_handler(
    State(state): State<AppState>,
    Path(dpp_id): Path<String>,
) -> impl IntoResponse {
    // Validate the id at the resolver's own edge before it touches a cache
    // key, a server-to-server URL, or the rendered SVG/HTML — do not rely on the
    // vault for this surface's output safety.
    if !crate::domain::is_valid_dpp_id(&dpp_id) {
        return (
            StatusCode::NOT_FOUND,
            [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
            error_page("Digital Product Passport not found"),
        )
            .into_response();
    }

    let cache_key = format!("resolver:html:{dpp_id}");

    if let Some(cached) = state.cache.get(&cache_key).await {
        return (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
            cached,
        )
            .into_response();
    }

    let url = format!("{}/public/dpp/{dpp_id}", state.vault_base_url);
    let resp = match state.http.get(&url).send().await {
        Ok(r) => r,
        Err(_) => {
            return (
                StatusCode::BAD_GATEWAY,
                [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
                error_page("Service unavailable"),
            )
                .into_response();
        }
    };

    if matches!(
        resp.status(),
        reqwest::StatusCode::NOT_FOUND | reqwest::StatusCode::BAD_REQUEST
    ) {
        return (
            StatusCode::NOT_FOUND,
            [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
            error_page("Digital Product Passport not found"),
        )
            .into_response();
    }

    if resp.status() == reqwest::StatusCode::GONE {
        return (
            StatusCode::GONE,
            [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
            error_page("This Digital Product Passport is no longer active"),
        )
            .into_response();
    }

    if !resp.status().is_success() {
        return (
            StatusCode::BAD_GATEWAY,
            [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
            error_page("Failed to load passport data"),
        )
            .into_response();
    }

    let passport: serde_json::Value = match resp.json().await {
        Ok(v) => v,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
                error_page("Failed to parse passport data"),
            )
                .into_response();
        }
    };

    // Verify the public signature against the operator DID. We render from the
    // *verified* payload — the exact content that was signed — never the
    // separately-served JSON. Fails closed.
    let verified = match did::verify_passport_jws(&state.http, &state.operator_did_url, &passport)
        .await
    {
        Ok(v) => v,
        Err(status) => {
            let message = if status == StatusCode::SERVICE_UNAVAILABLE {
                "This Digital Product Passport cannot be verified right now — please try again later."
            } else {
                "Passport signature verification failed — this passport may have been tampered with."
            };
            return (
                status,
                [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
                error_page(message),
            )
                .into_response();
        }
    };

    let html = render_html(&dpp_id, &verified, &state.resolver_base_url);
    state.cache.set(&cache_key, &html).await;

    (
        StatusCode::OK,
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/html; charset=utf-8"),
            ),
            (
                // Keep downstream/CDN caching within the recall-propagation
                // window so a suspended passport is not pinned as active in an
                // intermediary cache longer than the resolver's own TTL.
                header::CACHE_CONTROL,
                HeaderValue::from_static("public, max-age=30, stale-while-revalidate=15"),
            ),
        ],
        html,
    )
        .into_response()
}

fn render_html(dpp_id: &str, p: &serde_json::Value, resolver_base_url: &str) -> String {
    let product = p
        .get("productName")
        .and_then(|v| v.as_str())
        .unwrap_or("Unknown product");
    let product = esc(product);
    let manufacturer = esc(p
        .get("manufacturer")
        .and_then(|m| m.get("name"))
        .and_then(|v| v.as_str())
        .unwrap_or("Unknown"));
    let status = esc(p
        .get("status")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown"));
    // `gtin` lives in the sector-specific payload, not on the passport itself
    // (see `crate::domain::carrier_uri`'s doc comment for the JSON shape).
    let gtin = esc(p
        .get("sectorData")
        .and_then(|sd| sd.get("gtin"))
        .and_then(|v| v.as_str())
        .unwrap_or("-"));
    let batch_id = esc(p.get("batchId").and_then(|v| v.as_str()).unwrap_or("-"));

    let sector_html = sections::build_sector_section(p);
    let qr_svg = crate::domain::carrier_uri(p, resolver_base_url, dpp_id)
        .map(|uri| build_qr_svg(&uri))
        .unwrap_or_default();
    // Escape the id for HTML contexts (the QR above encodes the carrier URI).
    let dpp_id = esc(dpp_id);
    let page_url = format!("{}/dpp/{dpp_id}", resolver_base_url.trim_end_matches('/'));

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta property="og:title" content="{product}">
  <meta property="og:description" content="Digital Product Passport — {manufacturer}">
  <meta property="og:url" content="{page_url}">
  <meta property="og:type" content="website">
  <title>DPP — {product}</title>
  <style>
    *{{box-sizing:border-box;margin:0;padding:0}}
    body{{font-family:system-ui,-apple-system,sans-serif;background:#f3f4f6;color:#111827;padding:1rem}}
    .card{{background:#fff;border-radius:10px;box-shadow:0 2px 12px rgba(0,0,0,.08);max-width:720px;margin:0 auto;padding:2rem}}
    h1{{font-size:1.4rem;font-weight:700;margin-bottom:.35rem;line-height:1.3}}
    h2{{font-size:1rem;font-weight:600;margin:1.4rem 0 .5rem;color:#374151}}
    .badge{{display:inline-flex;align-items:center;padding:.25em .75em;border-radius:4px;font-size:.75rem;font-weight:700;letter-spacing:.05em;text-transform:uppercase;margin-bottom:1rem}}
    .badge-active,.badge-published{{background:#d1fae5;color:#065f46}}
    .badge-draft{{background:#fef3c7;color:#92400e}}
    .badge-suspended{{background:#fee2e2;color:#991b1b}}
    .badge-archived{{background:#e5e7eb;color:#374151}}
    table{{width:100%;border-collapse:collapse;margin-top:.5rem}}
    th,td{{text-align:left;padding:.5rem .4rem;border-bottom:1px solid #f3f4f6;vertical-align:top}}
    th{{width:44%;color:#6b7280;font-weight:500;font-size:.875rem}}
    td{{font-size:.9rem}}
    .fibre-bar{{display:flex;height:18px;border-radius:4px;overflow:hidden;margin-top:.3rem}}
    .fibre-seg{{height:100%;display:flex;align-items:center;justify-content:center;font-size:.65rem;color:#fff;font-weight:600;white-space:nowrap;overflow:hidden}}
    .qr-wrap{{text-align:center;margin-top:1.5rem}}
    .qr-wrap svg{{max-width:140px;height:auto}}
    footer{{margin-top:1.5rem;font-size:.75rem;color:#9ca3af;text-align:center}}
    footer a{{color:#6b7280;text-decoration:none}}
    footer a:hover{{text-decoration:underline}}
    @media(max-width:480px){{.card{{padding:1rem}}h1{{font-size:1.2rem}}th,td{{padding:.4rem .2rem}}}}
  </style>
</head>
<body>
  <div class="card">
    <h1>{product}</h1>
    <span class="badge badge-{status}" role="status" aria-label="Passport status: {status}">{status}</span>

    <h2>Product Information</h2>
    <table aria-label="Product information">
      <tr><th scope="row">Passport ID</th><td><code>{dpp_id}</code></td></tr>
      <tr><th scope="row">Manufacturer</th><td>{manufacturer}</td></tr>
      <tr><th scope="row">GTIN</th><td>{gtin}</td></tr>
      <tr><th scope="row">Batch ID</th><td>{batch_id}</td></tr>
    </table>

    {sector_html}

    <div class="qr-wrap" aria-label="QR code linking to this passport">
      {qr_svg}
      <p style="font-size:.7rem;color:#9ca3af;margin-top:.3rem">Scan to verify</p>
    </div>

    <footer>
      Powered by <a href="https://odal-node.io" rel="noopener">Odal Node</a>
      &nbsp;·&nbsp;
      <a href="/dpp/{dpp_id}">JSON-LD</a>
      &nbsp;·&nbsp;
      <a href="/dpp/{dpp_id}/qr">QR PNG</a>
    </footer>
  </div>
</body>
</html>"#
    )
}

/// Render a carrier URI as an inline SVG QR code.
fn build_qr_svg(carrier_uri: &str) -> String {
    let code = match QrCode::new(carrier_uri.as_bytes()) {
        Ok(c) => c,
        Err(_) => return String::new(),
    };

    let width = code.width();
    let colors = code.to_colors();
    let module_size = 4u32;
    let quiet = 4u32; // quiet zone in modules
    let total = (width as u32 + quiet * 2) * module_size;

    let mut rects = String::new();
    for (i, color) in colors.iter().enumerate() {
        if *color == qrcode::Color::Dark {
            let x = (i as u32 % width as u32 + quiet) * module_size;
            let y = (i as u32 / width as u32 + quiet) * module_size;
            rects.push_str(&format!(
                r#"<rect x="{x}" y="{y}" width="{module_size}" height="{module_size}"/>"#
            ));
        }
    }

    // Defense-in-depth: escape the URI in the SVG <title> text context. The id is
    // already constrained to a UUID at the handler edge, so this is belt-and-
    // suspenders against any future change to how the URI is built.
    let title_url = esc(carrier_uri);
    format!(
        r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {total} {total}" role="img" aria-label="QR code for this passport">
  <title>QR code: {title_url}</title>
  <rect width="{total}" height="{total}" fill="white"/>
  <g fill="black">{rects}</g>
</svg>"#
    )
}

fn error_page(message: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Error — Odal Node</title>
<style>body{{font-family:system-ui,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;background:#f5f5f5}}
.box{{background:#fff;padding:2rem;border-radius:8px;box-shadow:0 2px 8px rgba(0,0,0,.1);text-align:center}}
h1{{color:#dc3545;margin-bottom:.5rem}}p{{color:#555}}</style></head>
<body><div class="box"><h1>Error</h1><p>{message}</p></div></body>
</html>"#
    )
}
