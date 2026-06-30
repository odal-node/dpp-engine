//! Handler for `GET /dpp/{dppId}` when `Accept: text/html` — renders a self-contained
//! HTML passport page with sector-specific tables and an inline SVG QR code.

use axum::{
    extract::{Path, State},
    http::{HeaderValue, StatusCode, header},
    response::IntoResponse,
};
use qrcode::QrCode;

use crate::{infra::did, state::AppState};

/// Serve a DPP as a human-readable HTML page.
///
/// Invoked when the `Accept` header contains `text/html`.
/// Intentionally self-contained — no external CSS/JS — for WASM/edge compatibility.
pub async fn resolve_html_handler(
    State(state): State<AppState>,
    Path(dpp_id): Path<String>,
) -> impl IntoResponse {
    // N-4: validate the id at the resolver's own edge before it touches a cache
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

    let html = render_html(&dpp_id, &verified);
    state.cache.set(&cache_key, &html).await;

    (
        StatusCode::OK,
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/html; charset=utf-8"),
            ),
            (
                // N-3: keep downstream/CDN caching within the recall-propagation
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

/// HTML-escape untrusted text for both element and double-quoted attribute
/// contexts. Passport fields are operator/supplier-supplied free text, so every
/// interpolated value is escaped to prevent stored XSS on the public page.
fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn render_html(dpp_id: &str, p: &serde_json::Value) -> String {
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
    let gtin = esc(p.get("gtin").and_then(|v| v.as_str()).unwrap_or("-"));
    let batch_id = esc(p.get("batchId").and_then(|v| v.as_str()).unwrap_or("-"));
    let country = esc(p
        .get("countryOfOrigin")
        .and_then(|v| v.as_str())
        .unwrap_or("-"));

    let sector_html = build_sector_section(p);
    let qr_svg = build_qr_svg(dpp_id);
    // Escape the id for HTML contexts (the QR above encodes the raw id).
    let dpp_id = esc(dpp_id);

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta property="og:title" content="{product}">
  <meta property="og:description" content="Digital Product Passport — {manufacturer}">
  <meta property="og:url" content="https://passport.odal-node.io/dpp/{dpp_id}">
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
      <tr><th scope="row">Country of Origin</th><td>{country}</td></tr>
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

/// Build the sector-specific HTML section for every in-scope EU DPP sector.
fn build_sector_section(p: &serde_json::Value) -> String {
    let sector = p
        .get("sectorData")
        .and_then(|s| s.get("sector"))
        .and_then(|v| v.as_str())
        .unwrap_or("");

    match sector {
        "battery" => build_battery_section(p),
        "textile" | "unsoldGoods" => build_textile_section(p),
        "electronics" => build_electronics_section(p),
        "steel" => build_steel_section(p),
        "construction" => build_construction_section(p),
        "tyre" => build_tyre_section(p),
        "toy" => build_toy_section(p),
        "aluminium" => build_aluminium_section(p),
        "furniture" => build_furniture_section(p),
        "detergent" => build_detergent_section(p),
        _ => String::new(),
    }
}

fn build_battery_section(p: &serde_json::Value) -> String {
    let sd = match p.get("sectorData") {
        Some(v) => v,
        None => return String::new(),
    };

    let chemistry = esc(sd
        .get("batteryChemistry")
        .and_then(|v| v.as_str())
        .unwrap_or("-"));
    let voltage = sd
        .get("nominalVoltageV")
        .and_then(|v| v.as_f64())
        .map(|v| format!("{v:.1} V"))
        .unwrap_or_else(|| "-".into());
    let capacity = sd
        .get("nominalCapacityAh")
        .and_then(|v| v.as_f64())
        .map(|v| format!("{v:.1} Ah"))
        .unwrap_or_else(|| "-".into());
    let cycles = sd
        .get("expectedLifetimeCycles")
        .and_then(|v| v.as_u64())
        .map(|v| format!("{v}"))
        .unwrap_or_else(|| "-".into());
    let co2e = sd
        .get("co2ePerUnitKg")
        .and_then(|v| v.as_f64())
        .map(|v| format!("{v:.2} kg CO\u{2082}e"))
        .unwrap_or_else(|| "Not disclosed".into());
    let recycled_co = sd
        .get("recycledContentCobaltPct")
        .and_then(|v| v.as_f64())
        .map(|v| format!("{v:.1}%"))
        .unwrap_or_else(|| "-".into());
    let recycled_li = sd
        .get("recycledContentLithiumPct")
        .and_then(|v| v.as_f64())
        .map(|v| format!("{v:.1}%"))
        .unwrap_or_else(|| "-".into());

    format!(
        r#"<h2>Battery Information</h2>
    <table aria-label="Battery data">
      <tr><th scope="row">Chemistry</th><td>{chemistry}</td></tr>
      <tr><th scope="row">Nominal Voltage</th><td>{voltage}</td></tr>
      <tr><th scope="row">Nominal Capacity</th><td>{capacity}</td></tr>
      <tr><th scope="row">Expected Lifetime</th><td>{cycles} cycles</td></tr>
      <tr><th scope="row">Carbon Footprint</th><td>{co2e}</td></tr>
      <tr><th scope="row">Recycled Cobalt</th><td>{recycled_co}</td></tr>
      <tr><th scope="row">Recycled Lithium</th><td>{recycled_li}</td></tr>
    </table>"#
    )
}

fn build_textile_section(p: &serde_json::Value) -> String {
    let sd = match p.get("sectorData") {
        Some(v) => v,
        None => return String::new(),
    };

    let country = esc(sd
        .get("countryOfManufacturing")
        .and_then(|v| v.as_str())
        .unwrap_or("-"));
    let care = esc(sd
        .get("careInstructions")
        .and_then(|v| v.as_str())
        .unwrap_or("-"));
    let chemical = esc(sd
        .get("chemicalComplianceStandard")
        .and_then(|v| v.as_str())
        .unwrap_or("-"));
    let recycled = sd
        .get("recycledContentPct")
        .and_then(|v| v.as_f64())
        .map(|v| format!("{v:.1}%"))
        .unwrap_or_else(|| "-".into());

    // Fibre composition bar
    let fibres: Vec<(&str, f64)> = sd
        .get("fibreComposition")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|e| {
                    let name = e.get("fibre")?.as_str()?;
                    let pct = e.get("pct")?.as_f64()?;
                    Some((name, pct))
                })
                .collect()
        })
        .unwrap_or_default();

    let fibre_bar = build_fibre_bar(&fibres);
    let fibre_legend = build_fibre_legend(&fibres);

    format!(
        r#"<h2>Textile Information</h2>
    <table aria-label="Textile data">
      <tr><th scope="row">Country of Manufacturing</th><td>{country}</td></tr>
      <tr><th scope="row">Care Instructions</th><td>{care}</td></tr>
      <tr><th scope="row">Chemical Compliance</th><td>{chemical}</td></tr>
      <tr><th scope="row">Recycled Content</th><td>{recycled}</td></tr>
      <tr>
        <th scope="row">Fibre Composition</th>
        <td>
          {fibre_bar}
          {fibre_legend}
        </td>
      </tr>
    </table>"#
    )
}

fn build_electronics_section(p: &serde_json::Value) -> String {
    let sd = match p.get("sectorData") {
        Some(v) => v,
        None => return String::new(),
    };
    let category = esc(sd
        .get("productCategory")
        .and_then(|v| v.as_str())
        .unwrap_or("-"));
    let efficiency = esc(sd
        .get("energyEfficiencyClass")
        .and_then(|v| v.as_str())
        .unwrap_or("-"));
    let co2e = sd
        .get("co2ePerUnitKg")
        .and_then(|v| v.as_f64())
        .map(|v| format!("{v:.2} kg CO\u{2082}e"))
        .unwrap_or_else(|| "Not disclosed".into());
    let repair = sd
        .get("repairabilityScore")
        .and_then(|v| v.as_f64())
        .map(|v| format!("{v:.1} / 10"))
        .unwrap_or_else(|| "-".into());
    let lifetime = sd
        .get("expectedLifetimeYears")
        .and_then(|v| v.as_u64())
        .map(|v| format!("{v} years"))
        .unwrap_or_else(|| "-".into());
    format!(
        r#"<h2>Electronics Information</h2>
    <table aria-label="Electronics data">
      <tr><th scope="row">Product Category</th><td>{category}</td></tr>
      <tr><th scope="row">Energy Efficiency</th><td>{efficiency}</td></tr>
      <tr><th scope="row">Carbon Footprint</th><td>{co2e}</td></tr>
      <tr><th scope="row">Repairability Score</th><td>{repair}</td></tr>
      <tr><th scope="row">Expected Lifetime</th><td>{lifetime}</td></tr>
    </table>"#
    )
}

fn build_steel_section(p: &serde_json::Value) -> String {
    let sd = match p.get("sectorData") {
        Some(v) => v,
        None => return String::new(),
    };
    let route = esc(sd
        .get("productionRoute")
        .and_then(|v| v.as_str())
        .unwrap_or("-"));
    let category = esc(sd
        .get("productCategory")
        .and_then(|v| v.as_str())
        .unwrap_or("-"));
    let country = esc(sd
        .get("countryOfProduction")
        .and_then(|v| v.as_str())
        .unwrap_or("-"));
    let co2e = sd
        .get("co2ePerTonneSteel")
        .and_then(|v| v.as_f64())
        .map(|v| format!("{v:.3} t CO\u{2082}e / t steel"))
        .unwrap_or_else(|| "-".into());
    let recycled = sd
        .get("recycledScrapContentPct")
        .and_then(|v| v.as_f64())
        .map(|v| format!("{v:.1}%"))
        .unwrap_or_else(|| "-".into());
    format!(
        r#"<h2>Steel Product Information</h2>
    <table aria-label="Steel data">
      <tr><th scope="row">Product Category</th><td>{category}</td></tr>
      <tr><th scope="row">Production Route</th><td>{route}</td></tr>
      <tr><th scope="row">Country of Production</th><td>{country}</td></tr>
      <tr><th scope="row">Carbon Intensity</th><td>{co2e}</td></tr>
      <tr><th scope="row">Recycled Scrap Content</th><td>{recycled}</td></tr>
    </table>"#
    )
}

fn build_construction_section(p: &serde_json::Value) -> String {
    let sd = match p.get("sectorData") {
        Some(v) => v,
        None => return String::new(),
    };
    let family = esc(sd
        .get("productFamily")
        .and_then(|v| v.as_str())
        .unwrap_or("-"));
    let country = esc(sd
        .get("countryOfManufacture")
        .and_then(|v| v.as_str())
        .unwrap_or("-"));
    let unit = esc(sd
        .get("functionalUnit")
        .and_then(|v| v.as_str())
        .unwrap_or("unit"));
    let co2e = sd
        .get("co2ePerFunctionalUnitKg")
        .and_then(|v| v.as_f64())
        .map(|v| format!("{v:.2} kg CO\u{2082}e / {unit}"))
        .unwrap_or_else(|| "-".into());
    let ce = sd
        .get("ceMarking")
        .and_then(|v| v.as_bool())
        .map(|v| if v { "Yes" } else { "No" })
        .unwrap_or("-");
    format!(
        r#"<h2>Construction Product Information</h2>
    <table aria-label="Construction product data">
      <tr><th scope="row">Product Family</th><td>{family}</td></tr>
      <tr><th scope="row">Country of Manufacture</th><td>{country}</td></tr>
      <tr><th scope="row">Carbon Footprint</th><td>{co2e}</td></tr>
      <tr><th scope="row">CE Marking</th><td>{ce}</td></tr>
    </table>"#
    )
}

fn build_tyre_section(p: &serde_json::Value) -> String {
    let sd = match p.get("sectorData") {
        Some(v) => v,
        None => return String::new(),
    };
    let class = esc(sd.get("tyreClass").and_then(|v| v.as_str()).unwrap_or("-"));
    let fuel = esc(sd
        .get("fuelEfficiencyClass")
        .and_then(|v| v.as_str())
        .unwrap_or("-"));
    let wet = esc(sd
        .get("wetGripClass")
        .and_then(|v| v.as_str())
        .unwrap_or("-"));
    let noise = sd
        .get("externalRollingNoiseDb")
        .and_then(|v| v.as_f64())
        .map(|v| format!("{v:.0} dB"))
        .unwrap_or_else(|| "-".into());
    let noise_class = esc(sd
        .get("noisePerformanceClass")
        .and_then(|v| v.as_str())
        .unwrap_or("-"));
    format!(
        r#"<h2>Tyre Labelling Information</h2>
    <table aria-label="Tyre data">
      <tr><th scope="row">Tyre Class</th><td>{class}</td></tr>
      <tr><th scope="row">Fuel Efficiency (EU 2020/740)</th><td>{fuel}</td></tr>
      <tr><th scope="row">Wet Grip Class</th><td>{wet}</td></tr>
      <tr><th scope="row">External Rolling Noise</th><td>{noise}</td></tr>
      <tr><th scope="row">Noise Performance Class</th><td>{noise_class}</td></tr>
    </table>"#
    )
}

fn build_toy_section(p: &serde_json::Value) -> String {
    let sd = match p.get("sectorData") {
        Some(v) => v,
        None => return String::new(),
    };
    let age = esc(sd.get("ageGroup").and_then(|v| v.as_str()).unwrap_or("-"));
    let material = esc(sd
        .get("primaryMaterial")
        .and_then(|v| v.as_str())
        .unwrap_or("-"));
    let country = esc(sd
        .get("countryOfManufacture")
        .and_then(|v| v.as_str())
        .unwrap_or("-"));
    let ce = sd
        .get("ceMarking")
        .and_then(|v| v.as_bool())
        .map(|v| if v { "Yes" } else { "No" })
        .unwrap_or("-");
    format!(
        r#"<h2>Toy Safety Information</h2>
    <table aria-label="Toy data">
      <tr><th scope="row">Age Group</th><td>{age}</td></tr>
      <tr><th scope="row">Primary Material</th><td>{material}</td></tr>
      <tr><th scope="row">Country of Manufacture</th><td>{country}</td></tr>
      <tr><th scope="row">CE Marking</th><td>{ce}</td></tr>
    </table>"#
    )
}

fn build_aluminium_section(p: &serde_json::Value) -> String {
    let sd = match p.get("sectorData") {
        Some(v) => v,
        None => return String::new(),
    };
    let grade = esc(sd.get("alloyGrade").and_then(|v| v.as_str()).unwrap_or("-"));
    let route = esc(sd
        .get("productionRoute")
        .and_then(|v| v.as_str())
        .unwrap_or("-"));
    let country = esc(sd
        .get("countryOfProduction")
        .and_then(|v| v.as_str())
        .unwrap_or("-"));
    let co2e = sd
        .get("co2ePerTonneKg")
        .and_then(|v| v.as_f64())
        .map(|v| format!("{v:.2} kg CO\u{2082}e / t"))
        .unwrap_or_else(|| "-".into());
    let recycled = sd
        .get("recycledContentPct")
        .and_then(|v| v.as_f64())
        .map(|v| format!("{v:.1}%"))
        .unwrap_or_else(|| "-".into());
    format!(
        r#"<h2>Aluminium Product Information</h2>
    <table aria-label="Aluminium data">
      <tr><th scope="row">Alloy Grade</th><td>{grade}</td></tr>
      <tr><th scope="row">Production Route</th><td>{route}</td></tr>
      <tr><th scope="row">Country of Production</th><td>{country}</td></tr>
      <tr><th scope="row">Carbon Intensity</th><td>{co2e}</td></tr>
      <tr><th scope="row">Recycled Content</th><td>{recycled}</td></tr>
    </table>"#
    )
}

fn build_furniture_section(p: &serde_json::Value) -> String {
    let sd = match p.get("sectorData") {
        Some(v) => v,
        None => return String::new(),
    };
    let product_type = esc(sd
        .get("productType")
        .and_then(|v| v.as_str())
        .unwrap_or("-"));
    let material = esc(sd
        .get("primaryMaterial")
        .and_then(|v| v.as_str())
        .unwrap_or("-"));
    let country = esc(sd
        .get("countryOfManufacture")
        .and_then(|v| v.as_str())
        .unwrap_or("-"));
    let co2e = sd
        .get("co2ePerUnitKg")
        .and_then(|v| v.as_f64())
        .map(|v| format!("{v:.2} kg CO\u{2082}e"))
        .unwrap_or_else(|| "Not disclosed".into());
    let repair = sd
        .get("repairabilityScore")
        .and_then(|v| v.as_f64())
        .map(|v| format!("{v:.1} / 10"))
        .unwrap_or_else(|| "-".into());
    format!(
        r#"<h2>Furniture Information</h2>
    <table aria-label="Furniture data">
      <tr><th scope="row">Product Type</th><td>{product_type}</td></tr>
      <tr><th scope="row">Primary Material</th><td>{material}</td></tr>
      <tr><th scope="row">Country of Manufacture</th><td>{country}</td></tr>
      <tr><th scope="row">Carbon Footprint</th><td>{co2e}</td></tr>
      <tr><th scope="row">Repairability Score</th><td>{repair}</td></tr>
    </table>"#
    )
}

fn build_detergent_section(p: &serde_json::Value) -> String {
    let sd = match p.get("sectorData") {
        Some(v) => v,
        None => return String::new(),
    };
    let product_type = esc(sd
        .get("productType")
        .and_then(|v| v.as_str())
        .unwrap_or("-"));
    let format = esc(sd.get("format").and_then(|v| v.as_str()).unwrap_or("-"));
    let country = esc(sd
        .get("countryOfManufacture")
        .and_then(|v| v.as_str())
        .unwrap_or("-"));
    let biodegradable = sd
        .get("biodegradable")
        .and_then(|v| v.as_bool())
        .map(|v| {
            if v {
                "All surfactants biodegradable"
            } else {
                "Not fully biodegradable"
            }
        })
        .unwrap_or("-");
    let surfactant_count = sd
        .get("surfactants")
        .and_then(|v| v.as_array())
        .map(|a| a.len().to_string())
        .unwrap_or_else(|| "-".into());
    format!(
        r#"<h2>Detergent Information</h2>
    <table aria-label="Detergent data">
      <tr><th scope="row">Product Type</th><td>{product_type}</td></tr>
      <tr><th scope="row">Format</th><td>{format}</td></tr>
      <tr><th scope="row">Country of Manufacture</th><td>{country}</td></tr>
      <tr><th scope="row">Biodegradability</th><td>{biodegradable}</td></tr>
      <tr><th scope="row">Surfactants Declared</th><td>{surfactant_count}</td></tr>
    </table>"#
    )
}

/// Palette of accessible colours for fibre composition segments.
const FIBRE_COLOURS: &[&str] = &[
    "#2563eb", "#16a34a", "#d97706", "#dc2626", "#7c3aed", "#0891b2", "#059669", "#b45309",
    "#9333ea", "#0284c7",
];

fn build_fibre_bar(fibres: &[(&str, f64)]) -> String {
    if fibres.is_empty() {
        return String::new();
    }
    let segs: String = fibres
        .iter()
        .enumerate()
        .map(|(i, (name, pct))| {
            let colour = FIBRE_COLOURS[i % FIBRE_COLOURS.len()];
            let name = esc(name);
            let label = if *pct >= 10.0 {
                format!("{pct:.0}%")
            } else {
                String::new()
            };
            format!(
                r#"<div class="fibre-seg" style="width:{pct:.1}%;background:{colour}" title="{name}: {pct:.1}%" aria-label="{name} {pct:.1} percent">{label}</div>"#
            )
        })
        .collect();
    format!(
        r#"<div class="fibre-bar" role="img" aria-label="Fibre composition bar chart">{segs}</div>"#
    )
}

fn build_fibre_legend(fibres: &[(&str, f64)]) -> String {
    if fibres.is_empty() {
        return String::new();
    }
    let items: String = fibres
        .iter()
        .enumerate()
        .map(|(i, (name, pct))| {
            let colour = FIBRE_COLOURS[i % FIBRE_COLOURS.len()];
            let name = esc(name);
            format!(
                r#"<span style="display:inline-flex;align-items:center;gap:.25rem;margin:.2rem .4rem 0 0;font-size:.75rem"><span style="display:inline-block;width:10px;height:10px;background:{colour};border-radius:2px;flex-shrink:0" aria-hidden="true"></span>{name} {pct:.1}%</span>"#
            )
        })
        .collect();
    format!(r#"<div style="margin-top:.4rem">{items}</div>"#)
}

/// Render the DPP URL as an inline SVG QR code.
fn build_qr_svg(dpp_id: &str) -> String {
    let url = format!("https://passport.odal-node.io/dpp/{dpp_id}");

    let code = match QrCode::new(url.as_bytes()) {
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

    // Defense-in-depth: escape the URL in the SVG <title> text context. The id is
    // already constrained to a UUID at the handler edge (N-4), so this is belt-and-
    // suspenders against any future change to how the URL is built.
    let title_url = esc(&url);
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

#[cfg(test)]
mod security_regression {
    //! **F5 / R2** (stored XSS): every operator/supplier-supplied value
    //! interpolated into the public HTML page must be escaped for both element
    //! and double-quoted-attribute contexts.
    use super::esc;

    #[test]
    fn script_tags_are_neutralised() {
        let out = esc("<script>alert(1)</script>");
        assert!(!out.contains('<') && !out.contains('>'), "got: {out}");
        assert_eq!(out, "&lt;script&gt;alert(1)&lt;/script&gt;");
    }

    #[test]
    fn attribute_breakout_is_neutralised() {
        // A value placed in a double-quoted attribute must not be able to close
        // the attribute or inject a new one.
        let out = esc("\" onmouseover=\"alert(1)");
        assert!(!out.contains('"'), "quote leaked: {out}");
        assert_eq!(out, "&quot; onmouseover=&quot;alert(1)");
    }

    #[test]
    fn ampersand_and_single_quote_escaped() {
        assert_eq!(esc("a&b'c"), "a&amp;b&#39;c");
    }

    #[test]
    fn benign_text_unchanged() {
        assert_eq!(
            esc("Eco Jacket 30C cotton/polyester"),
            "Eco Jacket 30C cotton/polyester"
        );
    }
}
