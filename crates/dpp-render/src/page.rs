//! The public passport page — one renderer for the live read and the
//! pre-rendered continuity snapshot.

use std::fmt::Write as _;

use chrono::{DateTime, Utc};
use qrcode::QrCode;

use crate::carrier::carrier_uri;
use crate::esc::esc;
use crate::sections;

/// Whether this render is the live page or a snapshot, and if a snapshot, when
/// it was taken.
///
/// The static tier serves a copy that is authentic and signed but possibly
/// stale. Availability must not be bought by pretending the staleness away, so
/// a snapshot render states its age on the page itself rather than leaving the
/// reader to infer it from a header they will never see.
#[derive(Debug, Clone, Copy)]
pub enum SnapshotNotice {
    /// Rendered live from the node — no banner.
    Live,
    /// Rendered into the continuity tier at this instant.
    AsOf(DateTime<Utc>),
}

impl SnapshotNotice {
    /// The banner markup, or empty for a live render.
    fn banner_html(self) -> String {
        match self {
            Self::Live => String::new(),
            Self::AsOf(ts) => format!(
                r#"<div class="snapshot-note" role="status">This is a saved copy of this passport as of {} UTC. The live service is temporarily unavailable, so some details may have changed since. The copy is still signed and can be verified.</div>"#,
                ts.format("%Y-%m-%d %H:%M")
            ),
        }
    }
}

/// Render the passport page from its **public view** JSON.
///
/// `p` must already be the redacted public view — this renders whatever it is
/// given and performs no filtering of its own.
pub fn render_page(
    dpp_id: &str,
    p: &serde_json::Value,
    resolver_base_url: &str,
    notice: SnapshotNotice,
) -> String {
    let banner = notice.banner_html();
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
    let qr_svg = carrier_uri(p, resolver_base_url, dpp_id)
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
    .snapshot-note{{background:#fef3c7;border-left:4px solid #d97706;color:#78350f;padding:.75rem 1rem;border-radius:6px;font-size:.85rem;line-height:1.45;margin-bottom:1rem}}
    footer{{margin-top:1.5rem;font-size:.75rem;color:#9ca3af;text-align:center}}
    footer a{{color:#6b7280;text-decoration:none}}
    footer a:hover{{text-decoration:underline}}
    @media(max-width:480px){{.card{{padding:1rem}}h1{{font-size:1.2rem}}th,td{{padding:.4rem .2rem}}}}
  </style>
</head>
<body>
  <div class="card">
    {banner}
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
pub fn build_qr_svg(carrier_uri: &str) -> String {
    let code = match QrCode::new(carrier_uri.as_bytes()) {
        Ok(c) => c,
        Err(_) => return String::new(),
    };

    let width = code.width();
    let colors = code.to_colors();
    let module_size = 4u32;
    let quiet = 4u32; // quiet zone in modules
    let total = (width as u32 + quiet * 2) * module_size;

    let mut rects = String::with_capacity(colors.len() * 48);
    for (i, color) in colors.iter().enumerate() {
        if *color == qrcode::Color::Dark {
            let x = (i as u32 % width as u32 + quiet) * module_size;
            let y = (i as u32 / width as u32 + quiet) * module_size;
            let _ = write!(
                rects,
                r#"<rect x="{x}" y="{y}" width="{module_size}" height="{module_size}"/>"#
            );
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

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;

    // Same fixture id used in `carrier.rs`'s tests — first 10 bytes hex-encode
    // to a fixed 20-char AI 21 serial, so the QR carrier URI is deterministic.
    const DPP_ID: &str = "0190a9f0-1234-7abc-8def-0123456789ab";

    /// Deliberately **not** a realistic Public-tier view: it includes `batchId`,
    /// which `SectorAccessPolicy::passport_default` tiers as Professional (see
    /// the README), so a genuine public read would never contain it. Used here
    /// to test `render_page`'s raw mechanics — it renders whatever it is given,
    /// by design — not to model what a real public render looks like.
    fn unredacted_passport() -> serde_json::Value {
        serde_json::json!({
            "productName": "Organic Cotton T-Shirt",
            "manufacturer": { "name": "Sample Textiles Co." },
            "status": "active",
            "batchId": "BATCH-42",
            "sectorData": { "sector": "textile", "gtin": "09506000134352" }
        })
    }

    #[test]
    fn live_render_includes_core_fields_and_no_banner() {
        let html = render_page(
            DPP_ID,
            &unredacted_passport(),
            "https://id.odal-node.io",
            SnapshotNotice::Live,
        );
        assert!(html.contains("Organic Cotton T-Shirt"));
        assert!(html.contains("Sample Textiles Co."));
        assert!(html.contains("badge-active"));
        assert!(html.contains("BATCH-42"));
        assert!(html.contains(DPP_ID));
        assert!(
            !html.contains("This is a saved copy"),
            "live render must not show a snapshot banner"
        );
        assert!(html.starts_with("<!DOCTYPE html>"));
    }

    /// `batchId` is Professional-tier (see the README), so a genuine Public-tier
    /// view never contains it — `dpp-vault::public_view` strips it before this
    /// crate ever sees the passport. Pins the resulting fallback: the row still
    /// renders, showing "-" rather than being silently omitted or erroring.
    #[test]
    fn batch_id_absent_from_a_realistic_public_view_falls_back_to_dash() {
        let p = serde_json::json!({
            "productName": "Organic Cotton T-Shirt",
            "manufacturer": { "name": "Sample Textiles Co." },
            "status": "active",
            "sectorData": { "sector": "textile", "gtin": "09506000134352" }
        });
        let html = render_page(DPP_ID, &p, "https://id.odal-node.io", SnapshotNotice::Live);
        assert!(
            html.contains("<th scope=\"row\">Batch ID</th><td>-</td>"),
            "expected batch id to fall back to a dash: {html}"
        );
    }

    #[test]
    fn snapshot_render_shows_dated_banner() {
        let ts = Utc.with_ymd_and_hms(2026, 7, 19, 12, 30, 0).unwrap();
        let html = render_page(
            DPP_ID,
            &unredacted_passport(),
            "https://id.odal-node.io",
            SnapshotNotice::AsOf(ts),
        );
        assert!(html.contains("snapshot-note"));
        assert!(html.contains("2026-07-19 12:30"));
    }

    #[test]
    fn missing_fields_fall_back_to_placeholders() {
        let html = render_page(
            DPP_ID,
            &serde_json::json!({}),
            "https://id.odal-node.io",
            SnapshotNotice::Live,
        );
        assert!(html.contains("Unknown product"));
        assert!(html.contains("badge-unknown"));
        assert!(
            html.contains(">-<"),
            "gtin/batch must fall back to a dash, not be omitted"
        );
    }

    /// `render_page` reads a fixed set of named fields off the passport — it must
    /// not fall back to serializing unrecognised top-level data. Guards the same
    /// leak-safe-by-construction property the section builders rely on, at the
    /// whole-page level.
    #[test]
    fn unrecognised_fields_are_never_rendered() {
        let mut p = unredacted_passport();
        p["internalNotes"] = serde_json::json!("MARKER_INTERNAL_NOTES");
        p["supplierCostEur"] = serde_json::json!("MARKER_SUPPLIER_COST");
        let html = render_page(DPP_ID, &p, "https://id.odal-node.io", SnapshotNotice::Live);
        assert!(!html.contains("MARKER_INTERNAL_NOTES"), "leaked: {html}");
        assert!(!html.contains("MARKER_SUPPLIER_COST"), "leaked: {html}");
    }

    #[test]
    fn dpp_id_is_html_escaped_defensively() {
        // Real ids are validated at the resolver's edge before reaching this
        // crate, but this crate offers no such guarantee on its own — belt and
        // suspenders against a future caller that skips validation.
        let id = "abc\"><script>alert(1)</script>";
        let html = render_page(
            id,
            &unredacted_passport(),
            "https://id.odal-node.io",
            SnapshotNotice::Live,
        );
        assert!(
            !html.contains("<script>"),
            "unescaped id leaked a tag: {html}"
        );
        assert!(html.contains("&lt;script&gt;"));
    }

    #[test]
    fn build_qr_svg_encodes_the_carrier_uri() {
        let svg = build_qr_svg("https://id.odal-node.io/01/09506000134352/21/abc");
        assert!(svg.starts_with("<svg"));
        assert!(svg.contains("id.odal-node.io"));
    }

    #[test]
    fn build_qr_svg_escapes_the_title() {
        let svg = build_qr_svg("https://id.odal-node.io/\"><script>alert(1)</script>");
        assert!(
            !svg.contains("<script>"),
            "unescaped uri leaked a tag: {svg}"
        );
    }
}
