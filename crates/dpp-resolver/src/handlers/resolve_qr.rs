//! Handler for `GET /dpp/{dppId}/qr` — serves a PNG QR code encoding the
//! passport's GS1 Digital Link URI, derived from verified passport fields,
//! never from the stored `qrCodeUrl` field.

use axum::{
    extract::{Path, State},
    http::{StatusCode, header},
    response::IntoResponse,
};
use base64::Engine;
use image::{DynamicImage, GrayImage, ImageFormat, Luma};
use qrcode::QrCode;
use serde_json::Value;

use dpp_render::carrier_uri;

use crate::{infra::did, state::AppState};

/// Fetch the passport JSON from the vault's public endpoint.
///
/// Mirrors `resolve_json::fetch_passport`: a 400/404 from the vault is "not
/// found" to a consumer; transport/parse failures are a bad gateway.
async fn fetch_passport(state: &AppState, dpp_id: &str) -> Result<Value, StatusCode> {
    let url = format!("{}/public/dpp/{dpp_id}", state.vault_base_url);
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

/// Generate and return a PNG QR code encoding the passport's GS1 Digital Link
/// URI.
///
/// The URI is built from `gtin` (`productGroupData.gtin`) and `batchId`, read from
/// the verified passport JSON — NOT from the stored `qrCodeUrl`, which is set
/// *after* signing and is therefore content-binding-exempt and tamperable
/// (red-team RT2-2). The passport's JWS is verified first, exactly as the
/// HTML/JSON paths do, so the QR image fails closed on a tampered or
/// unverifiable passport. A passport whose product group data carries no GTIN (e.g.
/// an unsold-goods report) has no valid GS1 Digital Link carrier and fails
/// closed with `422` rather than printing a broken or misleading code.
pub async fn resolve_qr_handler(
    State(state): State<AppState>,
    Path(dpp_id): Path<String>,
) -> impl IntoResponse {
    // Validate the id at the edge before it reaches a cache key or URL.
    if !crate::domain::is_valid_dpp_id(&dpp_id) {
        return (
            StatusCode::NOT_FOUND,
            [(header::CONTENT_TYPE, "image/png")],
            Vec::new(),
        )
            .into_response();
    }

    let cache_key = format!("resolver:qr:{dpp_id}");

    // Return cached PNG bytes if available (stored as base64 string in Redis)
    if let Some(cached_b64) = state.cache.get(&cache_key).await
        && let Ok(png) = base64::engine::general_purpose::STANDARD.decode(&cached_b64)
    {
        record_qr_render(&state, &dpp_id);
        return (StatusCode::OK, [(header::CONTENT_TYPE, "image/png")], png).into_response();
    }

    // Fetch + verify the passport before serving its QR. Fails closed: an
    // unfound/tampered/unverifiable passport never yields a QR image.
    let passport = match fetch_passport(&state, &dpp_id).await {
        Ok(p) => p,
        Err(status) => {
            return (status, [(header::CONTENT_TYPE, "image/png")], Vec::new()).into_response();
        }
    };
    if let Err(status) =
        did::verify_passport_jws(&state.http, &state.operator_did_url, &passport).await
    {
        return (status, [(header::CONTENT_TYPE, "image/png")], Vec::new()).into_response();
    }

    let Some(carrier_uri) = carrier_uri(&passport, &state.resolver_base_url, &dpp_id) else {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            [(header::CONTENT_TYPE, "image/png")],
            Vec::new(),
        )
            .into_response();
    };

    let png_bytes = match qr_png(&carrier_uri) {
        Ok(bytes) => bytes,
        Err(e) => {
            tracing::error!(dpp_id = %dpp_id, error = %e, "QR PNG generation failed");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                [(header::CONTENT_TYPE, "image/png")],
                Vec::new(),
            )
                .into_response();
        }
    };

    // Cache as base64 string
    let b64 = base64::engine::general_purpose::STANDARD.encode(&png_bytes);
    state.cache.set(&cache_key, &b64).await;

    record_qr_render(&state, &dpp_id);
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "image/png")],
        png_bytes,
    )
        .into_response()
}

/// Pixels per QR module in the served PNG.
///
/// Eight keeps a typical Digital Link symbol comfortably above the size a phone
/// camera resolves, without making the response large enough to be worth
/// tuning.
const MODULE_SCALE: u32 = 8;

/// Render a carrier URI as PNG bytes.
///
/// Extracted from the handler so the encoding can be tested for what it
/// *encodes* rather than only for having produced bytes. The handler's own path
/// reaches this only after fetching and verifying a passport, which a test
/// cannot exercise without a vault, a cache and a DID document — so for as long
/// as this lived inline, the only affordable assertion was `is_a_png`, and that
/// is what shipped.
///
/// The quiet zone is [`dpp_render::QR_QUIET_ZONE_MODULES`], the same value the
/// SVG renderer uses. This function previously applied none: the image was
/// exactly `width * scale` pixels of symbol, which is out of spec under
/// ISO/IEC 18004 and is the rendering an operator prints onto a physical label.
fn qr_png(carrier_uri: &str) -> Result<Vec<u8>, String> {
    let code = QrCode::new(carrier_uri.as_bytes()).map_err(|e| e.to_string())?;

    // Build the PNG from the raw colour matrix rather than `qrcode`'s own image
    // renderer, which pins a different `image` major than this workspace.
    let width = code.width() as u32;
    let colors = code.to_colors();
    let quiet = dpp_render::QR_QUIET_ZONE_MODULES;
    let img_size = (width + quiet * 2) * MODULE_SCALE;

    // Start from white so the quiet-zone border is blank without writing it.
    let mut img = GrayImage::from_pixel(img_size, img_size, Luma([255u8]));
    for (i, color) in colors.iter().enumerate() {
        if *color != qrcode::Color::Dark {
            continue;
        }
        let x = ((i as u32) % width + quiet) * MODULE_SCALE;
        let y = ((i as u32) / width + quiet) * MODULE_SCALE;
        for dy in 0..MODULE_SCALE {
            for dx in 0..MODULE_SCALE {
                img.put_pixel(x + dx, y + dy, Luma([0u8]));
            }
        }
    }

    let mut png_bytes: Vec<u8> = Vec::new();
    DynamicImage::ImageLuma8(img)
        .write_to(&mut std::io::Cursor::new(&mut png_bytes), ImageFormat::Png)
        .map_err(|e| e.to_string())?;
    Ok(png_bytes)
}

/// Record a QR-image render for telemetry, when telemetry is configured. This is
/// label production, tracked separately from consumer scans and never summed
/// into them.
fn record_qr_render(state: &AppState, dpp_id: &str) {
    if let Some(counter) = &state.scan_counter {
        counter.record_qr_render(dpp_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A GS1 Digital Link of the shape `carrier_uri` produces — the longest
    /// form, with both AI 10 and AI 21, so the symbol is at the larger end of
    /// what this route emits.
    const CARRIER: &str =
        "https://id.odal-node.io/01/09506000134352/10/BATCH-42/21/7abc8def0123456789ab";

    /// Decode a PNG back to the single QR payload it carries.
    fn decode(png: &[u8]) -> String {
        let img = image::load_from_memory(png).expect("handler must emit a decodable PNG");
        let mut prepared = rqrr::PreparedImage::prepare(img.to_luma8());
        let grids = prepared.detect_grids();
        assert_eq!(grids.len(), 1, "exactly one QR symbol must be detectable");
        let (_meta, content) = grids[0].decode().expect("the symbol must decode");
        content
    }

    /// The whole point: the image encodes the carrier URI, not merely *a* URI
    /// and not merely some bytes.
    ///
    /// Everything before this asserted `image/png` and a non-empty body, which
    /// a solid white square satisfies. A `qrcode` or `image` bump could have
    /// changed what the label says and stayed green.
    #[test]
    fn the_png_encodes_the_carrier_uri_it_was_given() {
        let png = qr_png(CARRIER).expect("a valid URI must render");
        assert_eq!(decode(&png), CARRIER);
    }

    /// The symbol carries the four-module quiet zone ISO/IEC 18004 requires.
    ///
    /// Asserted geometrically rather than by decoding, and that is deliberate:
    /// `rqrr` reads a symbol with no quiet zone perfectly well, so a round-trip
    /// test alone is satisfied by an image no hand scanner would read against a
    /// busy background. This is the assertion that would have caught the
    /// zero-margin rendering this route used to serve.
    ///
    /// Checked as a blank border of the expected thickness on all four sides.
    #[test]
    fn the_symbol_keeps_its_quiet_zone_on_every_side() {
        let png = qr_png(CARRIER).expect("a valid URI must render");
        let img = image::load_from_memory(&png).unwrap().to_luma8();
        let margin = dpp_render::QR_QUIET_ZONE_MODULES * MODULE_SCALE;
        let (w, h) = img.dimensions();
        assert_eq!(w, h, "a QR symbol is square");

        for y in 0..h {
            for x in 0..w {
                let in_border = x < margin || y < margin || x >= w - margin || y >= h - margin;
                if in_border {
                    assert_eq!(
                        img.get_pixel(x, y)[0],
                        255,
                        "({x},{y}) lies in the {margin}px quiet zone and must be blank"
                    );
                }
            }
        }
    }

    /// The border is a margin around a symbol, not the whole image — a blank
    /// PNG would satisfy the test above on its own.
    #[test]
    fn the_quiet_zone_check_cannot_pass_on_a_blank_image() {
        let png = qr_png(CARRIER).expect("a valid URI must render");
        let img = image::load_from_memory(&png).unwrap().to_luma8();
        assert!(
            img.pixels().any(|p| p[0] == 0),
            "the image must contain dark modules"
        );
    }

    /// A URI too long for any QR version fails as an error rather than
    /// producing an image that encodes something other than what was asked.
    #[test]
    fn an_unencodable_uri_is_an_error_not_a_wrong_symbol() {
        let too_long = "https://id.odal-node.io/01/".to_owned() + &"9".repeat(8000);
        assert!(qr_png(&too_long).is_err());
    }
}
