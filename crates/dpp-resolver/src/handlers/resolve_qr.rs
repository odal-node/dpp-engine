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

use crate::{domain::carrier_uri, infra::did, state::AppState};

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
/// The URI is built from `gtin` (`sectorData.gtin`) and `batchId`, read from
/// the verified passport JSON — NOT from the stored `qrCodeUrl`, which is set
/// *after* signing and is therefore content-binding-exempt and tamperable
/// (red-team RT2-2). The passport's JWS is verified first, exactly as the
/// HTML/JSON paths do, so the QR image fails closed on a tampered or
/// unverifiable passport. A passport whose sector data carries no GTIN (e.g.
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

    let code = match QrCode::new(carrier_uri.as_bytes()) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(dpp_id = %dpp_id, error = %e, "QR code generation failed");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                [(header::CONTENT_TYPE, "image/png")],
                Vec::new(),
            )
                .into_response();
        }
    };

    // Build PNG from raw color matrix — avoids qrcode/image crate version conflict
    let width = code.width() as u32;
    let colors = code.to_colors();
    let scale: u32 = 8;
    let img_size = width * scale;
    let mut img = GrayImage::new(img_size, img_size);
    for (i, color) in colors.iter().enumerate() {
        let x = (i as u32) % width;
        let y = (i as u32) / width;
        let luma = if *color == qrcode::Color::Dark {
            0u8
        } else {
            255u8
        };
        for dy in 0..scale {
            for dx in 0..scale {
                img.put_pixel(x * scale + dx, y * scale + dy, Luma([luma]));
            }
        }
    }

    let mut png_bytes: Vec<u8> = Vec::new();
    let dyn_img = DynamicImage::ImageLuma8(img);
    if let Err(e) = dyn_img.write_to(&mut std::io::Cursor::new(&mut png_bytes), ImageFormat::Png) {
        tracing::error!(dpp_id = %dpp_id, error = %e, "PNG encoding failed");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            [(header::CONTENT_TYPE, "image/png")],
            Vec::new(),
        )
            .into_response();
    }

    // Cache as base64 string
    let b64 = base64::engine::general_purpose::STANDARD.encode(&png_bytes);
    state.cache.set(&cache_key, &b64).await;

    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "image/png")],
        png_bytes,
    )
        .into_response()
}
