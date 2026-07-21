//! Handler for `GET /dpp/{dppId}` when `Accept: text/html` — renders a self-contained
//! HTML passport page with sector-specific tables and an inline SVG QR code.

use axum::{
    extract::{Path, State},
    http::{HeaderValue, StatusCode, header},
    response::IntoResponse,
};
use dpp_render::{SnapshotNotice, render_page};

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

    let html = render_page(
        &dpp_id,
        &verified,
        &state.resolver_base_url,
        SnapshotNotice::Live,
    );
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
