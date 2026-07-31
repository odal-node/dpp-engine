//! Handler for `GET /dpp/{dppId}` when `Accept: application/aas+json` — serves
//! the passport as an IDTA Asset Administration Shell Environment.
//!
//! Built from the **verified signed public payload**, never the live row, for
//! the same reason the JSON-LD door is: the body and the signature must agree
//! by construction. An AAS assembled from the current database state would
//! drift from the view the operator actually signed.
//!
//! Field selection is not made here. `dpp_aas::build_aas_environment` filters
//! the passport through the disclosure seam before any mapper sees it, so this
//! door cannot widen what a public caller receives even by accident. A
//! projection that picked its own fields would eventually disagree with the
//! canonical one, and the direction it disagrees in is the direction that leaks.

use axum::{
    extract::{Path, State},
    http::{StatusCode, header},
    response::IntoResponse,
};
use dpp_common::http_problem;
use dpp_domain::{Audience, Passport};

use crate::{handlers::resolve_json::fetch_passport, infra::did, state::AppState};

/// The media type this door answers to.
pub const AAS_MEDIA_TYPE: &str = "application/aas+json";

/// Serve a passport as an AAS Environment.
pub async fn resolve_aas_handler(
    State(state): State<AppState>,
    Path(dpp_id): Path<String>,
) -> impl IntoResponse {
    // Validate at the resolver's own edge before touching a cache key or a
    // server-to-server URL, exactly as the other doors do.
    if !crate::domain::is_valid_dpp_id(&dpp_id) {
        return problem(StatusCode::NOT_FOUND, "DPP not found");
    }

    let cache_key = format!("resolver:aas:{dpp_id}");
    if let Some(cached) = state.cache.get(&cache_key).await {
        return (
            StatusCode::OK,
            [(header::CONTENT_TYPE, AAS_MEDIA_TYPE)],
            cached,
        )
            .into_response();
    }

    let raw = match fetch_passport(&state, &dpp_id).await {
        Ok(v) => v,
        Err(status) => return problem(status, "DPP not found"),
    };

    // Fails closed: an unverifiable passport yields no projection at all.
    let verified = match did::verify_passport_jws(&state.http, &state.operator_did_url, &raw).await
    {
        Ok(v) => v,
        Err(status) => {
            let detail = if status == StatusCode::SERVICE_UNAVAILABLE {
                "The passport could not be verified right now; try again later."
            } else {
                "The passport's digital signature could not be verified."
            };
            return problem(status, detail);
        }
    };

    let passport: Passport = match serde_json::from_value(verified) {
        Ok(p) => p,
        Err(_) => {
            return problem(
                StatusCode::BAD_GATEWAY,
                "The signed passport payload could not be read.",
            );
        }
    };

    // The AAS asset identity is the GTIN. Unsold-goods reports and untyped
    // sectors carry none — they do not identify a trade item — so no AAS
    // representation of them exists. 406 is the honest answer to "I want this
    // as AAS": the resource has no representation matching the request.
    let Some(gtin) = passport.sector_data.as_ref().and_then(|sd| sd.gtin()) else {
        return problem(
            StatusCode::NOT_ACCEPTABLE,
            "This passport has no GTIN, so it has no AAS representation.",
        );
    };

    let environment = match dpp_aas::build_aas_environment(&passport, gtin, Audience::Public) {
        Ok(env) => env,
        Err(_) => {
            // A masking failure is a disclosure-policy defect, not a caller
            // error, and the detail is deliberately not echoed to a public
            // caller — it names fields.
            return problem(
                StatusCode::INTERNAL_SERVER_ERROR,
                "The AAS projection could not be built for this passport.",
            );
        }
    };

    let body = match serde_json::to_string(&environment) {
        Ok(b) => b,
        Err(_) => {
            return problem(
                StatusCode::INTERNAL_SERVER_ERROR,
                "The AAS projection could not be serialised.",
            );
        }
    };
    state.cache.set(&cache_key, &body).await;

    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, AAS_MEDIA_TYPE)],
        body,
    )
        .into_response()
}

/// An RFC 7807 problem carrying this door's own content type, so a client that
/// negotiated AAS never receives a body typed as something it did not ask for.
fn problem(status: StatusCode, detail: &str) -> axum::response::Response {
    let problem = http_problem::Problem::new(status, status.canonical_reason().unwrap_or("Error"))
        .with_detail(detail);
    (
        status,
        [(header::CONTENT_TYPE, "application/problem+json")],
        serde_json::to_string(&problem).unwrap_or_default(),
    )
        .into_response()
}
