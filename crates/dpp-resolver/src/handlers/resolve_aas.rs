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
        return ok(&state, &dpp_id, cached);
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
    //
    // This is the door's constraint, not the mappers'. `dpp-aas` still builds a
    // correct unsold-goods submodel for a caller that supplies its own asset
    // identity — a file export or an AASX package for a reporting authority —
    // because `build_aas_from_passport` takes the identity as a parameter. What
    // is unavailable is *this* representation at *this* URL, and the fix is not
    // to invent a `globalAssetId`: a fabricated trade-item identifier inside a
    // document an integrator treats as authoritative is worse than a 406.
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

    ok(&state, &dpp_id, body)
}

/// A `200` carrying the AAS body and its link back to the signed canonical.
///
/// Both success paths — cache hit and fresh build — go through here, so the
/// cached response cannot advertise less than the one that populated it. That
/// is the whole reason this is a function rather than two literals: the cached
/// branch returning early with only a content type is exactly how the two
/// would drift.
fn ok(state: &AppState, dpp_id: &str, body: String) -> axum::response::Response {
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, AAS_MEDIA_TYPE.to_owned()),
            (header::LINK, canonical_link(state, dpp_id)),
        ],
        body,
    )
        .into_response()
}

/// `Link` pointing at the signed canonical view this projection derives from.
///
/// This body is unsigned and cannot carry the public proof: that signature
/// covers the canonical public payload, not this serialisation of it, so
/// attaching it would hand a verifier a proof that fails against the bytes it
/// arrived with. The honest alternative is to say where the signed thing is,
/// which is what this header does.
///
/// **`alternate`, not `canonical` or `describedby`.** The two representations
/// share one URL and are separated only by `Accept`, so `canonical` — which
/// nominates a preferred *IRI* (RFC 6596) — would point this resource at
/// itself and say nothing. `describedby` claims the target *describes* the
/// context resource, and the JSON-LD view does not describe the AAS; it is the
/// same resource in another form, which is precisely what `alternate` means.
/// Carrying `type` makes it actionable: a client reading this header knows both
/// where to go and what to ask for.
///
/// The target is built from the resolver's own configured base, never from the
/// passport's `qrCodeUrl` — that field is mutable and content-binding-exempt,
/// so deriving a link from it would let an altered value point a verifier at an
/// attacker's host, the same open redirect the QR handler hardcodes against.
fn canonical_link(state: &AppState, dpp_id: &str) -> String {
    let base = state.resolver_base_url.trim_end_matches('/');
    format!(r#"<{base}/dpp/{dpp_id}>; rel="alternate"; type="application/ld+json""#)
}

/// An RFC 7807 problem carrying this door's own content type, so a client that
/// negotiated AAS never receives a body typed as something it did not ask for.
///
/// Deliberately carries no `Link`: an error is not a representation of the
/// passport, so it has no alternate representation to advertise.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infra::cache::Cache;

    const ID: &str = "00000000-0000-4000-8000-0000000000aa";

    fn state_with_base(base: &str) -> AppState {
        AppState {
            vault_base_url: "http://127.0.0.1:1".into(),
            operator_did_url: String::new(),
            resolver_base_url: base.into(),
            cache: Cache::new_noop(),
            http: reqwest::Client::new(),
            scan_counter: None,
        }
    }

    fn link_of(response: &axum::response::Response) -> &str {
        response
            .headers()
            .get(header::LINK)
            .expect("a 200 carries a Link header")
            .to_str()
            .expect("the Link header is ASCII")
    }

    /// The response construction the **cache-hit** branch returns through.
    ///
    /// The cached branch cannot be driven end-to-end in this tier — populating
    /// it needs a live Redis, and the resolver has no integration tier. So this
    /// exercises the constructor itself, which is not a stand-in for that
    /// branch: it is literally the code that branch runs. The only step not
    /// covered is `Cache::get` returning `Some`, which decides *whether* a
    /// response is built here, never what headers it carries.
    ///
    /// That both branches call this one function is what makes them equal, and
    /// it is why the cached branch no longer builds its own response literal.
    #[test]
    fn the_shared_success_constructor_carries_the_canonical_link() {
        let state = state_with_base("https://id.odal-node.io");
        let response = ok(&state, ID, "{}".into());

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some(AAS_MEDIA_TYPE)
        );
        assert_eq!(
            link_of(&response),
            r#"<https://id.odal-node.io/dpp/00000000-0000-4000-8000-0000000000aa>; rel="alternate"; type="application/ld+json""#
        );
    }

    /// The target names the JSON-LD media type, or a client has been told where
    /// to look without being told what to ask for — and `Accept` is the only
    /// thing separating the two representations at that URL.
    #[test]
    fn the_link_names_the_media_type_that_reaches_the_signed_view() {
        let state = state_with_base("https://id.odal-node.io");
        let link = canonical_link(&state, ID);
        assert!(link.contains(r#"type="application/ld+json""#), "{link}");
        assert!(link.contains(r#"rel="alternate""#), "{link}");
    }

    /// A configured base with a trailing slash must not produce `//dpp/…`.
    #[test]
    fn a_trailing_slash_on_the_configured_base_does_not_double() {
        let state = state_with_base("https://id.odal-node.io/");
        assert!(
            canonical_link(&state, ID).starts_with("<https://id.odal-node.io/dpp/"),
            "{}",
            canonical_link(&state, ID)
        );
    }
}
