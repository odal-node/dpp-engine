//! `POST /api/v1/dpp/validate` — would this body be accepted, without creating anything.

use axum::{extract::State, http::StatusCode, response::IntoResponse};
use serde::Serialize;

use crate::state::AppState;

use super::create::CreatePassportRequest;
use crate::extract::Json;
use crate::middleware::scope::RequireWrite;

/// The dry-run verdict.
///
/// Two booleans rather than one, because create and publish deliberately differ:
/// a body can be creatable as a draft and not yet publishable, and collapsing
/// that into a single flag would hide the gap until the caller tried to publish.
///
/// A named type rather than a `json!` literal so the OpenAPI contract test can
/// check `components/schemas/passport-reports/ValidateResponse` against it.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidateResponse {
    /// Always `true` when this body is returned — a create-invalid body gets
    /// the identical rejection `POST /api/v1/dpp` would have sent instead.
    pub create_valid: bool,
    /// Whether the stricter publish gate would also pass.
    pub product_group_data_valid: bool,
    /// Why publish would be blocked. `null` when nothing blocks it.
    pub detail: Option<String>,
}

/// `POST /api/v1/dpp/validate` — dry-run a create body and report the verdict.
///
/// Persists nothing. Runs [`super::create::validate_create_request`] — the same
/// function `POST /api/v1/dpp` runs — so the preview and the real thing cannot
/// disagree. When the body would be rejected, this returns **the identical
/// rejection** create would have returned, rather than a paraphrase of it.
///
/// **Two verdicts, because create and publish deliberately differ.** Create is
/// lenient about a product group with no resolvable JSON Schema — a draft may stay
/// incomplete — while publish fails closed on it, because a signed passport
/// must have passed a real schema check. A body can therefore be creatable and
/// not yet publishable, and collapsing that into one boolean would hide the gap
/// until the caller tried to publish.
///
/// **Write-scoped.** It reads no stored data and writes none, but it is a
/// preview of a write and it runs schema validation on caller-supplied input —
/// work a read-only credential has no reason to be able to commission.
pub async fn validate_handler(
    State(state): State<AppState>,
    // The gate is an extractor, and it precedes the body extractor
    // deliberately: axum runs body-less extractors first, so a wrong-scope
    // caller is refused before the body is buffered or parsed.
    RequireWrite(_auth): RequireWrite,
    Json(body): Json<CreatePassportRequest>,
) -> impl IntoResponse {
    // The create gate, exactly as `POST /api/v1/dpp` applies it — and on
    // failure, byte-for-byte the response create would have sent.
    if let Some(rejection) = super::create::validate_create_request(&body) {
        return rejection;
    }

    // Create would accept it. Now the stricter publish gate, so the caller
    // learns now rather than at publish time.
    let publish_blocker = match body.product_group_data.as_ref() {
        Some(product_group_data) => state
            .service
            .publish_readiness(product_group_data)
            .err()
            .map(|e| e.to_string()),
        // ProductGroup data is optional at create. Publish validates it only when
        // present, so its absence is not a publish blocker here either.
        None => None,
    };

    (
        StatusCode::OK,
        Json(ValidateResponse {
            create_valid: true,
            product_group_data_valid: publish_blocker.is_none(),
            detail: publish_blocker,
        }),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use axum::{
        Router,
        body::Body,
        http::{Request, StatusCode},
        routing::post,
    };
    use tower::ServiceExt;

    /// `/dpp/validate` shares a prefix with `/dpp/{dppId}`. The router must send
    /// the literal to the validate handler and never read `validate` as a
    /// passport id — and it must do so whichever order the routes were added,
    /// so a later reorder cannot silently break the dry-run endpoint.
    ///
    /// Registers the parameter route *first* here, which is the order that
    /// would fail if precedence went by declaration.
    #[tokio::test]
    async fn literal_validate_route_beats_the_id_parameter() {
        let app = Router::new()
            .route("/dpp/{dppId}", post(|| async { "param" }))
            .route("/dpp/validate", post(|| async { "literal" }));

        for (path, expected) in [("/dpp/validate", "literal"), ("/dpp/abc123", "param")] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(path)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK, "{path}");
            let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            assert_eq!(
                String::from_utf8_lossy(&bytes),
                expected,
                "{path} reached the wrong handler"
            );
        }
    }
}
