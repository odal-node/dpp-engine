use axum::{
    Json,
    extract::State,
    http::{HeaderValue, StatusCode, header::CACHE_CONTROL},
    response::IntoResponse,
};
use dpp_common::http_problem;

use dpp_crypto::identity::did_builder;

use crate::state::AppState;

/// Short max-age so a key rotation propagates to verifiers quickly, with
/// `must-revalidate` so nothing serves a stale key past that window.
const DID_DOCUMENT_CACHE_CONTROL: &str = "public, max-age=60, must-revalidate";

/// Serve the `did:web` DID document for this node's operator.
///
/// Mounted only at `/.well-known/did.json`. The node is single-tenant, so there
/// is one operator (`root`) and no per-operator DID route — the previous
/// `Option<Path>` per-operator branch was dead code (no such route was ever
/// registered).
pub async fn did_document_handler(State(state): State<AppState>) -> impl IntoResponse {
    let operator_id = "root";

    match did_builder::build_did_document(&state.store, &state.did_web_base_url, operator_id) {
        Ok(doc) => (
            StatusCode::OK,
            [(
                CACHE_CONTROL,
                HeaderValue::from_static(DID_DOCUMENT_CACHE_CONTROL),
            )],
            Json(doc),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(operator_id = %operator_id, error = %e, "failed to build DID document");
            http_problem::internal_error(e.to_string()).into_response()
        }
    }
}
