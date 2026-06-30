use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use dpp_common::http_problem;

use dpp_crypto::identity::did_builder;

use crate::state::AppState;

/// Serve the `did:web` DID document for a given operator.
/// Accessible at `/.well-known/did.json` (root operator) or `/operators/{id}/did.json`.
pub async fn did_document_handler(
    State(state): State<AppState>,
    operator_path: Option<Path<String>>,
) -> impl IntoResponse {
    let operator_id = match operator_path {
        Some(Path(id)) => id,
        None => "root".to_owned(),
    };

    match did_builder::build_did_document(&state.store, &state.did_web_base_url, &operator_id) {
        Ok(doc) => (StatusCode::OK, Json(doc)).into_response(),
        Err(e) => {
            tracing::error!(operator_id = %operator_id, error = %e, "failed to build DID document");
            http_problem::internal_error(e.to_string()).into_response()
        }
    }
}
