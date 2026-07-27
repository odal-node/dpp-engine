//! `GET /api/v1/dpp/{dppId}/verify-tree` — recursively verify a passport's
//! component tree (its bill of materials) against each node's pinned public JWS.

use axum::{
    Json,
    extract::{Extension, Path, State},
    http::StatusCode,
    response::IntoResponse,
};

use dpp_domain::domain::graph::DEFAULT_DEPTH_CAP;

use crate::domain::verify::{DEFAULT_NODE_CAP, fetch_public_json, verify_tree};
use crate::{middleware::auth::AuthContext, state::AppState};

use super::error::{internal_error, not_found_error, parse_passport_id};

/// `GET /api/v1/dpp/{dppId}/verify-tree` — walk `component_refs` from this
/// passport, fetching and pin-checking each node, and return a per-node report
/// with the path to any broken node. Fails closed on every ambiguity.
pub async fn verify_tree_handler(
    State(state): State<AppState>,
    Extension(_auth): Extension<AuthContext>,
    Path(dpp_id): Path<String>,
) -> impl IntoResponse {
    let passport_id = match parse_passport_id(&dpp_id) {
        Ok(id) => id,
        Err(e) => return e,
    };

    let root = match state.service.find_by_id(passport_id).await {
        Ok(p) => p,
        Err(dpp_domain::DppError::NotFound(_)) => {
            return not_found_error("DPP not found.");
        }
        Err(e) => return internal_error(e),
    };

    let report = verify_tree(
        &root.component_refs,
        fetch_public_json,
        DEFAULT_DEPTH_CAP,
        DEFAULT_NODE_CAP,
    )
    .await;
    (StatusCode::OK, Json(report)).into_response()
}
