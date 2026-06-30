//! `GET /api/v1/dpps` — paginated passport list with optional status and text filtering.

use axum::{
    Json,
    extract::{Extension, Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::Deserialize;
use serde_json::json;

use dpp_domain::domain::status::PassportStatus;

use crate::{middleware::auth::AuthContext, state::AppState};

use super::error::internal_error;

/// Query parameters for the passport list endpoint.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListQuery {
    /// Filter by passport status. Omit to return all statuses.
    pub status: Option<PassportStatus>,
    /// Free-text search across `productName`, `batchId`, and
    /// `manufacturer.name`. Trimmed + lowercased server-side.
    pub q: Option<String>,
    /// Filter to passports stamped with this exact facility identifier
    /// (ESPR Annex III; ADR-006 grouping filter, not an isolation boundary).
    pub facility_id: Option<String>,
    /// Maximum results to return (capped at 100, default 20).
    pub limit: Option<u32>,
    /// Offset into the result set for pagination (default 0).
    pub skip: Option<u32>,
}

/// `GET /api/v1/dpps` — paginated, filterable list of passports.
pub async fn list_handler(
    State(state): State<AppState>,
    Extension(_auth): Extension<AuthContext>,
    Query(query): Query<ListQuery>,
) -> impl IntoResponse {
    let limit = query.limit.unwrap_or(20).min(100);
    let offset = query.skip.unwrap_or(0);
    let status = query.status;
    let list_status = status.clone();
    let q = query.q.as_deref();
    let facility_id = query.facility_id.as_deref();

    let passports = match state
        .service
        .list(list_status, q, facility_id, limit, offset)
        .await
    {
        Ok(p) => p,
        Err(e) => return internal_error(e),
    };

    let total = state.service.count(status, facility_id).await.unwrap_or(0);

    (
        StatusCode::OK,
        Json(json!({
            "dpps": passports,
            "total": total,
            "limit": limit,
            "skip": offset,
        })),
    )
        .into_response()
}
