//! `GET /api/v1/imports/{job_id}` — poll the status of an async import job.

use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use dpp_common::http_problem;
use uuid::Uuid;

use crate::{handlers::import::extract_bearer_token, infra::job_store::JobStatus, state::AppState};

/// `GET /api/v1/imports/{job_id}`
///
/// Returns the status and progress of an async import job. Requires the same
/// bearer auth as the rest of the API (validated against the vault) so job
/// status and failure details are not exposed to unauthenticated callers.
/// Returns `401` if unauthenticated, `404` if the job does not exist.
pub async fn get_job_status(
    Path(job_id): Path<String>,
    headers: HeaderMap,
    State(state): State<AppState>,
) -> impl IntoResponse {
    let token = extract_bearer_token(&headers).unwrap_or_default();
    if !state.vault_client.verify_token(&token).await {
        return (
            StatusCode::UNAUTHORIZED,
            [(axum::http::header::WWW_AUTHENTICATE, "Bearer")],
            Json(
                http_problem::Problem::new(StatusCode::UNAUTHORIZED, "Unauthorized")
                    .with_detail("Unauthorized."),
            ),
        )
            .into_response();
    }

    let id = match job_id.parse::<Uuid>() {
        Ok(u) => u,
        Err(_) => {
            return http_problem::bad_request("Invalid job ID format.").into_response();
        }
    };

    match state.job_store.get(id).await {
        None => http_problem::not_found("Job not found.").into_response(),
        Some(job) => {
            let (status_str, result_json) = match &job.status {
                JobStatus::Queued => ("queued", serde_json::Value::Null),
                JobStatus::Processing => ("processing", serde_json::Value::Null),
                JobStatus::Completed => (
                    "completed",
                    serde_json::to_value(&job.result).unwrap_or(serde_json::Value::Null),
                ),
                JobStatus::Failed(reason) => ("failed", serde_json::json!({"reason": reason})),
            };

            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "jobId": job.id,
                    "status": status_str,
                    "progress": {
                        "processed": job.processed,
                        "total": job.total_rows
                    },
                    "result": result_json
                })),
            )
                .into_response()
        }
    }
}
