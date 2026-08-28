//! `GET /api/v1/imports/{job_id}` — poll the status of an async import job.

use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use dpp_common::http_problem;
use serde::Serialize;
use uuid::Uuid;

use crate::{handlers::import::extract_bearer_token, infra::job_store::JobStatus, state::AppState};

/// How far an async import job has progressed.
#[derive(Debug, Serialize)]
pub struct JobProgress {
    pub processed: usize,
    pub total: usize,
}

/// Response body for the job-status endpoint.
///
/// A named type rather than a `json!` literal so the OpenAPI contract test can
/// check `components/schemas/JobStatusResponse` against it.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JobStatusResponse {
    pub job_id: Uuid,
    /// `queued`, `processing`, `completed`, or `failed`.
    pub status: String,
    pub progress: JobProgress,
    /// Populated on completion (created/errors) or failure (reason); `null`
    /// while the job is still queued or processing.
    pub result: serde_json::Value,
    /// The row-addressed findings report — populated for every job, dry-run or
    /// apply, independent of `result`.
    pub report: serde_json::Value,
}

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

            let report_json = serde_json::to_value(&job.report).unwrap_or(serde_json::Value::Null);
            (
                StatusCode::OK,
                Json(JobStatusResponse {
                    job_id: job.id,
                    status: status_str.to_owned(),
                    progress: JobProgress {
                        processed: job.processed,
                        total: job.total_rows,
                    },
                    result: result_json,
                    report: report_json,
                }),
            )
                .into_response()
        }
    }
}
