//! Concurrent batch runner — fans out validated passport rows to `dpp-vault`.

use std::sync::Arc;

use tokio::sync::Semaphore;
use tracing;

use crate::{
    domain::validator::CreatePassportRequest,
    infra::vault_client::{VaultClientError, VaultHttpClient},
};

// ─── Result types ─────────────────────────────────────────────────────────────

/// A successfully created passport entry in the batch result.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CreatedItem {
    /// 1-based row number from the uploaded file.
    pub row: usize,
    /// The `id` returned by the vault for the newly created passport.
    pub passport_id: String,
}

/// A row-level error recorded during the batch run.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RowError {
    /// 1-based row number from the uploaded file.
    pub row: usize,
    /// Field name that triggered the error, or `"vault"` / `"auth"` / `"internal"`.
    pub field: String,
    /// Human-readable error message returned to the caller.
    pub message: String,
}

/// Aggregate result of a batch import run.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BatchResult {
    /// Rows that were successfully sent to the vault and created as passports.
    pub created: Vec<CreatedItem>,
    /// Rows that failed validation, auth, or vault creation.
    pub errors: Vec<RowError>,
}

// ─── Runner ───────────────────────────────────────────────────────────────────

/// Fan out a batch of validated passport requests to the vault service.
///
/// - Maximum `concurrency` requests run concurrently (Tokio semaphore).
/// - Vault `429` responses are retried with exponential backoff (max 3 attempts).
/// - Vault `422` responses are recorded as row errors; the batch continues.
/// - Vault `5xx` responses are recorded as row errors.
#[tracing::instrument(skip(valid_rows, vault_client, auth_token), fields(row_count = valid_rows.len()))]
pub async fn run_batch(
    valid_rows: Vec<(usize, CreatePassportRequest)>,
    vault_client: &VaultHttpClient,
    auth_token: &str,
    concurrency: usize,
) -> BatchResult {
    let sem = Arc::new(Semaphore::new(concurrency.max(1)));
    let mut handles = Vec::with_capacity(valid_rows.len());

    for (row_num, req) in valid_rows {
        let sem = sem.clone();
        let client = vault_client.clone();
        let token = auth_token.to_owned();

        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.expect("semaphore closed unexpectedly");
            let result = retry_create(&client, &req, &token).await;
            (row_num, result)
        }));
    }

    let mut created: Vec<CreatedItem> = Vec::new();
    let mut errors: Vec<RowError> = Vec::new();

    for handle in handles {
        match handle.await {
            Ok((row_num, Ok(body))) => {
                let passport_id = body
                    .get("id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_owned();
                created.push(CreatedItem {
                    row: row_num,
                    passport_id,
                });
            }
            Ok((row_num, Err(VaultClientError::Validation(msg)))) => {
                errors.push(RowError {
                    row: row_num,
                    field: "request".into(),
                    message: msg,
                });
            }
            Ok((row_num, Err(VaultClientError::Unauthorised))) => {
                errors.push(RowError {
                    row: row_num,
                    field: "auth".into(),
                    message: "Not authorised — check your Bearer token.".into(),
                });
            }
            Ok((row_num, Err(e))) => {
                errors.push(RowError {
                    row: row_num,
                    field: "vault".into(),
                    message: e.to_string(),
                });
            }
            Err(join_err) => {
                errors.push(RowError {
                    row: 0,
                    field: "internal".into(),
                    message: format!("Task panicked: {join_err}"),
                });
            }
        }
    }

    BatchResult { created, errors }
}

// ─── Retry logic ─────────────────────────────────────────────────────────────

/// Attempt to create a passport, retrying on `429 Too Many Requests` with
/// exponential backoff. Returns the first non-rate-limit result.
async fn retry_create(
    client: &VaultHttpClient,
    req: &CreatePassportRequest,
    token: &str,
) -> Result<serde_json::Value, VaultClientError> {
    const MAX_RETRIES: u32 = 3;
    const BASE_DELAY_MS: u64 = 100;

    for attempt in 0..MAX_RETRIES {
        match client.create_passport(req, token).await {
            Ok(resp) => return Ok(resp),
            Err(VaultClientError::RateLimit) if attempt < MAX_RETRIES - 1 => {
                let delay = BASE_DELAY_MS * (1u64 << attempt);
                tokio::time::sleep(tokio::time::Duration::from_millis(delay)).await;
            }
            Err(e) => return Err(e),
        }
    }

    Err(VaultClientError::RateLimit)
}
