//! Delta-import matcher: classifies each valid row against existing passports
//! by exact compound identity (sector, GTIN, batch), so a re-uploaded sheet
//! updates what changed instead of creating duplicates.
//!
//! Classification names what should happen to each row
//! (`create`/`update_draft`/`conflict_published`/`unchanged`); that name (and,
//! for a match, the existing passport's id) is persisted into the import
//! report for both dry-run and apply, and `batch_runner::run_batch` reads it
//! back to decide what to actually write in apply mode.

use std::collections::HashMap;
use std::sync::Arc;

use sha2::{Digest, Sha256};
use tokio::sync::Semaphore;

use dpp_domain::domain::product_identity::ProductIdentity;

use crate::domain::request::CreatePassportRequest;
use crate::infra::vault_client::{VaultClientError, VaultHttpClient};

/// What should happen to a row, decided by identity match + content hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RowAction {
    /// No existing passport matches this identity.
    Create,
    /// Matches an existing `Draft` passport with different content.
    UpdateDraft,
    /// Matches an existing `Published` passport with different content.
    /// Detect-and-report only — never mutated by the importer.
    ConflictPublished,
    /// Matches an existing passport (`Draft` or `Published`) with identical
    /// content — nothing to do.
    Unchanged,
}

/// A row's classification, plus the matched passport's id when there is one
/// (`UpdateDraft`/`ConflictPublished`/`Unchanged` all matched *something*;
/// `Create` didn't).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Classification {
    pub action: RowAction,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub existing_id: Option<String>,
}

/// Fields that define a row's content for change detection. Deliberately
/// excludes `co2ePerUnit`/`repairabilityScore`: `CreatePassportRequest`
/// carries these as bare numbers but the persisted `Passport` carries them as
/// computed objects (e.g. `CarbonFootprint`), so comparing them directly
/// would always report a spurious change. `sectorData` already carries the
/// source values these are usually derived from.
const COMPARABLE_FIELDS: &[&str] = &[
    "productName",
    "sector",
    "manufacturer",
    "materials",
    "sectorData",
    "batchId",
];

/// Hash the comparable subset of a request or passport JSON body, so a
/// `CreatePassportRequest` and the persisted `Passport` it matches can be
/// compared without needing the same Rust type on both sides.
pub fn content_hash(value: &serde_json::Value) -> String {
    let mut canonical = serde_json::Map::new();
    for &field in COMPARABLE_FIELDS {
        if let Some(v) = value.get(field) {
            canonical.insert(field.to_owned(), v.clone());
        }
    }
    let bytes = serde_json::to_vec(&serde_json::Value::Object(canonical)).unwrap_or_default();
    format!("{:x}", Sha256::digest(&bytes))
}

/// Derive the compound identity from a not-yet-created request, or `None` if
/// its sector carries no GTIN (mirrors `ProductIdentity::from_passport`, but
/// operates on the pre-create request shape).
pub fn identity_from_request(req: &CreatePassportRequest) -> Option<ProductIdentity> {
    let sector = req.sector.clone().or_else(|| {
        req.sector_data
            .as_ref()
            .map(dpp_domain::domain::sector::SectorData::sector)
    })?;
    let gtin = req.sector_data.as_ref()?.gtin()?.to_owned();
    Some(ProductIdentity {
        sector,
        gtin,
        batch_id: req.batch_id.clone(),
    })
}

/// Classify one row against the vault's existing passports.
///
/// Rows whose sector carries no GTIN (no identity derivable) always classify
/// as `Create` — there is nothing to match against.
pub async fn classify_row(
    vault_client: &VaultHttpClient,
    req: &CreatePassportRequest,
    auth_token: &str,
) -> Result<Classification, VaultClientError> {
    let Some(identity) = identity_from_request(req) else {
        return Ok(Classification {
            action: RowAction::Create,
            existing_id: None,
        });
    };

    let existing = match vault_client.find_by_identity(&identity, auth_token).await? {
        Some(p) => p,
        None => {
            return Ok(Classification {
                action: RowAction::Create,
                existing_id: None,
            });
        }
    };
    let existing_id = existing
        .get("id")
        .and_then(|v| v.as_str())
        .map(str::to_owned);

    let req_value = serde_json::to_value(req).unwrap_or_default();
    if content_hash(&req_value) == content_hash(&existing) {
        return Ok(Classification {
            action: RowAction::Unchanged,
            existing_id,
        });
    }

    let action = match existing.get("status").and_then(|s| s.as_str()) {
        Some("active") => RowAction::ConflictPublished,
        _ => RowAction::UpdateDraft,
    };
    Ok(Classification {
        action,
        existing_id,
    })
}

/// Classify a batch of valid rows concurrently (same bounded-concurrency
/// pattern as `batch_runner::run_batch`, since this is the same kind of
/// per-row vault HTTP call). A row whose classification call fails (network,
/// auth, vault error) falls back to `Create` — the same "nothing matched"
/// outcome as a genuine no-match, so a transient lookup failure degrades to
/// the always-safe default (a possible duplicate, never a missed conflict)
/// rather than silently dropping the row from the report.
pub async fn classify_batch(
    rows: &[(usize, CreatePassportRequest)],
    vault_client: &VaultHttpClient,
    auth_token: &str,
    concurrency: usize,
) -> HashMap<usize, Classification> {
    let sem = Arc::new(Semaphore::new(concurrency.max(1)));
    let mut handles = Vec::with_capacity(rows.len());

    for (row_num, req) in rows {
        let sem = sem.clone();
        let client = vault_client.clone();
        let token = auth_token.to_owned();
        let req = req.clone();
        let row_num = *row_num;

        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.expect("semaphore closed unexpectedly");
            let classification =
                classify_row(&client, &req, &token)
                    .await
                    .unwrap_or(Classification {
                        action: RowAction::Create,
                        existing_id: None,
                    });
            (row_num, classification)
        }));
    }

    let mut result = HashMap::with_capacity(rows.len());
    for handle in handles {
        if let Ok((row_num, classification)) = handle.await {
            result.insert(row_num, classification);
        }
    }
    result
}
