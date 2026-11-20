//! `/api/v1/discard-records` — ESPR Art. 24 and Art. 25 discard records, and the
//! documents that stand behind them.
//!
//! # What is checked, and where
//!
//! A record is checked against dpp-core's discard-record JSON Schema **as sent**,
//! before it is read into `DiscardRecord`. Reading first would drop a misspelt
//! field and store the record without it, so the schema is the gate and the type
//! is what it has already admitted. Reading a stored record back is more lenient
//! (`dpp_domain::unsold_goods`), so a stored record is never refused here.
//!
//! What the node does not decide is whether a discard is lawful. A record that
//! cites no derogation, or lacks a document, is stored and reported by
//! `missing-evidence`; the record is the claim, the documents its proof.
//!
//! # Why these routes are not on a passport
//!
//! There is no digital product passport anywhere in Art. 24 or Art. 25. The
//! subject is an operator over a financial year, so these sit beside the other
//! operator-scoped routes rather than under `/dpp/{dppId}`.

use std::sync::OnceLock;

use axum::{
    extract::{DefaultBodyLimit, Multipart, Path, State, multipart::MultipartRejection},
    http::StatusCode,
    response::{IntoResponse as _, Response},
};
use chrono::NaiveDate;
use dpp_domain::{
    DppError,
    schemas::VersionedSchemaRegistry,
    unsold_goods::{
        DiscardRecord, EnterpriseSize, EvidenceKind, EvidenceRequirement, FinancialYear,
        RECORD_SCHEMA_KEY, document_schemas,
    },
};
use dpp_types::EVIDENCE_FILE_MAX_BYTES;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use crate::extract::{Json, Query};
use crate::handlers::error::{
    api_error, conflict_error, field_validation_error, internal_error, not_found_error,
    validation_error,
};
use crate::middleware::scope::{RequireAdmin, RequireWrite};
use crate::state::AppState;

/// Head-room for the multipart framing around a file of the largest allowed size.
/// The per-file cap is checked on the file itself; this only stops an upload
/// far beyond it from being buffered.
pub const EVIDENCE_UPLOAD_LIMIT: usize = EVIDENCE_FILE_MAX_BYTES + 1024 * 1024;

/// The financial year a listing covers, by its first and last day.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListQuery {
    /// First day of the financial year.
    pub financial_year_start: NaiveDate,
    /// Last day of the financial year.
    pub financial_year_end: NaiveDate,
}

/// The body of `POST /discard-records`.
///
/// `record` is the discard as core models it, kept as sent until the schema has
/// checked it. `passportIds` names the passports of the units discarded: a join
/// in this node's storage, not part of the record.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateDiscardRecordRequest {
    /// The discard, as core's discard-record schema describes it.
    pub record: serde_json::Value,
    /// The passports of the units discarded. Optional.
    #[serde(default)]
    pub passport_ids: Vec<Uuid>,
}

/// The document an attachment answers with.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttachedEvidence {
    /// The record the document is attached to.
    pub discard_record_id: Uuid,
    /// The evidence kind the document was attached under.
    pub kind: EvidenceKind,
    /// Lower-case hex SHA-256 of the stored bytes.
    pub sha256: String,
    /// Size of the stored bytes.
    pub size_bytes: u64,
}

/// What a record still lacks.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissingEvidence {
    /// The operator's size class, as the requirements were read for it.
    pub enterprise_size: EnterpriseSize,
    /// Each requirement no attached document meets. Empty when none is missing.
    pub missing_evidence: Vec<EvidenceRequirement>,
}

/// Core's discard-record schemas, built once.
fn record_schemas() -> &'static VersionedSchemaRegistry {
    static REGISTRY: OnceLock<VersionedSchemaRegistry> = OnceLock::new();
    REGISTRY.get_or_init(document_schemas)
}

/// The record, as sent, against the current discard-record schema. Returns the
/// version it was checked under, which the store keeps with the row.
#[allow(clippy::result_large_err)]
fn check_record_schema(record: &serde_json::Value) -> Result<String, Response> {
    let registry = record_schemas();
    let Some((version, _)) = registry.latest(RECORD_SCHEMA_KEY) else {
        return Err(internal_error(
            "the catalog names no current discard-record schema",
        ));
    };
    registry
        .validate(RECORD_SCHEMA_KEY, version, record)
        .map_err(|errors| field_validation_error(&errors))?;
    Ok(version.to_string())
}

#[allow(clippy::result_large_err)]
fn parse_record_id(s: &str) -> Result<Uuid, Response> {
    Uuid::parse_str(s)
        .map_err(|_| api_error(StatusCode::BAD_REQUEST, "", "Invalid discard record id"))
}

/// Record a discard, with the passports it names.
///
/// Creating a record is not idempotent on its own, so the route is keyed in the
/// idempotency policy; a retry under the same key replays this answer.
pub async fn discard_record_create_handler(
    State(state): State<AppState>,
    RequireWrite(_auth): RequireWrite,
    Json(body): Json<CreateDiscardRecordRequest>,
) -> Response {
    let schema_version = match check_record_schema(&body.record) {
        Ok(version) => version,
        Err(response) => return response,
    };
    let record: DiscardRecord = match serde_json::from_value(body.record) {
        Ok(record) => record,
        Err(e) => return validation_error(&format!("The record could not be read: {e}")),
    };
    match state
        .discard_records
        .create(&record, &schema_version, &body.passport_ids)
        .await
    {
        Ok(stored) => (StatusCode::CREATED, Json(stored)).into_response(),
        Err(DppError::Validation(errors)) => field_validation_error(&errors),
        Err(e) => internal_error(e),
    }
}

/// List the discard records of a financial year, earliest discard first.
///
/// Admin rather than write: these are the operator's own annual figures, and
/// reading them back is an administrative act rather than part of producing
/// passports.
pub async fn discard_record_list_handler(
    State(state): State<AppState>,
    RequireAdmin(_auth): RequireAdmin,
    Query(q): Query<ListQuery>,
) -> Response {
    let year = FinancialYear {
        start: q.financial_year_start,
        end: q.financial_year_end,
    };
    match state.discard_records.list_for_year(year).await {
        Ok(rows) => Json(rows).into_response(),
        Err(e) => internal_error(e),
    }
}

/// Attach a document to a record under an evidence kind.
///
/// The form has two fields: `kind`, an evidence kind as core names it, and
/// `file`, the document. The document is stored under its SHA-256, once however
/// many records cite it, and the attachment is recorded against the record.
pub async fn discard_record_attach_handler(
    State(state): State<AppState>,
    RequireWrite(_auth): RequireWrite,
    Path(id): Path<String>,
    multipart: Result<Multipart, MultipartRejection>,
) -> Response {
    let id = match parse_record_id(&id) {
        Ok(id) => id,
        Err(response) => return response,
    };
    let mut multipart = match multipart {
        Ok(multipart) => multipart,
        Err(rejection) => {
            return api_error(rejection.status(), "", &rejection.body_text());
        }
    };

    let mut kind: Option<EvidenceKind> = None;
    let mut file: Option<Vec<u8>> = None;
    loop {
        match multipart.next_field().await {
            Ok(Some(field)) => {
                let name = field.name().unwrap_or("").to_owned();
                match name.as_str() {
                    "kind" => {
                        let text = match field.text().await {
                            Ok(text) => text,
                            Err(e) => return api_error(e.status(), "", &e.body_text()),
                        };
                        kind = match serde_json::from_value(serde_json::Value::String(
                            text.trim().to_owned(),
                        )) {
                            Ok(kind) => Some(kind),
                            Err(_) => {
                                return validation_error(
                                    "`kind` must be one of the evidence kinds dpp-core names, \
                                     for example `deliveryDocumentation`.",
                                );
                            }
                        };
                    }
                    "file" => match field.bytes().await {
                        Ok(bytes) => file = Some(bytes.to_vec()),
                        Err(e) => return api_error(e.status(), "", &e.body_text()),
                    },
                    _ => {
                        if let Err(e) = field.bytes().await {
                            return api_error(e.status(), "", &e.body_text());
                        }
                    }
                }
            }
            Ok(None) => break,
            Err(e) => return api_error(e.status(), "", &e.body_text()),
        }
    }

    let Some(kind) = kind else {
        return validation_error("The form needs a `kind`: the evidence kind the document is for.");
    };
    let Some(bytes) = file else {
        return validation_error("The form needs a `file`: the document to attach.");
    };
    if bytes.len() > EVIDENCE_FILE_MAX_BYTES {
        return api_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "",
            "The file is larger than the 25 MiB one evidence file may be.",
        );
    }

    match state.discard_records.get(id).await {
        Ok(Some(_)) => {}
        Ok(None) => return not_found_error("Discard record not found."),
        Err(e) => return internal_error(e),
    }

    let sha256 = hex::encode(Sha256::digest(&bytes));
    if let Err(e) = state.evidence_store.put(&sha256, &bytes).await {
        return internal_error(e);
    }
    match state.discard_records.attach(id, kind, &sha256).await {
        Ok(true) => (
            StatusCode::CREATED,
            Json(AttachedEvidence {
                discard_record_id: id,
                kind,
                sha256,
                size_bytes: bytes.len() as u64,
            }),
        )
            .into_response(),
        Ok(false) => conflict_error("This record already holds this document under this kind."),
        Err(e) => internal_error(e),
    }
}

/// The evidence a record still lacks, read against the operator's size class.
///
/// A requirement is missing when no attached document meets it. A missing
/// document is not proof of a breach: the Regulation excepts information the
/// competent authority already holds under another act, which only the operator
/// can say.
pub async fn discard_record_missing_handler(
    State(state): State<AppState>,
    RequireAdmin(_auth): RequireAdmin,
    Path(id): Path<String>,
) -> Response {
    let id = match parse_record_id(&id) {
        Ok(id) => id,
        Err(response) => return response,
    };
    let stored = match state.discard_records.get(id).await {
        Ok(Some(stored)) => stored,
        Ok(None) => return not_found_error("Discard record not found."),
        Err(e) => return internal_error(e),
    };
    let size = match state.service.enterprise_size().await {
        Ok(size) => size,
        Err(e) => return internal_error(e),
    };
    let held = match state.discard_records.held_kinds(id).await {
        Ok(held) => held,
        Err(e) => return internal_error(e),
    };
    Json(MissingEvidence {
        enterprise_size: size,
        missing_evidence: stored.record.missing_evidence(size, &held),
    })
    .into_response()
}

/// The body limit the attachment route reads through. Set on the route, because
/// the default would refuse a document between 2 MiB and the per-file cap.
pub fn evidence_body_limit() -> DefaultBodyLimit {
    DefaultBodyLimit::max(EVIDENCE_UPLOAD_LIMIT)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A discard is a record, and the record names its derogation point by its
    /// wire name. A reason written in the old line vocabulary is refused here.
    #[test]
    fn a_record_is_refused_while_it_is_checked_as_sent() {
        let misspelt = serde_json::json!({
            "discardedOn": "2026-08-01",
            "cnCodes": ["420300"],
            "description": "Jackets",
            "units": { "value": 10 },
            "weight": { "grams": 5000 },
            "packagingIncluded": false,
            "treatment": "recycling",
            "receiver": { "name": "Recycler" },
            "reasonLabel": "Stock",
            "reasonn": "damagedOrContaminated"
        });
        assert!(check_record_schema(&misspelt).is_err());
    }

    /// The per-file cap is the one number the spec and the store both have to
    /// agree on, so it is pinned here.
    #[test]
    fn the_per_file_cap_is_twenty_five_mebibytes() {
        assert_eq!(EVIDENCE_FILE_MAX_BYTES, 25 * 1024 * 1024);
    }

    #[test]
    fn a_record_id_is_a_uuid() {
        assert!(parse_record_id(&Uuid::now_v7().to_string()).is_ok());
        assert!(parse_record_id("not-a-record").is_err());
    }
}
