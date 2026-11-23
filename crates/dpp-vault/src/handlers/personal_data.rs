//! `/api/v1/personal-data/{record}` — erase a record of personal data.
//!
//! # Why the route exists
//!
//! A passport's `personalData` statement may name a record held outside the
//! passport, on a stated lawful basis. When the basis is consent, withdrawing it
//! (GDPR Art. 7(3)) obliges erasure (Art. 17(1)(b)), and a published passport
//! cannot be erased from — so the record is held where it can be, and this is
//! how the operator honours the withdrawal.
//!
//! # What erasing does and does not touch
//!
//! It drops the record's content and keeps a tombstone: the identifier, the
//! passport and field the record belonged to, and when it was erased. It never
//! reaches the passport, which is signed and frozen, nor the statement in it,
//! which keeps naming the record — so a reader following the statement learns
//! that the record is gone rather than that it never existed.
//!
//! **The tombstone is not free of personal data.** A passport identifier can
//! relate to whoever owns the item, and information that can be linked to a
//! person is personal data (GDPR Recital 26). So the receipt is as sensitive as
//! the passport's individual-item data, and the operator needs a basis for
//! keeping the tombstone — to show that it erased (Art. 5(2)) is one. Nothing
//! here deletes it.
//!
//! # Scope
//!
//! Admin, like every other route that removes something (`DELETE` on API keys,
//! webhooks, facilities and operator identifiers). The write scope produces and
//! moves passports; none of that destroys anything, and this cannot be undone.
//! Loosening the gate later breaks nobody; tightening it would.
//!
//! # No `Idempotency-Key`
//!
//! The route is idempotent without one: erasing a record already erased returns
//! the receipt it was given the first time, so a caller that lost the answer
//! asks again. Keying it would store a second copy of the receipt.
//!
//! # Storing and listing: `/api/v1/dpp/{dppId}/personal-data`
//!
//! Erasing needs a record to exist, and nothing else in the node writes one, so
//! the same path takes `POST` to hold one and `GET` to list what is held for the
//! passport. A client creates the draft, stores the record, then patches the
//! statement that names it into the draft: the statement needs the record's id
//! and the store needs the passport's.
//!
//! **A listing is as sensitive as the passport's individual-item data.** It
//! returns identifiers, the field, whether each record is present or erased, and
//! the instants, which relate a passport to whoever owns the item (Recital 26).
//! Both routes are admin, like the erase route, and neither ever returns, logs or
//! stores anywhere else the content.
//!
//! **No `Idempotency-Key`, on purpose.** The key store keeps a SHA-256 of the raw
//! request body, and the response, for a day. For this route the body is the
//! personal data: a hash of it would outlive an erasure that nothing here can
//! reach, and the hash of a short or guessable value is not anonymous. A retry
//! stores a second record instead, which is the contract core states for
//! `store`: the listing finds the first, and the erase route erases it.
//!
//! # Why no route returns a record's content
//!
//! A record's content is served by no route of this node. Serving it to a reader
//! is a disclosure that needs a basis of its own, which only the controller can
//! establish for each purpose; GDPR Art. 25(2) makes withholding it the default.

use std::collections::BTreeSet;
use std::sync::OnceLock;

use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse as _, Response};
use chrono::{DateTime, Utc};
use dpp_domain::status::PassportStatus;
use dpp_domain::{
    DppError, ErasureReceipt, HeldRecord, PersonalDataRecordId, ProductGroup, ProductGroupCatalog,
    personal_data_marks,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::extract::Json;
use crate::handlers::error::{
    conflict_error, internal_error, not_found_error, parse_passport_id, validation_error,
};
use crate::middleware::scope::RequireAdmin;
use crate::state::AppState;

/// The most a store request's body may be: the field and the content it holds.
///
/// Personal data related to one marked field is a note, a name, a contact or a
/// log of events, and the node holds it as one JSON value. 64 KiB is generous for
/// that and small enough that the route cannot be used to park documents, which
/// is what the evidence store is for.
pub const PERSONAL_DATA_BODY_MAX_BYTES: usize = 64 * 1024;

/// The limit on the store route, in place of the node-wide one.
pub fn personal_data_body_limit() -> DefaultBodyLimit {
    DefaultBodyLimit::max(PERSONAL_DATA_BODY_MAX_BYTES)
}

/// What is left of an erased record: which record it was, which passport and
/// field it related to, and when it was erased. None of the erased content.
///
/// The same receipt on every call after the first.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PersonalDataErasureReceipt {
    /// The erased record's identifier, as the passport's statement names it.
    pub record: String,
    /// The passport the record related to. Still related to whoever owns the
    /// item, so this receipt is kept like the passport's individual-item data.
    pub passport_id: Uuid,
    /// The marked field the record related to, as a dotted path inside
    /// `productGroupData`.
    pub field: String,
    /// When the record's content was erased.
    pub erased_at: DateTime<Utc>,
}

impl From<ErasureReceipt> for PersonalDataErasureReceipt {
    fn from(receipt: ErasureReceipt) -> Self {
        Self {
            record: receipt.record.to_string(),
            passport_id: receipt.passport_id.0,
            field: receipt.field,
            erased_at: receipt.erased_at,
        }
    }
}

/// `DELETE /api/v1/personal-data/{record}` — erase one record, keeping its
/// tombstone, and answer with the receipt.
///
/// `404` for a `record` this node never minted — including a string that could
/// not have been, which is not told apart from a well-formed identifier that
/// names nothing. Erasing a record already erased is not an error.
pub async fn personal_data_erase_handler(
    State(state): State<AppState>,
    RequireAdmin(auth): RequireAdmin,
    Path(record): Path<String>,
) -> Response {
    let record = PersonalDataRecordId::new(record);
    match state.personal_data.erase(&record).await {
        Ok(receipt) => {
            // Who erased it. The tombstone records what was erased and when, and
            // not by whom, so this line is where the actor is kept. It names the
            // record and never the passport: the module doc explains why the
            // passport is personal data. A retry logs again and answers the
            // same receipt.
            tracing::info!(
                actor = %auth.user_id,
                record = %record,
                "erased a personal data record"
            );
            Json(PersonalDataErasureReceipt::from(receipt)).into_response()
        }
        Err(DppError::NotFound(_)) => {
            not_found_error(&format!("No personal data record {record} is held here."))
        }
        Err(e) => internal_error(e),
    }
}

/// What is held for one passport's marked field, and nothing it holds: no
/// content, in either state.
///
/// A present record carries when it was stored; an erased one carries when it
/// was erased, since that is all its tombstone keeps.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PersonalDataRecordSummary {
    /// The record's identifier, as the passport's statement names it.
    pub record: String,
    /// The marked field the record relates to, as a dotted path inside
    /// `productGroupData`.
    pub field: String,
    /// Whether the content is still held.
    pub state: RecordState,
    /// When the record was stored. Absent once it is erased.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stored_at: Option<DateTime<Utc>>,
    /// When the record's content was erased. Absent while it is present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub erased_at: Option<DateTime<Utc>>,
}

/// Whether a record's content is still held.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RecordState {
    /// The content is held and can be erased.
    Present,
    /// The content is gone and the tombstone remains.
    Erased,
}

impl From<HeldRecord> for PersonalDataRecordSummary {
    /// The one place a held record becomes an answer. It names the fields it
    /// carries over, so the content a present record holds is dropped here and
    /// cannot reach a response by being added to a struct elsewhere.
    fn from(held: HeldRecord) -> Self {
        match held {
            HeldRecord::Present(record) => Self {
                record: record.id.to_string(),
                field: record.field,
                state: RecordState::Present,
                stored_at: Some(record.stored_at),
                erased_at: None,
            },
            HeldRecord::Erased(receipt) => Self {
                record: receipt.record.to_string(),
                field: receipt.field,
                state: RecordState::Erased,
                stored_at: None,
                erased_at: Some(receipt.erased_at),
            },
        }
    }
}

/// Every record held for a passport, oldest first.
#[derive(Debug, Serialize)]
pub struct PersonalDataRecordList {
    /// Present and erased records alike. Empty when none was ever stored.
    pub records: Vec<PersonalDataRecordSummary>,
}

/// The body of a store request.
///
/// No `Debug`: the content is personal data, and a derived `Debug` is one
/// `{:?}` away from a log line. `Serialize` is for the OpenAPI contract test,
/// which checks the published request schema against the type behind it.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StorePersonalDataRequest {
    /// The marked field the record relates to, as a dotted path inside
    /// `productGroupData` (`usageHistory.negativeEvents`).
    pub field: String,
    /// The personal data, in whatever shape the controller keeps it. Not `null`.
    pub content: serde_json::Value,
}

/// The fields a passport's product group marks as able to hold personal data.
///
/// The same two calls core's `check_personal_data` makes to decide whether a
/// statement may be made about a field: the current schema version of the
/// product group, and the marks read from it. A record stored for any other
/// field could never be named by a statement, so it could only ever be an
/// orphan. `a_stored_field_is_one_core_lets_a_statement_name` pins that this set
/// and core's check agree.
fn marked_fields(group: &ProductGroup) -> BTreeSet<String> {
    static CATALOG: OnceLock<ProductGroupCatalog> = OnceLock::new();
    let key = group.catalog_key();
    CATALOG
        .get_or_init(ProductGroupCatalog::new)
        .current_schema_version(key)
        .and_then(|version| personal_data_marks(key, version))
        .unwrap_or_default()
}

/// `POST /api/v1/dpp/{dppId}/personal-data` — hold personal data related to one
/// marked field of a draft passport, and answer the record's identifier.
///
/// Refuses, in this order: `404` for a passport this node does not hold, `409`
/// for one that is not a draft (its statement is signed, or about to be, and can
/// no longer be changed to name a new record), then `422` for a `field` the
/// passport's schema does not mark and for `content` that is `null`. A body over
/// [`PERSONAL_DATA_BODY_MAX_BYTES`] is `413`.
///
/// Every call stores a new record. A retry after a lost answer stores a second,
/// which the listing finds.
pub async fn personal_data_store_handler(
    State(state): State<AppState>,
    // The gate precedes the body extractor, so a refused caller's body is never
    // buffered or parsed.
    RequireAdmin(auth): RequireAdmin,
    Path(dpp_id): Path<String>,
    Json(body): Json<StorePersonalDataRequest>,
) -> Response {
    let passport_id = match parse_passport_id(&dpp_id) {
        Ok(id) => id,
        Err(e) => return e,
    };

    let passport = match state.service.find_by_id(passport_id).await {
        Ok(p) => p,
        Err(DppError::NotFound(_)) => return not_found_error("DPP not found."),
        Err(e) => return internal_error(e),
    };
    if passport.status != PassportStatus::Draft {
        return conflict_error(
            "Only a draft takes a new record: the statement of a passport that is no longer a \
             draft cannot be changed to name one.",
        );
    }

    let marks = marked_fields(&passport.product_group);
    if !marks.contains(&body.field) {
        let marked = if marks.is_empty() {
            "This product group's schema marks no field".to_owned()
        } else {
            format!(
                "The fields it marks are: {}",
                marks
                    .iter()
                    .map(String::as_str)
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        };
        return validation_error(&format!(
            "'{}' is not a field this product group's schema marks as able to hold personal \
             data, so no statement could name a record for it. {marked}.",
            body.field
        ));
    }
    if body.content.is_null() {
        return validation_error("`content` is the personal data to hold, and cannot be null.");
    }

    let record = match state
        .personal_data
        .store(passport_id, &body.field, &body.content)
        .await
    {
        Ok(record) => record,
        Err(DppError::NotFound(_)) => return not_found_error("DPP not found."),
        Err(e) => return internal_error(e),
    };
    // Who stored it, by the record and never the passport or the content: the
    // module doc of the erase route explains why the passport is personal data.
    tracing::info!(actor = %auth.user_id, record = %record, "stored a personal data record");

    match state.personal_data.fetch(&record).await {
        Ok(Some(held @ HeldRecord::Present(_))) => (
            StatusCode::CREATED,
            Json(PersonalDataRecordSummary::from(held)),
        )
            .into_response(),
        // The record was stored a moment ago. The caller is not told its id, so
        // it finds it through the listing.
        Ok(_) => internal_error("a personal data record that was just stored is not present"),
        Err(e) => internal_error(e),
    }
}

/// `GET /api/v1/dpp/{dppId}/personal-data` — every record held for a passport,
/// present or erased, oldest first, and none of their content.
///
/// `404` for a passport this node does not hold, which is not told apart from
/// nothing being stored: that is a `200` with no records.
pub async fn personal_data_list_handler(
    State(state): State<AppState>,
    RequireAdmin(_auth): RequireAdmin,
    Path(dpp_id): Path<String>,
) -> Response {
    let passport_id = match parse_passport_id(&dpp_id) {
        Ok(id) => id,
        Err(e) => return e,
    };

    match state.service.find_by_id(passport_id).await {
        Ok(_) => {}
        Err(DppError::NotFound(_)) => return not_found_error("DPP not found."),
        Err(e) => return internal_error(e),
    }

    match state.personal_data.records_for(passport_id).await {
        Ok(records) => Json(PersonalDataRecordList {
            records: records
                .into_iter()
                .map(PersonalDataRecordSummary::from)
                .collect(),
        })
        .into_response(),
        Err(e) => internal_error(e),
    }
}

#[cfg(test)]
mod tests {
    use dpp_domain::passport::{Passport, PassportId};
    use dpp_domain::personal_data::PersonalDataStatement;
    use dpp_domain::{PersonalDataRecord, check_personal_data};

    use super::*;

    /// A passport of `group` whose statement says nothing is held about `field`.
    fn stating(group: &ProductGroup, field: &str) -> Passport {
        let mut passport = crate::public_view::tests::stub_passport();
        passport.product_group = group.clone();
        passport
            .personal_data
            .insert(field.to_owned(), PersonalDataStatement::NothingHeld);
        passport
    }

    /// Whether core refuses the statement for being about a field the schema does
    /// not mark. A statement that holds nothing meets no other condition, so this
    /// is the only finding that can sit at the statement's own pointer.
    fn refused_as_unmarked(passport: &Passport, field: &str) -> bool {
        let pointer = format!(
            "/personalData/{}",
            field.replace('~', "~0").replace('/', "~1")
        );
        check_personal_data(passport)
            .iter()
            .any(|e| e.field == pointer)
    }

    /// 🚨 This route restates two calls core's `check_personal_data` makes. If core
    /// reads the marks another way, this is where the two part: a record would be
    /// stored for a field no statement can name, or refused for one that one can.
    #[test]
    fn a_stored_field_is_one_core_lets_a_statement_name() {
        let catalog = ProductGroupCatalog::new();
        let mut marked = 0usize;

        for descriptor in catalog.all() {
            let group = ProductGroup::from_wire_tag(&descriptor.key);
            for field in marked_fields(&group) {
                marked += 1;
                assert!(
                    !refused_as_unmarked(&stating(&group, &field), &field),
                    "{} marks '{field}', and core refuses a statement about it",
                    descriptor.key
                );
            }
            assert!(
                refused_as_unmarked(&stating(&group, "notAMarkedField"), "notAMarkedField"),
                "{}: core accepts a statement about a field nothing marks, so the check above \
                 proves nothing",
                descriptor.key
            );
        }
        assert!(marked > 0, "no product group marks a field in this build");
    }

    /// The summary names fields; it does not copy them. A present record holds
    /// the content, and the one conversion that builds an answer from it must
    /// leave it behind.
    #[test]
    fn the_summary_of_a_present_record_carries_no_content() {
        let held = HeldRecord::Present(PersonalDataRecord {
            id: PersonalDataRecordId::new("record-1"),
            passport_id: PassportId::new(),
            field: "repairHistoryUrl".into(),
            content: serde_json::json!({ "owner": "Ada Lovelace" }),
            stored_at: Utc::now(),
        });

        let summary = serde_json::to_value(PersonalDataRecordSummary::from(held)).unwrap();

        assert!(!summary.to_string().contains("Ada Lovelace"), "{summary}");
        assert_eq!(summary["state"], "present");
        assert_eq!(summary["record"], "record-1");
        assert!(summary["storedAt"].is_string());
        assert!(summary.get("erasedAt").is_none(), "{summary}");
    }
}
