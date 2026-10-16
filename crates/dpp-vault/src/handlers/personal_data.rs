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
//! # Why there is no read route
//!
//! A record is served by no route of this node. Serving one to a reader is a
//! disclosure that needs a basis of its own, which only the controller can
//! establish for each purpose; GDPR Art. 25(2) makes withholding it the default.

use axum::extract::{Path, State};
use axum::response::{IntoResponse as _, Response};
use chrono::{DateTime, Utc};
use dpp_domain::{DppError, ErasureReceipt, PersonalDataRecordId};
use serde::Serialize;
use uuid::Uuid;

use crate::extract::Json;
use crate::handlers::error::{internal_error, not_found_error};
use crate::middleware::scope::RequireAdmin;
use crate::state::AppState;

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
    RequireAdmin(_auth): RequireAdmin,
    Path(record): Path<String>,
) -> Response {
    let record = PersonalDataRecordId::new(record);
    match state.personal_data.erase(&record).await {
        Ok(receipt) => Json(PersonalDataErasureReceipt::from(receipt)).into_response(),
        Err(DppError::NotFound(_)) => {
            not_found_error(&format!("No personal data record {record} is held here."))
        }
        Err(e) => internal_error(e),
    }
}
