//! Recording, by hand, the correlation identifier of a registry submission whose
//! handle this node lost.
//!
//! The registry drain recovers a lost handle by itself where it can: it looks the
//! submission up by the unique product identifier the passport was submitted
//! under. Three cases it deliberately leaves alone — several submissions report
//! the identifier, none could be placed, and an adapter that cannot look one up —
//! because choosing would give a passport another passport's registration. A row
//! in one of them stays `submitted`, says why, and waits for a person, who can
//! read the right handle off the registry's own interface.
//!
//! This is what that person's answer is recorded with. It does not take their word
//! for it: the submission the handle names is read back from the registry and must
//! report the identifier this passport was submitted under, so a typo, or the
//! handle of a neighbouring passport, is refused and not recorded.
//!
//! # What it does not do
//!
//! It records the handle and nothing else. The ruling on the submission is the
//! drain's to apply, on its next pass, because the drain is the one place that
//! decides what a registration, a refusal or a state nobody has named does to a
//! row; applying it here as well would be a second copy of that rule.

use dpp_domain::{
    error::DppError,
    passport::PassportId,
    ports::registry_sync::{RegistrationRequest, SubmissionConfirmation, SubmissionReport},
};
use dpp_types::{
    RegistrySyncRow, RegistrySyncStatus, audit::PassportAuditEntry, auth::AuthContext,
};

use super::PassportService;

/// The audit action recording that a person established a submission's handle.
pub const REGISTRY_HANDLE_RECORDED: &str = "registry_handle_recorded";

/// A handle recorded, or found to be recorded already.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedHandle {
    /// The correlation identifier the row now holds.
    pub correlation_id: String,
    /// What the registry reported about the submission when the handle was
    /// checked. `None` when the row already held this handle and nothing was
    /// checked or written: a retry of a request whose answer was lost.
    pub report: Option<SubmissionReport>,
}

/// Why a handle was not recorded.
#[derive(Debug)]
pub enum RecordHandleError {
    /// This node has no registry queues, so there is no row to record on.
    NotConfigured,
    /// The passport has no registry row: it was never published.
    NoRegistration,
    /// The row is not `submitted`. A row still `pending` has not been accepted by
    /// the registry, so it has no handle to record; a row that has been ruled on
    /// no longer needs one.
    NotAwaitingAHandle(RegistrySyncStatus),
    /// The row already holds a different handle. One the registry gave is never
    /// overwritten by a person's.
    HoldsAnotherHandle,
    /// The row's frozen payload is missing or unreadable, so there is nothing to
    /// check the handle against.
    CannotSayWhatWasSubmitted,
    /// The registry did not show the handle to be this passport's. Carries what
    /// it did show.
    NotConfirmed(SubmissionConfirmation),
    /// The registry could not be read.
    Registry(DppError),
    /// The row could not be read or written.
    Storage(DppError),
}

/// What the row says about recording `correlation_id` on it, before and after a
/// write that may have lost a race.
enum RowState {
    /// It holds this handle already.
    Recorded,
    /// Nothing stands in the way.
    Open,
    /// Something does.
    Refused(RecordHandleError),
}

fn state_of(row: &RegistrySyncRow, correlation_id: &str) -> RowState {
    if row.status != RegistrySyncStatus::Submitted {
        return RowState::Refused(RecordHandleError::NotAwaitingAHandle(row.status));
    }
    match row
        .registry_id
        .as_deref()
        .map(str::trim)
        .filter(|held| !held.is_empty())
    {
        Some(held) if held == correlation_id => RowState::Recorded,
        Some(_) => RowState::Refused(RecordHandleError::HoldsAnotherHandle),
        None => RowState::Open,
    }
}

impl PassportService {
    /// Record `correlation_id` as the handle of this passport's submission, once
    /// the registry has shown it to be the passport's.
    ///
    /// Idempotent: a row that already holds this handle answers as though it had
    /// just recorded it, without asking the registry or writing the trail again,
    /// so a retry of a request whose answer was lost does not fail on its own
    /// success.
    ///
    /// # Errors
    /// See [`RecordHandleError`].
    pub async fn record_registry_handle(
        &self,
        id: PassportId,
        correlation_id: &str,
        auth: &AuthContext,
    ) -> Result<RecordedHandle, RecordHandleError> {
        let outbox = self
            .registry_outbox
            .as_ref()
            .ok_or(RecordHandleError::NotConfigured)?;
        let recorded = |report| RecordedHandle {
            correlation_id: correlation_id.to_owned(),
            report,
        };

        let row = outbox
            .pending_for(id)
            .await
            .map_err(RecordHandleError::Storage)?
            .ok_or(RecordHandleError::NoRegistration)?;
        match state_of(&row, correlation_id) {
            RowState::Recorded => return Ok(recorded(None)),
            RowState::Refused(why) => return Err(why),
            RowState::Open => {}
        }

        let request: RegistrationRequest = row
            .payload
            .and_then(|payload| serde_json::from_value(payload).ok())
            .ok_or(RecordHandleError::CannotSayWhatWasSubmitted)?;
        let confirmation = self
            .registry_sync
            .confirm_submission(&request, correlation_id)
            .await
            .map_err(RecordHandleError::Registry)?;
        let SubmissionConfirmation::Confirmed { report } = confirmation else {
            return Err(RecordHandleError::NotConfirmed(confirmation));
        };

        let took = outbox
            .record_handle(id, correlation_id)
            .await
            .map_err(RecordHandleError::Storage)?;
        if !took {
            // The row moved between the read and the write: the drain ruled on it,
            // or another request recorded a handle. Say what it is now, which may
            // be this very handle, recorded by a concurrent request.
            let now = outbox
                .pending_for(id)
                .await
                .map_err(RecordHandleError::Storage)?
                .ok_or(RecordHandleError::NoRegistration)?;
            return match state_of(&now, correlation_id) {
                RowState::Recorded => Ok(recorded(None)),
                RowState::Refused(why) => Err(why),
                // Still open, and yet the write took nothing: the row is not in
                // the state the statement requires. Not something to retry into.
                RowState::Open => Err(RecordHandleError::NotAwaitingAHandle(now.status)),
            };
        }

        // The handle is the row's now. The trail records who put it there and what
        // the registry said when they did, which is the only account of a write
        // that overrides the drain's own judgement.
        let entry = PassportAuditEntry::new(
            &id.to_string(),
            REGISTRY_HANDLE_RECORDED,
            &auth.user_id,
            None,
            None,
        )
        .with_metadata(serde_json::json!({
            "correlationId": correlation_id,
            "report": &report,
        }));
        self.audit
            .append(entry)
            .await
            .map_err(RecordHandleError::Storage)?;

        tracing::warn!(
            passport_id = %id,
            correlation_id,
            actor = %auth.user_id,
            "a registry submission's correlation identifier was recorded by hand — the drain \
             will poll it from now on"
        );
        Ok(recorded(Some(report)))
    }
}
