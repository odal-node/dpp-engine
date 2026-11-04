//! Giving up, on a person's say-so, on a registration the registry never accepted.
//!
//! A `pending` row is retried with backoff for as long as the passport is
//! published. When the payload is refused every time, or the product is withdrawn
//! before it was ever registered, that is forever, and the only way off the queue
//! used to be a database edit.
//!
//! The danger is not the write, it is what it can be wrong about. A `pending` row
//! whose first attempt got through and whose reply was lost looks exactly like one
//! that never did: the registry holds a submission for the passport, and this node
//! has no record that it does. Abandoning that row would leave a registration the
//! registry is checking, and may grant, that the node believes it dropped.
//!
//! So this does not take the operator's word for it either. The registry's own
//! task list is read for a submission under the identifier the passport was
//! submitted under, and the row is abandoned only when **all** of it was read and
//! none reports that identifier. Anything short of that is refused, including the
//! cases that are not a refusal in any other sense: a list too long to read in
//! full, a task still being checked, and an adapter that cannot look.
//!
//! # What it ends, and what it does not
//!
//! It ends the *queue row*, not the passport: the passport stays published, and
//! the rollup counts it as `abandoned` so it is not read as still owed. Publishing
//! the passport again queues it afresh, which is the only way back.

use dpp_domain::{
    error::DppError,
    passport::PassportId,
    ports::registry_sync::{RegistrationRequest, SubmissionLookup},
};
use dpp_types::{
    RegistrySyncRow, RegistrySyncStatus, audit::PassportAuditEntry, auth::AuthContext,
};

use super::PassportService;

/// The audit action recording that a person gave up on a registration.
pub const REGISTRY_ABANDONED: &str = "registry_abandoned";

/// A registration abandoned, or found to be abandoned already.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Abandoned {
    /// `true` when the row was already abandoned: a retry of a request whose answer
    /// was lost. Nothing was read from the registry and nothing was written.
    pub already: bool,
}

/// Why a registration was not abandoned.
#[derive(Debug)]
pub enum AbandonError {
    /// This node has no registry queues, so there is no row to end.
    NotConfigured,
    /// The passport has no registry row: it was never published.
    NoRegistration,
    /// The row is not `pending`. A `submitted` row is one the registry holds, and a
    /// ruled-on one needs nothing.
    NotAbandonable(RegistrySyncStatus),
    /// The row has not been tried yet, or is due now, so the drain is about to try
    /// it or is trying it. Abandoning would race the attempt.
    DueForAnAttempt,
    /// The row's frozen payload is missing or unreadable, so there is nothing to
    /// look the registry up by.
    CannotSayWhatWasSubmitted,
    /// The registry holds a submission for this passport's identifier. Carries the
    /// lookup, which names the handle or the candidates.
    RegistryHoldsIt(SubmissionLookup),
    /// The registry could not be shown to hold nothing: part of its list was not
    /// read, a task is still being checked, or the adapter cannot look.
    NotShownAbsent(SubmissionLookup),
    /// The registry could not be read.
    Registry(DppError),
    /// The row could not be read or written.
    Storage(DppError),
}

/// What the row says about abandoning it, before and after a write that may have
/// lost a race.
enum RowState {
    /// It is abandoned already.
    Done,
    /// Nothing stands in the way of the registry check.
    Open,
    /// Something does.
    Refused(AbandonError),
}

fn state_of(row: &RegistrySyncRow, now: chrono::DateTime<chrono::Utc>) -> RowState {
    match row.status {
        RegistrySyncStatus::Abandoned => RowState::Done,
        RegistrySyncStatus::Pending => {
            if row.attempts < 1 || row.next_attempt_at <= now {
                RowState::Refused(AbandonError::DueForAnAttempt)
            } else {
                RowState::Open
            }
        }
        other => RowState::Refused(AbandonError::NotAbandonable(other)),
    }
}

impl PassportService {
    /// Give up on this passport's registration, once the registry has been shown to
    /// hold no submission for it.
    ///
    /// Idempotent: a row that is already abandoned answers as though it had just
    /// been, without asking the registry or writing the trail again, so a retry of
    /// a request whose answer was lost does not fail on its own success.
    ///
    /// # Errors
    /// See [`AbandonError`].
    pub async fn abandon_registration(
        &self,
        id: PassportId,
        reason: &str,
        auth: &AuthContext,
    ) -> Result<Abandoned, AbandonError> {
        let outbox = self
            .registry_outbox
            .as_ref()
            .ok_or(AbandonError::NotConfigured)?;

        let row = outbox
            .pending_for(id)
            .await
            .map_err(AbandonError::Storage)?
            .ok_or(AbandonError::NoRegistration)?;
        match state_of(&row, chrono::Utc::now()) {
            RowState::Done => return Ok(Abandoned { already: true }),
            RowState::Refused(why) => return Err(why),
            RowState::Open => {}
        }

        let request: RegistrationRequest = row
            .payload
            .clone()
            .and_then(|payload| serde_json::from_value(payload).ok())
            .ok_or(AbandonError::CannotSayWhatWasSubmitted)?;

        // The check that makes this safe. All of the registry's list was read and
        // none of it reports the identifier: only then is "the registry has
        // nothing" a fact and not a hope.
        match self
            .registry_sync
            .find_submission(&request)
            .await
            .map_err(AbandonError::Registry)?
        {
            SubmissionLookup::NotFound { exhaustive: true } => {}
            held @ (SubmissionLookup::Found { .. } | SubmissionLookup::Ambiguous { .. }) => {
                return Err(AbandonError::RegistryHoldsIt(held));
            }
            // Not found in part of the list, a task still being checked, an adapter
            // that cannot look, and anything the lookup grows later: none of them
            // shows the registry to hold nothing.
            other => return Err(AbandonError::NotShownAbsent(other)),
        }

        let message = format!("abandoned by {}: {reason}", auth.user_id);
        let took = outbox
            .abandon(id, message)
            .await
            .map_err(AbandonError::Storage)?;
        if !took {
            // The row moved between the read and the write: the drain tried it, or
            // another request ended it. Say what it is now, which may be this very
            // outcome, reached by a concurrent request.
            let now = outbox
                .pending_for(id)
                .await
                .map_err(AbandonError::Storage)?
                .ok_or(AbandonError::NoRegistration)?;
            return match state_of(&now, chrono::Utc::now()) {
                RowState::Done => Ok(Abandoned { already: true }),
                RowState::Refused(why) => Err(why),
                // Open, and yet the write took nothing: the row is not in the state
                // the statement requires. Not something to retry into.
                RowState::Open => Err(AbandonError::DueForAnAttempt),
            };
        }

        // The trail is the only account of a write that ends an obligation on a
        // person's word: who, why, and what the row had been saying.
        let entry = PassportAuditEntry::new(
            &id.to_string(),
            REGISTRY_ABANDONED,
            &auth.user_id,
            None,
            None,
        )
        .with_metadata(serde_json::json!({
            "reason": reason,
            "attempts": row.attempts,
            "lastMessage": row.message,
            "registryCheck": "no submission reports this passport's unique product identifier; \
                              every task the registry listed was read",
        }));
        self.audit
            .append(entry)
            .await
            .map_err(AbandonError::Storage)?;

        tracing::warn!(
            passport_id = %id,
            actor = %auth.user_id,
            attempts = row.attempts,
            "a registry registration was abandoned by hand — the registry holds nothing for it \
             and the node will no longer try"
        );
        Ok(Abandoned { already: false })
    }
}
