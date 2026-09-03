//! The transfer-of-responsibility lifecycle — `initiate`, `accept`, `reject`
//! and `cancel` — persisted as a `TransferChain`.

use chrono::Utc;
use dpp_common::{event, event_codes};
use dpp_domain::{
    error::DppError,
    passport::PassportId,
    status::PassportStatus,
    transfer::{
        ResponsibleOperator, TransferChain, TransferError, TransferReason, TransferRecord,
        TransferStatus,
    },
};
use dpp_types::{audit::PassportAuditEntry, auth::AuthContext};
use uuid::Uuid;

use super::PassportService;

impl PassportService {
    /// Initiate a transfer of responsibility: the outgoing operator signs
    /// a `TransferRecord` over its canonical `signing_payload`, appended to the
    /// passport's `TransferChain` as a pending handover awaiting acceptance.
    ///
    /// Single-node/managed mode: this node signs on behalf of the outgoing
    /// operator via `IdentityPort`, verifiable against the node's DID. Only
    /// `Published` passports transfer.
    pub async fn initiate_transfer(
        &self,
        id: PassportId,
        from_operator: ResponsibleOperator,
        to_operator: ResponsibleOperator,
        reason: TransferReason,
        notes: Option<String>,
        auth: &AuthContext,
    ) -> Result<TransferRecord, DppError> {
        let passport = self.find_by_id(id).await?;
        if passport.status != PassportStatus::Published {
            return Err(DppError::InvalidTransition {
                current: passport.status.to_string(),
                required: PassportStatus::Published.to_string(),
            });
        }
        let store = self
            .transfer_store
            .as_ref()
            .ok_or_else(|| DppError::Internal("transfer store not configured".into()))?;

        let mut chain = store
            .get_chain(id)
            .await?
            .unwrap_or_else(|| TransferChain::new(id, from_operator.clone()));

        let mut record = TransferRecord {
            transfer_id: Uuid::now_v7(),
            passport_id: id,
            from_operator,
            to_operator,
            reason,
            from_signature: None,
            node_acceptance_attestation: None,
            initiated_at: Utc::now(),
            completed_at: None,
            rejected_at: None,
            cancelled_at: None,
            notes,
        };
        // The outgoing operator signs the canonical handover terms.
        let payload = record.signing_payload();
        record.from_signature = Some(self.identity.sign_passport(id, &payload).await?.jws);

        chain
            .initiate_transfer(record.clone())
            .map_err(|e| DppError::Validation(e.to_string().into()))?;
        store.save_chain(&chain).await?;

        let entry =
            PassportAuditEntry::new(&id.to_string(), "transferred", &auth.user_id, None, None)
                .with_metadata(serde_json::json!({
                    "event": "transfer.initiated",
                    "transferId": record.transfer_id,
                    "toOperator": record.to_operator.did,
                }));
        self.audit.append(entry).await?;

        self.emit(
            event::subjects::PASSPORT_TRANSFERRED,
            serde_json::json!({
                "passportId": id.to_string(),
                "phase": "initiated",
                "transferId": record.transfer_id.to_string(),
                "toOperator": record.to_operator.did,
            }),
        )
        .await;

        Ok(record)
    }

    /// Accept a pending transfer: verify the outgoing operator's signature,
    /// countersign as the incoming operator, and complete the handover. The
    /// incoming operator becomes the current responsible operator on the chain.
    pub async fn accept_transfer(
        &self,
        id: PassportId,
        auth: &AuthContext,
    ) -> Result<TransferRecord, DppError> {
        let store = self
            .transfer_store
            .as_ref()
            .ok_or_else(|| DppError::Internal("transfer store not configured".into()))?;
        let mut chain = store
            .get_chain(id)
            .await?
            .ok_or_else(|| DppError::NotFound(format!("no transfer chain for {id}")))?;

        let idx = chain
            .transfers
            .iter()
            .position(|t| t.status() == TransferStatus::Initiated)
            .ok_or_else(|| DppError::Validation("no pending transfer to accept".into()))?;

        let payload = chain.transfers[idx].signing_payload();
        let from_sig = chain.transfers[idx]
            .from_signature
            .clone()
            .ok_or_else(|| DppError::Validation("pending transfer has no from-signature".into()))?;

        // Fail-closed: the outgoing signature must verify before we countersign.
        if !self.identity.verify_signature(&from_sig, &payload).await? {
            tracing::warn!(
                code = event_codes::TRANSFER_SIGNATURE_INVALID,
                passport_id = %id,
                transfer_id = %chain.transfers[idx].transfer_id,
                "accept_transfer rejected — outgoing signature failed verification"
            );
            return Err(DppError::Validation(
                "transfer from-signature failed verification".into(),
            ));
        }

        // Signed over `acceptance_payload`, not over `payload` (the initiation
        // bytes the outgoing operator already signed). Re-signing those made
        // this attestation byte-identical to `from_signature` whenever the node
        // key and the from-operator key are the same one — which is every
        // single-operator node — so the "acceptance" could be produced by
        // copying a field that predates the acceptance.
        let attestation = crate::domain::verify::acceptance_payload(&chain.transfers[idx]);
        chain.transfers[idx].node_acceptance_attestation =
            Some(self.identity.sign_passport(id, &attestation).await?.jws);
        chain.transfers[idx]
            .complete()
            .map_err(|e| DppError::Validation(e.to_string().into()))?;
        let record = chain.transfers[idx].clone();

        // Persist the completed handover and enqueue the registry notification.
        // With the outbox present these commit atomically, so an accepted
        // transfer can never exist without a queued notification — the same
        // guarantee publish gets for registration. Without one (in-memory test
        // doubles), fall back to a plain chain write.
        match &self.transfer_outbox {
            Some(outbox) => {
                let payload = serde_json::to_value(&record)
                    .map_err(|e| DppError::Serialisation(e.to_string()))?;
                outbox
                    .commit_accept(&chain, record.transfer_id, payload)
                    .await?;
            }
            None => store.save_chain(&chain).await?,
        }

        let entry =
            PassportAuditEntry::new(&id.to_string(), "transferred", &auth.user_id, None, None)
                .with_metadata(serde_json::json!({
                    "event": "transfer.accepted",
                    "transferId": record.transfer_id,
                    "toOperator": record.to_operator.did,
                }));
        self.audit.append(entry).await?;

        self.emit(
            event::subjects::PASSPORT_TRANSFERRED,
            serde_json::json!({
                "passportId": id.to_string(),
                "phase": "accepted",
                "transferId": record.transfer_id.to_string(),
                "toOperator": record.to_operator.did,
            }),
        )
        .await;

        Ok(record)
    }

    /// End a pending transfer as **refused**.
    ///
    /// Terminal — the record can never complete afterwards, and the chain is
    /// free to carry a new transfer.
    ///
    /// The name records the outcome, not the caller. A node serves one operator
    /// and accepts only that operator's credentials, so the incoming operator
    /// cannot reach this route; both terminations are made by this node's
    /// operator. See [`Self::terminate_pending_transfer`].
    pub async fn reject_transfer(
        &self,
        id: PassportId,
        auth: &AuthContext,
    ) -> Result<TransferRecord, DppError> {
        self.terminate_pending_transfer(id, auth, Termination::Rejected)
            .await
    }

    /// End a pending transfer as **withdrawn**, before it completes.
    ///
    /// Terminal, like [`Self::reject_transfer`], and the same caller — the two
    /// differ in the outcome written to the record, not in who writes it.
    ///
    /// Core permits a cancel from `Accepted` as well as `Initiated`, one state
    /// more than a reject. That breadth is unreachable here: `accept_transfer`
    /// sets the attestation and calls `complete()` before any save, so no
    /// *stored* record is ever in `Accepted`. The wider rule is core's; this
    /// method does not depend on it.
    pub async fn cancel_transfer(
        &self,
        id: PassportId,
        auth: &AuthContext,
    ) -> Result<TransferRecord, DppError> {
        self.terminate_pending_transfer(id, auth, Termination::Cancelled)
            .await
    }

    /// The shared body of [`Self::reject_transfer`] and
    /// [`Self::cancel_transfer`] — the two differ only in which core method
    /// they call and what they are called in the audit trail.
    ///
    /// # Why this exists at all
    ///
    /// `TransferChain::initiate_transfer` refuses a new handover while any
    /// record is `Initiated` or `Accepted`. Before these two paths were wired,
    /// nothing could move a record out of `Initiated`: a handover the
    /// counterparty never accepted blocked **every** future transfer on that
    /// passport, permanently, with no route able to clear it. `TransferRecord`
    /// has carried `reject`/`cancel` all along; only the way in was missing.
    ///
    /// # Why the selection predicate is what it is
    ///
    /// It matches `initiate_transfer`'s own `has_pending` check exactly —
    /// whatever blocks a new transfer is precisely what these two clear. Legality
    /// is not decided here: the record's own state machine refuses a `reject`
    /// from anything but `Initiated`, and a `cancel` from anything terminal, so
    /// this selects a candidate and lets core reject it.
    ///
    /// The `Accepted` arm is defensive rather than reachable. `accept_transfer`
    /// sets the attestation and calls `complete()` before any save, so no stored
    /// record is ever in that state. It is matched anyway because the predicate
    /// is the `has_pending` one: should acceptance ever become a separate step,
    /// what blocks a new transfer must remain exactly what these clear, and a
    /// predicate that had drifted narrower would silently strand the record.
    ///
    /// # Who calls this
    ///
    /// Both terminations come from this node's operator. A node serves one
    /// operator and accepts only that operator's credentials, so the incoming
    /// counterparty cannot reach either route. `Rejected` and `Cancelled` record
    /// **what happened to the handover**, not which party ended it — nothing
    /// here establishes that, and the audit metadata below should not be read as
    /// if it did.
    ///
    /// # Why no registry notification is enqueued
    ///
    /// A notification is queued when a handover **completes**, not when one is
    /// initiated. A transfer ending here never completed, so the registry was
    /// never told it was coming and is owed nothing now. A plain chain write is
    /// the whole of the persistence.
    async fn terminate_pending_transfer(
        &self,
        id: PassportId,
        auth: &AuthContext,
        how: Termination,
    ) -> Result<TransferRecord, DppError> {
        let store = self
            .transfer_store
            .as_ref()
            .ok_or_else(|| DppError::Internal("transfer store not configured".into()))?;
        let mut chain = store
            .get_chain(id)
            .await?
            .ok_or_else(|| DppError::NotFound(format!("no transfer chain for {id}")))?;

        let idx = chain
            .transfers
            .iter()
            .position(|t| {
                matches!(
                    t.status(),
                    TransferStatus::Initiated | TransferStatus::Accepted
                )
            })
            .ok_or_else(|| {
                DppError::Validation(format!("no pending transfer to {}", how.verb()).into())
            })?;

        how.apply(&mut chain.transfers[idx])
            .map_err(|e| DppError::Validation(e.to_string().into()))?;
        let record = chain.transfers[idx].clone();
        store.save_chain(&chain).await?;

        let entry =
            PassportAuditEntry::new(&id.to_string(), "transferred", &auth.user_id, None, None)
                .with_metadata(serde_json::json!({
                    "event": format!("transfer.{}", how.phase()),
                    "transferId": record.transfer_id,
                    "toOperator": record.to_operator.did,
                }));
        self.audit.append(entry).await?;

        self.emit(
            event::subjects::PASSPORT_TRANSFERRED,
            serde_json::json!({
                "passportId": id.to_string(),
                "phase": how.phase(),
                "transferId": record.transfer_id.to_string(),
                "toOperator": record.to_operator.did,
            }),
        )
        .await;

        Ok(record)
    }
}

/// How a pending handover was ended.
///
/// Both outcomes are terminal, both free the chain for a new transfer, and both
/// are written by this node's operator. They differ in the outcome recorded and
/// in the states core permits them from — not in who ended it.
#[derive(Clone, Copy)]
enum Termination {
    /// The counterparty declined. Core permits this only from `Initiated`.
    Rejected,
    /// The handover was withdrawn. Core permits this from `Initiated` or
    /// `Accepted`, though no stored record reaches `Accepted` — see
    /// [`PassportService::cancel_transfer`].
    Cancelled,
}

impl Termination {
    /// The past-tense form, used in the audit event name and the emitted phase.
    fn phase(self) -> &'static str {
        match self {
            Self::Rejected => "rejected",
            Self::Cancelled => "cancelled",
        }
    }

    /// The imperative form, used in the "no pending transfer to …" message.
    fn verb(self) -> &'static str {
        match self {
            Self::Rejected => "reject",
            Self::Cancelled => "cancel",
        }
    }

    /// Apply the outcome, letting the record's own state machine refuse it.
    fn apply(self, record: &mut TransferRecord) -> Result<(), TransferError> {
        match self {
            Self::Rejected => record.reject(),
            Self::Cancelled => record.cancel(),
        }
    }
}
