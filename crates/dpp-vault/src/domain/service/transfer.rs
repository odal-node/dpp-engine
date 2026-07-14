//! `initiate_transfer` and `accept_transfer` — dual-signed transfer of
//! responsibility between operators, persisted as a `TransferChain`.

use chrono::Utc;
use dpp_common::{event, event_codes};
use dpp_domain::domain::{
    error::DppError,
    passport::PassportId,
    status::PassportStatus,
    transfer::{
        ResponsibleOperator, TransferChain, TransferReason, TransferRecord, TransferStatus,
    },
};
use dpp_types::{audit::AuditEntry, auth::AuthContext};
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
            to_signature: None,
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

        let entry = AuditEntry::new(&id.to_string(), "transferred", &auth.user_id, None, None)
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

        chain.transfers[idx].to_signature =
            Some(self.identity.sign_passport(id, &payload).await?.jws);
        chain.transfers[idx]
            .complete()
            .map_err(|e| DppError::Validation(e.to_string().into()))?;
        let record = chain.transfers[idx].clone();
        store.save_chain(&chain).await?;

        let entry = AuditEntry::new(&id.to_string(), "transferred", &auth.user_id, None, None)
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

        // Registry transfer notification is deferred (the registry's transfer API
        // is unpublished); the local chain is authoritative in the meantime.

        Ok(record)
    }
}
