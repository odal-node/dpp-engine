//! `declare_eol` — end-of-life declaration (recycled, destroyed, exported, or
//! lost), transitioning a passport to the terminal `Deactivated` status.

use dpp_common::{event, event_codes};
use dpp_domain::domain::{
    eol::EolEvent,
    error::DppError,
    passport::{Passport, PassportId},
    status::PassportStatus,
};
use dpp_types::{audit::AuditEntry, auth::AuthContext, registry_sync::RegistrySyncStatus};

use super::PassportService;

impl PassportService {
    /// Declare a passport end-of-life: recycled, destroyed (with a
    /// derogation), exported, or lost. Transitions to `Deactivated` (terminal;
    /// the record is retained — the DPP outlives the product, EN 18221). The
    /// typed [`EolEvent`] is recorded in the hash-chained audit trail and
    /// a `deactivated` status intent is enqueued to the registry outbox.
    #[tracing::instrument(skip(self, eol), fields(passport_id = %id))]
    pub async fn declare_eol(
        &self,
        id: PassportId,
        eol: EolEvent,
        auth: &AuthContext,
    ) -> Result<Passport, DppError> {
        let passport = self.find_by_id(id).await?;

        if !passport
            .status
            .can_transition_to(&PassportStatus::Deactivated)
        {
            return Err(DppError::InvalidTransition {
                current: passport.status.to_string(),
                required: PassportStatus::Deactivated.to_string(),
            });
        }

        let prev_status = passport.status.to_string();
        let updated = self
            .repo
            .update_status(id, PassportStatus::Deactivated)
            .await?;

        // The typed EOL reason rides in the audit entry's metadata — it becomes
        // part of the tamper-evident chain.
        let eol_meta =
            serde_json::to_value(&eol).map_err(|e| DppError::Serialisation(e.to_string()))?;
        let entry = AuditEntry::new(
            &updated.id.to_string(),
            "deactivated",
            auth,
            Some(&prev_status),
            Some(&PassportStatus::Deactivated.to_string()),
        )
        .with_metadata(eol_meta);
        self.audit.append(entry).await?;

        // Registry outbox: record the deactivated status intent (pushed to the
        // EU registry once its status API exists). Non-fatal.
        if let Some(outbox) = &self.registry_outbox
            && let Err(e) = outbox
                .enqueue_status(id, RegistrySyncStatus::Deactivated)
                .await
        {
            tracing::warn!(
                code = event_codes::REGISTRY_SYNC_FAILED,
                passport_id = %id,
                error = %e,
                "failed to enqueue deactivated status to registry outbox (non-fatal)"
            );
        }

        self.emit(
            event::subjects::PASSPORT_DEACTIVATED,
            serde_json::json!({
                "passportId": updated.id.to_string(),
                "status": "deactivated",
                "previousStatus": prev_status,
            }),
        )
        .await;

        Ok(updated)
    }
}
