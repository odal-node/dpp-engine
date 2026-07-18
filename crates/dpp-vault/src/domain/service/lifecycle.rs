//! `suspend` and `archive` — reversible and terminal passport status transitions.

use chrono::Utc;
use dpp_common::{event, event_codes};
use dpp_domain::domain::{
    error::DppError,
    passport::{Passport, PassportId},
    status::PassportStatus,
};
use dpp_types::{audit::AuditEntry, auth::AuthContext, registry_sync::RegistrySyncStatus};

use super::PassportService;

impl PassportService {
    /// Suspend a published passport.
    ///
    /// Reversible — a suspended passport can be re-published. Appends an audit
    /// entry with the optional `reason` and emits `dpp.passport.suspended`.
    #[tracing::instrument(skip(self, reason), fields(passport_id = %id))]
    pub async fn suspend(
        &self,
        id: PassportId,
        auth: &AuthContext,
        reason: Option<String>,
    ) -> Result<Passport, DppError> {
        let passport = self.find_by_id(id).await?;

        if !passport
            .status
            .can_transition_to(&PassportStatus::Suspended)
        {
            return Err(DppError::InvalidTransition {
                current: passport.status.to_string(),
                required: PassportStatus::Suspended.to_string(),
            });
        }

        let updated = self
            .repo
            .update_status(id, PassportStatus::Suspended)
            .await?;

        let mut entry = AuditEntry::new(
            &updated.id.to_string(),
            "suspended",
            &auth.user_id,
            Some(&PassportStatus::Published.to_string()),
            Some(&PassportStatus::Suspended.to_string()),
        );
        if let Some(r) = reason {
            entry = entry.with_metadata(serde_json::json!({"reason": r}));
        }
        self.audit.append(entry).await?;

        // Record the suspended status intent in the registry outbox (drained to
        // the EU registry once its status-push API exists). Non-fatal.
        if let Some(outbox) = &self.registry_outbox
            && let Err(e) = outbox
                .enqueue_status(id, RegistrySyncStatus::Suspended)
                .await
        {
            tracing::warn!(
                code = event_codes::REGISTRY_SYNC_FAILED,
                passport_id = %id,
                error = %e,
                "failed to enqueue suspended status to registry outbox (non-fatal)"
            );
        }

        self.emit(
            event::subjects::PASSPORT_SUSPENDED,
            serde_json::json!({
                "passportId": updated.id.to_string(),
                "status": "suspended",
            }),
        )
        .await;

        // Reconcile the continuity tier: a suspended passport must not keep
        // being served as `active` from the static tier (non-fatal).
        self.enqueue_snapshot_reconcile(updated.id).await;

        Ok(updated)
    }

    /// Permanently archive a passport after retention expiry.
    ///
    /// Blocked by the ESPR retention guard: if `retention_locked` is set and the
    /// sector's minimum retention period has not yet elapsed from `published_at`,
    /// returns `DppError::Validation`. Emits `dpp.passport.archived`.
    #[tracing::instrument(skip(self), fields(passport_id = %id))]
    pub async fn archive(&self, id: PassportId, auth: &AuthContext) -> Result<Passport, DppError> {
        let passport = self.find_by_id(id).await?;

        if !passport.status.can_transition_to(&PassportStatus::Archived) {
            return Err(DppError::InvalidTransition {
                current: passport.status.to_string(),
                required: PassportStatus::Archived.to_string(),
            });
        }

        // ── Retention guard ─────────────────────────────────────────────
        // EU ESPR requires that published DPPs remain accessible for the
        // period defined in the applicable delegated act.  Archiving before
        // the retention period expires is blocked.
        if passport.retention_locked
            && let Some(published_at) = passport.published_at
        {
            let retention_years = passport
                .sector_data
                .as_ref()
                .map(|sd| sd.sector().minimum_retention_years())
                .unwrap_or(10) as i64;
            let retention_end = published_at + chrono::Duration::days(365 * retention_years);
            if Utc::now() < retention_end {
                tracing::warn!(
                    code = event_codes::RETENTION_BLOCKED,
                    passport_id = %id,
                    retention_end = %retention_end.format("%Y-%m-%d"),
                    "archive blocked by retention policy"
                );
                return Err(DppError::Validation(
                    format!(
                        "retention policy forbids archiving before {}",
                        retention_end.format("%Y-%m-%d")
                    )
                    .into(),
                ));
            }
        }

        let prev_status = passport.status.to_string();
        let updated = self
            .repo
            .update_status(id, PassportStatus::Archived)
            .await?;

        let entry = AuditEntry::new(
            &updated.id.to_string(),
            "archived",
            &auth.user_id,
            Some(&prev_status),
            Some(&PassportStatus::Archived.to_string()),
        );
        self.audit.append(entry).await?;

        // Record the deactivated status intent in the registry outbox (drained
        // to the EU registry once its status-push API exists). Non-fatal.
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
            event::subjects::PASSPORT_ARCHIVED,
            serde_json::json!({
                "passportId": updated.id.to_string(),
                "status": "archived",
                "previousStatus": prev_status,
            }),
        )
        .await;

        // Reconcile the continuity tier — an archived passport leaves the
        // public tier (non-fatal).
        self.enqueue_snapshot_reconcile(updated.id).await;

        Ok(updated)
    }
}
