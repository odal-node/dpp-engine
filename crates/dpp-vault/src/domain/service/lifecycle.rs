//! `suspend` and `archive` — reversible and terminal passport status transitions.

use chrono::Utc;
use dpp_common::{event, event_codes};
use dpp_domain::{
    error::DppError,
    passport::{Passport, PassportId},
    status::PassportStatus,
};
use dpp_types::{
    audit::PassportAuditEntry, auth::AuthContext, registry_sync::RegistryStatusIntent,
};

use super::{PassportService, retention_years_for};

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

        let mut entry = PassportAuditEntry::new(
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
                .enqueue_status(id, RegistryStatusIntent::Suspended)
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

    /// Retire `predecessor` in favour of `successor`, linking the two.
    ///
    /// # The shape, and why it is a link rather than a create
    ///
    /// `PassportStatus::Superseded` and `Passport::supersedes_id` have been in
    /// the model, the database and the published API description since the
    /// schema was cut, and nothing ever produced either — the column was always
    /// `NULL` and no code path set the status. A documented lifecycle state that
    /// cannot be reached is a claim the API makes and cannot honour.
    ///
    /// Supersession is expressed as a link between two passports that already
    /// exist rather than a create-and-retire in one call. A successor is a
    /// passport in its own right: it has its own content, its own gates and its
    /// own publish. Folding its creation in here would mean a second, partial
    /// create path that could drift from the real one — and it is the drift
    /// between two implementations of the same act that this codebase keeps
    /// paying for.
    ///
    /// # What is required, and why
    ///
    /// Both must be **published**. A draft successor retiring a live passport
    /// would leave the product with no servable record at all, and a
    /// not-yet-published successor may still fail its own gates. A predecessor
    /// that is not published has nothing to retire.
    ///
    /// Terminal, per the state machine: a superseded passport cannot be
    /// superseded again, and the transition table refuses it rather than this
    /// method having to.
    ///
    /// # Errors
    /// [`DppError::NotFound`] if either id is unknown, [`DppError::Validation`]
    /// if they are the same record or the successor is not published, and
    /// [`DppError::InvalidTransition`] if the predecessor cannot be superseded
    /// from its current state.
    pub async fn supersede(
        &self,
        predecessor_id: PassportId,
        successor_id: PassportId,
        auth: &AuthContext,
    ) -> Result<Passport, DppError> {
        if predecessor_id == successor_id {
            return Err(DppError::Validation(
                "a passport cannot supersede itself".into(),
            ));
        }

        let predecessor = self.find_by_id(predecessor_id).await?;
        let successor = self.find_by_id(successor_id).await?;

        if successor.status != PassportStatus::Published {
            return Err(DppError::Validation(
                "the successor must be published before it can replace another passport".into(),
            ));
        }
        if !predecessor
            .status
            .can_transition_to(&PassportStatus::Superseded)
        {
            return Err(DppError::InvalidTransition {
                current: predecessor.status.to_string(),
                required: PassportStatus::Superseded.to_string(),
            });
        }

        // The link is not written here — it is *checked*. `supersedesId` is a
        // protected field, set by the write that creates the whole record and
        // never by a field patch, so the successor declares it at create time
        // and this route confirms the two agree before retiring anything.
        //
        // That ordering is the safer one anyway. Writing the link here and then
        // the status would leave, on a failure between them, a retired passport
        // with nothing pointing at its replacement — the state a reader cannot
        // recover from. Requiring the link to exist first makes that
        // unreachable.
        if successor.supersedes_id != Some(predecessor_id) {
            return Err(DppError::Validation(
                "the successor does not declare that it supersedes this passport; \
                 create it with `supersedesId` set to this passport's id"
                    .into(),
            ));
        }

        let prev_status = predecessor.status.to_string();
        let updated = self
            .repo
            .update_status(predecessor_id, PassportStatus::Superseded)
            .await?;

        self.audit
            .append(PassportAuditEntry::new(
                &updated.id.to_string(),
                "superseded",
                &auth.user_id,
                Some(&prev_status),
                Some(&PassportStatus::Superseded.to_string()),
            ))
            .await?;

        self.emit(
            event::subjects::PASSPORT_SUPERSEDED,
            serde_json::json!({
                "passportId": updated.id.to_string(),
                "status": "superseded",
                "previousStatus": prev_status,
                "supersededBy": successor_id.0.to_string(),
            }),
        )
        .await;

        // A superseded passport keeps serving publicly, like an archived or
        // deactivated one — products made under the old specification are still
        // in the field carrying carriers that resolve to it. The reconcile is
        // still needed: the stored snapshot has to be refreshed to carry the new
        // status rather than the old one.
        self.enqueue_snapshot_reconcile(updated.id).await;

        Ok(updated)
    }

    /// Permanently archive a passport after retention expiry.
    ///
    /// Blocked by the ESPR retention guard: if `retention_locked` is set and the
    /// product group's minimum retention period has not yet elapsed from `published_at`,
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
            // Same resolver publish uses, so the guard and the sealed deadline
            // agree by construction.
            let retention_years = i64::from(retention_years_for(&passport.product_group));
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

        let entry = PassportAuditEntry::new(
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
                .enqueue_status(id, RegistryStatusIntent::Deactivated)
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
