//! `suspend`, `supersede` and `retire` — reversible and terminal passport
//! status transitions.
//!
//! `supersede` links a passport to an already-published replacement. It is the
//! sibling of [`super::amend`], not a duplicate of it: `amend` issues the
//! successor itself from a patch, so it cannot name one that already exists;
//! this names one and cannot create it. They share the transition and nothing
//! else, and the shared part lives in one place — `supersede_predecessor`.

use chrono::{DateTime, Utc};
use dpp_common::{event, event_codes};
use dpp_domain::{
    error::DppError,
    passport::{Passport, PassportId},
    status::PassportStatus,
};
use dpp_types::{
    audit::PassportAuditEntry,
    auth::AuthContext,
    registry_sync::RegistryStatusIntent,
    state_change::{PassportWrite, StateChange},
};

use super::{PassportService, retention_deadline, retention_years_for};

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

        let mut entry = PassportAuditEntry::new(
            &id.to_string(),
            "suspended",
            &auth.user_id,
            Some(&PassportStatus::Published.to_string()),
            Some(&PassportStatus::Suspended.to_string()),
        );
        if let Some(r) = reason {
            entry = entry.with_metadata(serde_json::json!({"reason": r}));
        }
        let event = Self::event(
            event::subjects::PASSPORT_SUSPENDED,
            serde_json::json!({
                "passportId": id.to_string(),
                "status": "suspended",
            }),
        );
        let updated = self
            .commit_passport_change(
                StateChange::new(entry)
                    .with_passport(PassportWrite::Status(id, PassportStatus::Suspended)),
                event,
            )
            .await?;

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

        // Reconcile the continuity tier: a suspended passport must not keep
        // being served as `active` from the static tier (non-fatal).
        self.enqueue_snapshot_reconcile(updated.id).await;

        Ok(updated)
    }

    /// Retire `predecessor_id` in favour of `successor_id`, linking the two.
    ///
    /// # Why this is not `amend`
    ///
    /// Both routes end in the same transition, and that is the whole of what
    /// they share. `amend` *issues* the successor: it clones the predecessor,
    /// applies a patch, runs the ordinary publish pipeline and hands back a
    /// record it created. It therefore cannot express retiring a passport whose
    /// replacement already exists — its successor is always freshly minted with
    /// a new id, so pointing it at an already-published passport would produce a
    /// *third* record and leave two live passports for one product.
    ///
    /// This route is the other act: the successor was created and published
    /// independently, on its own content and through its own gates, and is named
    /// here. `amend` explicitly declines one such case in its own comments —
    /// moving a passport to a newer schema version, which it refuses to do
    /// silently because disclosure classes are read from the schema version.
    /// That migration is only expressible as create-at-the-new-version and link,
    /// which is this.
    ///
    /// Everything downstream of the transition is
    /// [`PassportService::supersede_predecessor`], shared with `amend`, so both
    /// routes write one audit shape and emit one payload.
    ///
    /// # What is required, and why
    ///
    /// Both must be **published**. A draft successor retiring a live passport
    /// would leave the product with no servable record at all, and a
    /// not-yet-published successor may still fail its own gates. A predecessor
    /// that is not published has nothing to retire.
    ///
    /// The link is **checked, not written**. `supersedesId` is a protected
    /// field, set by the write that creates the whole record and never by a
    /// field patch, so the successor declares it at create time and this route
    /// confirms the two agree before retiring anything. That ordering is the
    /// safer one regardless: writing the link here and then the status would
    /// leave, on a failure between them, a retired passport with nothing
    /// pointing at its replacement — the one state a reader cannot recover from.
    ///
    /// Terminal, per the state machine: a superseded passport cannot be
    /// superseded again, and the transition table refuses it rather than this
    /// method having to.
    ///
    /// # Errors
    /// [`DppError::NotFound`] if either id is unknown, [`DppError::Validation`]
    /// if they are the same record, the successor is not published, or it does
    /// not declare the link, and [`DppError::InvalidTransition`] if the
    /// predecessor cannot be superseded from its current state.
    #[tracing::instrument(skip(self, reason), fields(passport_id = %predecessor_id, successor_id = %successor_id))]
    pub async fn supersede(
        &self,
        predecessor_id: PassportId,
        successor_id: PassportId,
        reason: Option<String>,
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

        // Asking the state machine rather than matching on the variant keeps
        // this in step with `can_transition_to` if the table ever widens, the
        // same way `amend` asks it.
        if !predecessor
            .status
            .can_transition_to(&PassportStatus::Superseded)
        {
            return Err(DppError::InvalidTransition {
                current: predecessor.status.to_string(),
                required: PassportStatus::Superseded.to_string(),
            });
        }

        if successor.supersedes_id != Some(predecessor_id) {
            return Err(DppError::Validation(
                "the successor does not declare that it supersedes this passport; \
                 create it with `supersedesId` set to this passport's id"
                    .into(),
            ));
        }

        self.supersede_predecessor(&predecessor, successor_id, reason, auth)
            .await
    }

    /// Permanently retire a passport after retention expiry.
    ///
    /// Blocked by the ESPR retention guard: if `retention_locked` is set and
    /// `retirement_deadline` has not passed, returns `DppError::Validation`.
    /// Emits `dpp.passport.retired`.
    #[tracing::instrument(skip(self), fields(passport_id = %id))]
    pub async fn retire(&self, id: PassportId, auth: &AuthContext) -> Result<Passport, DppError> {
        let passport = self.find_by_id(id).await?;

        if !passport.status.can_transition_to(&PassportStatus::Retired) {
            return Err(DppError::InvalidTransition {
                current: passport.status.to_string(),
                required: PassportStatus::Retired.to_string(),
            });
        }

        // ── Retention guard ─────────────────────────────────────────────
        // EU ESPR requires that published DPPs remain accessible for the
        // period defined in the applicable delegated act.  Retiring before
        // the retention period expires is blocked.
        if passport.retention_locked
            && let Some(published_at) = passport.published_at
        {
            let retention_end = retirement_deadline(
                passport.retention_until,
                published_at,
                retention_years_for(&passport.product_group),
            );
            if Utc::now() < retention_end {
                tracing::warn!(
                    code = event_codes::RETENTION_BLOCKED,
                    passport_id = %id,
                    retention_end = %retention_end.format("%Y-%m-%d"),
                    "retirement blocked by retention policy"
                );
                return Err(DppError::Validation(
                    format!(
                        "retention policy forbids retiring before {}",
                        retention_end.format("%Y-%m-%d")
                    )
                    .into(),
                ));
            }
        }

        let prev_status = passport.status.to_string();
        let entry = PassportAuditEntry::new(
            &id.to_string(),
            "retired",
            &auth.user_id,
            Some(&prev_status),
            Some(&PassportStatus::Retired.to_string()),
        );
        let event = Self::event(
            event::subjects::PASSPORT_RETIRED,
            serde_json::json!({
                "passportId": id.to_string(),
                "status": "retired",
                "previousStatus": prev_status,
            }),
        );
        let updated = self
            .commit_passport_change(
                StateChange::new(entry)
                    .with_passport(PassportWrite::Status(id, PassportStatus::Retired)),
                event,
            )
            .await?;

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

        // Reconcile the continuity tier — a retired passport keeps serving,
        // so its snapshot is refreshed rather than withdrawn (non-fatal).
        self.enqueue_snapshot_reconcile(updated.id).await;

        Ok(updated)
    }
}

/// The deadline `retire` enforces: the later of the one sealed into the
/// passport at publish (`retention_until`) and the one the product group's
/// current period gives from `published_at`.
///
/// The two agree until the catalog changes a product group's period in a later
/// `dpp-core`. Then neither alone is right. The sealed one is the obligation
/// recorded when the passport was published, and a shorter period later must
/// not cut it short. The current one is what the law asks of the product group
/// now, and a longer period applies to passports already published. A passport
/// published before `retention_until` existed carries none and gets the
/// current period.
fn retirement_deadline(
    sealed: Option<DateTime<Utc>>,
    published_at: DateTime<Utc>,
    current_years: u32,
) -> DateTime<Utc> {
    let current = retention_deadline(published_at, current_years);
    sealed.map_or(current, |sealed| sealed.max(current))
}

#[cfg(test)]
mod retirement_deadline_tests {
    use chrono::{DateTime, TimeZone, Utc};

    use super::retirement_deadline;
    use crate::domain::service::retention_deadline;

    fn published() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 3, 1, 9, 30, 0).unwrap()
    }

    #[test]
    fn a_period_that_shortens_does_not_shorten_the_guard() {
        // Published under a 15-year period; the catalog now says 10.
        let sealed = retention_deadline(published(), 15);
        assert_eq!(retirement_deadline(Some(sealed), published(), 10), sealed);
    }

    #[test]
    fn a_period_that_lengthens_lengthens_the_guard() {
        // Published under a 10-year period; the catalog now says 15.
        let sealed = retention_deadline(published(), 10);
        assert_eq!(
            retirement_deadline(Some(sealed), published(), 15),
            retention_deadline(published(), 15)
        );
    }

    #[test]
    fn a_stricter_deadline_set_before_publish_holds() {
        // An operator may seal a longer deadline than the catalog's before
        // publishing, for a delegated act stricter than the catalog knows.
        let sealed = Utc.with_ymd_and_hms(2050, 1, 1, 0, 0, 0).unwrap();
        assert_eq!(retirement_deadline(Some(sealed), published(), 10), sealed);
    }

    #[test]
    fn a_passport_without_a_sealed_deadline_gets_the_current_period() {
        assert_eq!(
            retirement_deadline(None, published(), 10),
            retention_deadline(published(), 10)
        );
    }
}
