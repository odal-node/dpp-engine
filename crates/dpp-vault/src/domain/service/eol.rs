//! `declare_eol` — end-of-life declaration (recycled, destroyed, exported, or
//! lost), transitioning a passport to the terminal `Deactivated` status.

use chrono::Utc;
use dpp_common::event;
use dpp_domain::{
    CommodityCode, DiscardReason, FieldError, ValidationErrors,
    eol::{DeactivationReason, Derogation, EolEvent},
    error::DppError,
    passport::{Passport, PassportId},
    status::PassportStatus,
    unsold_goods::{EnterpriseSize, destruction_ban_applies},
};
use dpp_types::{
    audit::PassportAuditEntry,
    auth::AuthContext,
    operator::STANDALONE_OPERATOR_ID,
    registry_sync::RegistryStatusIntent,
    state_change::{PassportWrite, StateChange},
};
use uuid::Uuid;

use super::PassportService;

impl PassportService {
    /// Declare a passport end-of-life: recycled, destroyed (with a
    /// derogation), exported, or lost. Transitions to `Deactivated` (terminal;
    /// the record is retained — the DPP outlives the product, EN 18221). The
    /// typed [`EolEvent`] is recorded in the hash-chained audit trail and
    /// a `deactivated` status intent is enqueued to the registry outbox.
    #[tracing::instrument(skip(self, eol), fields(passport_id = %id))]
    ///
    /// `unsold` says whether the product was an unsold consumer product, which a
    /// passport does not record. Together with the operator's enterprise size it
    /// decides whether ESPR Art. 25(1) reaches a destruction, and so whether the
    /// destruction must cite a derogation.
    ///
    /// `discard_record` is the record that documents the destruction, already
    /// checked by the caller against the reason. The join to it is written in the
    /// same transaction as the status, and the citation is recorded in the audit
    /// entry's metadata.
    pub async fn declare_eol(
        &self,
        id: PassportId,
        eol: EolEvent,
        unsold: bool,
        discard_record: Option<Uuid>,
        auth: &AuthContext,
    ) -> Result<Passport, DppError> {
        // Before the passport is read, so a refused declaration costs nothing and
        // changes nothing: `Deactivated` is terminal.
        if let Some(problem) = legacy_derogation_problem(&eol.reason) {
            return Err(DppError::Validation(ValidationErrors {
                errors: vec![problem],
            }));
        }

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

        if matches!(eol.reason, DeactivationReason::Destroyed { .. }) {
            let ban_applies = destruction_ban_applies(
                unsold,
                &declared_codes(&passport),
                self.enterprise_size().await?,
                Utc::now().date_naive(),
            );
            if eol.missing_derogation(ban_applies) {
                return Err(DppError::Validation(ValidationErrors {
                    errors: vec![missing_derogation_problem()],
                }));
            }
        }

        let prev_status = passport.status.to_string();

        // The typed EOL reason rides in the audit entry's metadata — it becomes
        // part of the tamper-evident chain — and so does the discard record that
        // documents the destruction, when there is one.
        let mut eol_meta =
            serde_json::to_value(&eol).map_err(|e| DppError::Serialisation(e.to_string()))?;
        if let Some(record) = discard_record
            && let Some(object) = eol_meta.as_object_mut()
        {
            object.insert("discardRecordId".to_owned(), serde_json::json!(record));
        }
        let entry = PassportAuditEntry::new(
            &id.to_string(),
            "deactivated",
            &auth.user_id,
            Some(&prev_status),
            Some(&PassportStatus::Deactivated.to_string()),
        )
        .with_metadata(eol_meta);
        let event = Self::event(
            event::subjects::PASSPORT_DEACTIVATED,
            serde_json::json!({
                "passportId": id.to_string(),
                "status": "deactivated",
                "previousStatus": prev_status,
            }),
        );
        // The status, the audit entry, the outbox and the discard join commit in
        // one transaction: the join is written with the destruction or not at all.
        let mut change = StateChange::new(entry)
            .with_passport(PassportWrite::Status(id, PassportStatus::Deactivated));
        if let Some(record) = discard_record {
            change = change.with_discard_record_link(record, id);
        }
        let updated = self
            .commit_passport_change(
                self.owing_registry_status(change, RegistryStatusIntent::Deactivated),
                event,
            )
            .await?;

        // Reconcile the continuity tier: the live public read serves only
        // `Published`, so a deactivated passport must stop being served from the
        // static tier too — otherwise it keeps answering `published` under a
        // valid signature for the rest of the bucket's life. The drain derives
        // the retire from the passport's status (non-fatal).
        self.enqueue_snapshot_reconcile(updated.id).await;

        Ok(updated)
    }
}

impl PassportService {
    /// The operator's enterprise size, from operator configuration. The one reader
    /// of it: the destruction ban here and the discard evidence route both read it
    /// through this function, so they cannot disagree about the default.
    ///
    /// An operator that has stated none is treated as large, so a destruction the
    /// ban would reach is asked for a derogation rather than let through on a size
    /// nobody declared.
    pub async fn enterprise_size(&self) -> Result<EnterpriseSize, DppError> {
        let declared = match &self.registry_reader {
            Some(reader) => reader
                .get(STANDALONE_OPERATOR_ID)
                .await?
                .and_then(|config| config.enterprise_size),
            None => None,
        };
        Ok(declared.unwrap_or(EnterpriseSize::Large))
    }
}

/// The passport's commodity code, where it reads as one. A declared code that
/// does not parse cannot be placed in Annex VII, so it reaches no ban.
fn declared_codes(passport: &Passport) -> Vec<CommodityCode> {
    passport
        .commodity_code
        .iter()
        .filter_map(|code| code.validated().ok())
        .collect()
}

/// The points of Art. 2 of Commission Delegated Regulation (EU) 2026/296, as a
/// request names them. Core carries the list as [`DiscardReason`], so the names
/// are core's and nothing here writes a point out again.
fn derogation_points() -> String {
    DiscardReason::ALL
        .iter()
        .filter_map(|point| {
            let wire = serde_json::to_value(point).ok()?;
            Some(format!(
                "{} (point {})",
                wire.as_str()?,
                point.article_2_point()
            ))
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// A new destruction that cites its derogation as free text, `{"category": ...}`.
///
/// Core reads that form only as the history of an event written before the closed
/// list was modelled, and never counts it as a derogation, so a new event written
/// with one would record a lawful basis nothing can check. A point is cited by its
/// name alone.
fn legacy_derogation_problem(reason: &DeactivationReason) -> Option<FieldError> {
    let DeactivationReason::Destroyed {
        derogation: Some(Derogation::Legacy(_)),
    } = reason
    else {
        return None;
    };
    Some(FieldError {
        field: "/reason/derogation".to_owned(),
        message: format!(
            "A destruction cites a point of Art. 2 of Commission Delegated Regulation (EU) \
             2026/296 by its name, not as free text. The points are: {}.",
            derogation_points()
        ),
    })
}

/// The refusal for a destruction the ESPR Art. 25(1) ban reaches that cites no
/// point.
fn missing_derogation_problem() -> FieldError {
    FieldError {
        field: "/reason/derogation".to_owned(),
        message: format!(
            "ESPR Art. 25(1) bars destroying this product: it is an unsold product of Annex VII, \
             the ban has applied since 19 July 2026, and the operator is not exempt. Cite the \
             derogation the destruction relies on, a point of Art. 2 of Commission Delegated \
             Regulation (EU) 2026/296: {}.",
            derogation_points()
        ),
    }
}

#[cfg(test)]
mod tests {
    use dpp_domain::DiscardReason;
    use dpp_domain::eol::{DeactivationReason, Derogation};
    use serde_json::json;

    use super::{legacy_derogation_problem, missing_derogation_problem};

    fn destroyed(derogation: Option<Derogation>) -> DeactivationReason {
        DeactivationReason::Destroyed { derogation }
    }

    /// A request cites a point by its name alone, and every point of the
    /// delegated act's Art. 2 reads as one. The names come from core's own list,
    /// so a point added there is accepted here without anything being edited.
    #[test]
    fn every_point_of_the_delegated_act_is_cited_by_its_name() {
        for point in DiscardReason::ALL {
            let name = serde_json::to_value(point).expect("a reason serialises");
            let derogation: Derogation =
                serde_json::from_value(name.clone()).expect("a point's name reads back");
            assert_eq!(derogation, Derogation::Point(*point), "{name}");
            assert_eq!(
                legacy_derogation_problem(&destroyed(Some(derogation))),
                None
            );
        }
    }

    /// The old free-text form still reads, so a stored event keeps its history,
    /// but a new destruction written with it is refused, and the refusal lists
    /// the points. `odal passport eol --reason destroyed --derogation
    /// bogus-category` once exited 0 and left the passport terminal with that
    /// string recorded as its lawful basis.
    #[test]
    fn a_free_text_citation_is_refused_with_the_list() {
        for category in ["bogus-category", "dangerousProduct", ""] {
            let legacy: Derogation = serde_json::from_value(json!({ "category": category }))
                .expect("the old form still reads");
            assert!(matches!(legacy, Derogation::Legacy(_)), "{category}");
            let problem = legacy_derogation_problem(&destroyed(Some(legacy)))
                .unwrap_or_else(|| panic!("`{category}` as free text was accepted"));
            assert_eq!(problem.field, "/reason/derogation");
            assert!(
                problem.message.contains("dangerousProduct"),
                "the refusal should list what is accepted: {}",
                problem.message
            );
            assert!(
                problem.message.contains("2026/296"),
                "the refusal should name the act: {}",
                problem.message
            );
        }
    }

    /// A name the act does not list is not a point and does not read as a
    /// derogation at all, so it is refused while the body is parsed, before the
    /// passport is read.
    #[test]
    fn a_name_the_act_does_not_list_does_not_read_as_a_derogation() {
        for name in [
            "bogus-category",
            "safety",
            "DangerousProduct",
            " dangerousProduct",
            "",
        ] {
            assert!(
                serde_json::from_value::<Derogation>(json!(name)).is_err(),
                "`{name}` read as a derogation"
            );
        }
    }

    /// Only a destruction carries a derogation, and one that cites none is a
    /// question for the ban, not for this check.
    #[test]
    fn nothing_but_a_free_text_destruction_is_refused_up_front() {
        for reason in [
            DeactivationReason::Recycled,
            DeactivationReason::Exported,
            DeactivationReason::Lost,
            destroyed(None),
        ] {
            assert_eq!(legacy_derogation_problem(&reason), None);
        }
    }

    /// The refusal for a destruction the ban reaches says why and what to cite.
    #[test]
    fn a_missing_derogation_is_refused_with_the_ban_and_the_list() {
        let problem = missing_derogation_problem();
        assert_eq!(problem.field, "/reason/derogation");
        assert!(
            problem.message.contains("Art. 25(1)"),
            "{}",
            problem.message
        );
        assert!(
            problem.message.contains("dangerousProduct"),
            "{}",
            problem.message
        );
    }
}
