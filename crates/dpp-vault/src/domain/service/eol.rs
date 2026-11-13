//! `declare_eol` — end-of-life declaration (recycled, destroyed, exported, or
//! lost), transitioning a passport to the terminal `Deactivated` status.

use dpp_common::event;
use dpp_domain::{
    DiscardReason, FieldError, ValidationErrors,
    eol::{DeactivationReason, EolEvent},
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
        // Before the passport is read, so a refused declaration costs nothing and
        // changes nothing: `Deactivated` is terminal.
        if let Some(problem) = derogation_category_problem(&eol.reason) {
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

        let prev_status = passport.status.to_string();

        // The typed EOL reason rides in the audit entry's metadata — it becomes
        // part of the tamper-evident chain.
        let eol_meta =
            serde_json::to_value(&eol).map_err(|e| DppError::Serialisation(e.to_string()))?;
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
        let updated = self
            .commit_passport_change(
                self.owing_registry_status(
                    StateChange::new(entry)
                        .with_passport(PassportWrite::Status(id, PassportStatus::Deactivated)),
                    RegistryStatusIntent::Deactivated,
                ),
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

/// Why a destruction's derogation category is not one the delegated act names, or
/// `None` when it is, or when the reason is not a destruction.
///
/// `DerogationRef` says the category "is validated against that list by the
/// host", and the type enforces only that one is present: any string was
/// accepted, recorded as the passport's lawful basis, and left it `Deactivated`,
/// which is terminal. The list is Art. 2 of Commission Delegated Regulation (EU)
/// 2026/296, points (a) to (j), and core already carries it as
/// [`DiscardReason`], so the names accepted are core's and nothing here writes a
/// point out again.
///
/// Spelling is exact, as everywhere a category is compared: the value stored is
/// the one a reader will look for.
fn derogation_category_problem(reason: &DeactivationReason) -> Option<FieldError> {
    let DeactivationReason::Destroyed { derogation } = reason else {
        return None;
    };
    let named: Vec<(String, char)> = DiscardReason::ALL
        .iter()
        .filter_map(|point| {
            let wire = serde_json::to_value(point).ok()?;
            Some((wire.as_str()?.to_owned(), point.article_2_point()))
        })
        .collect();
    if named.iter().any(|(name, _)| *name == derogation.category) {
        return None;
    }
    let list = named
        .iter()
        .map(|(name, point)| format!("{name} (point {point})"))
        .collect::<Vec<_>>()
        .join(", ");
    Some(FieldError {
        field: "/reason/derogation/category".to_owned(),
        message: format!(
            "'{}' is not a derogation the delegated act names. Art. 2 of Commission Delegated \
             Regulation (EU) 2026/296 lists: {list}.",
            derogation.category
        ),
    })
}

#[cfg(test)]
mod tests {
    use dpp_domain::DiscardReason;
    use dpp_domain::eol::{DeactivationReason, DerogationRef};

    use super::derogation_category_problem;

    fn destroyed(category: &str) -> DeactivationReason {
        DeactivationReason::Destroyed {
            derogation: DerogationRef {
                category: category.to_owned(),
                act_citation: None,
            },
        }
    }

    /// Every point of the delegated act's Art. 2 is a category a destruction may
    /// cite. The names come from core's own list, so a point added there is
    /// accepted here without anything being edited.
    #[test]
    fn every_point_of_the_delegated_act_is_an_accepted_category() {
        for point in DiscardReason::ALL {
            let name = serde_json::to_value(point).expect("a reason serialises");
            let category = name.as_str().expect("a reason serialises as a string");
            assert_eq!(
                derogation_category_problem(&destroyed(category)),
                None,
                "`{category}` is a point of the act and must be accepted"
            );
        }
    }

    /// A destruction that cites a lawful basis the act does not list is refused,
    /// and the refusal says what the act does list. `odal passport eol --reason
    /// destroyed --derogation bogus-category` exited 0 and left the passport
    /// terminal with that string recorded as its lawful basis.
    #[test]
    fn a_category_the_act_does_not_name_is_refused_with_the_list() {
        for category in [
            "bogus-category",
            "safety",
            "health-and-safety",
            "dangerous-product",
            "DangerousProduct",
            " dangerousProduct",
            "",
        ] {
            let problem = derogation_category_problem(&destroyed(category))
                .unwrap_or_else(|| panic!("`{category}` was accepted"));
            assert_eq!(problem.field, "/reason/derogation/category");
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

    /// Only destruction carries a derogation, so nothing else has a category to
    /// check.
    #[test]
    fn a_reason_other_than_destruction_has_no_category_to_refuse() {
        for reason in [
            DeactivationReason::Recycled,
            DeactivationReason::Exported,
            DeactivationReason::Lost,
        ] {
            assert_eq!(derogation_category_problem(&reason), None);
        }
    }
}
