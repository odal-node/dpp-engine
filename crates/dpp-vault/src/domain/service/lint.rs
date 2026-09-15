//! The plausibility lint, and `relint` — its on-demand re-check
//! (`POST /dpp/{dppId}/lint`).

use chrono::Utc;
use dpp_domain::{
    LintFinding, LintResult, LintSeverity,
    error::DppError,
    passport::{LifeStatus, Passport, PassportId},
};
use dpp_rules::lineage::StatusDefect;

use super::PassportService;

/// Every lint finding for `passport`: the product-group plausibility pack, plus
/// the envelope-level checks the pack cannot see.
///
/// `None` when there is nothing to say — no product group data to run the pack
/// against *and* no envelope finding — which leaves any existing `lintResult`
/// alone rather than replacing it with an empty one.
///
/// **One function, two callers**, deliberately. `apply_lint` runs on create and
/// update, `relint` on `POST /dpp/{dppId}/lint`, and the two used to compute the
/// result separately. A check added to one and not the other would make the
/// route disagree with the record it re-checks, which is the kind of drift
/// nothing would have reported.
pub(super) fn compute_lint(passport: &Passport) -> Option<LintResult> {
    let mut result = passport
        .product_group_data
        .as_ref()
        .map(LintResult::compute);

    if let Some(finding) = life_status_finding(passport) {
        result
            .get_or_insert_with(|| LintResult {
                // Names the product-group pack, which is the only versioned
                // rule set here — the envelope checks below are plain functions
                // in `dpp_rules::lineage` with no version of their own. Stamped
                // even on a result the pack did not contribute to, so the field
                // never reads as absent.
                pack_version: dpp_rules::lint::LINT_PACK_VERSION.to_owned(),
                findings: Vec::new(),
                assessed_at: Utc::now(),
            })
            .findings
            .push(finding);
    }

    result
}

/// Does the passport's claimed life status agree with its derivation edges?
///
/// The check is envelope-level, so the product-group lint pack cannot see it:
/// `life_status` and `derived_from` are fields every product group carries, and
/// `LintResult::compute` is handed only `product_group_data`.
///
/// Advisory rather than a refusal at create, which is what `dpp-core` asks for —
/// the status is stored and then checked, because Art. 77(7) permits several
/// predecessors with nothing forcing them to share an operation, so a status
/// cannot simply be derived from the edges and asserted.
fn life_status_finding(passport: &Passport) -> Option<LintFinding> {
    // `wire_str` on both sides rather than re-serialising: the rule compares
    // these vocabularies as strings, and core pins the two spellings against
    // each other precisely so a caller may pass them straight through.
    let operations: Vec<&str> = passport
        .derived_from
        .iter()
        .map(|edge| edge.operation.wire_str())
        .collect();

    let defect = dpp_rules::lineage::check_life_status_consistency(
        passport.life_status.as_ref().map(LifeStatus::wire_str),
        &operations,
    )?;

    let message = match defect {
        StatusDefect::OriginalIsDerived { operation } => format!(
            "lifeStatus is 'original' while derivedFrom records a '{operation}' edge — an              original unit is the one placed on the market, not the output of an operation              performed on something else"
        ),
        StatusDefect::NoEdgeSupportsStatus { status } => format!(
            "lifeStatus is '{status}' but no derivedFrom edge records an operation that              produces it — either the edges name a different operation, or there are none"
        ),
        StatusDefect::UnknownStatus { status } => format!(
            "lifeStatus is '{status}', which is not one of the five values Annex XIII point              4(c) enumerates"
        ),
        // `StatusDefect` is `#[non_exhaustive]`, so a variant added to core
        // lands here. Reported rather than dropped: a defect this build cannot
        // describe is still a defect, and silence would be the fail-open answer.
        other => format!("lifeStatus does not agree with derivedFrom: {other:?}"),
    };

    Some(LintFinding {
        code: "lineage.life_status_unsupported".to_owned(),
        field: "lifeStatus".to_owned(),
        // Advisory, like every other finding here — neither severity gates
        // publish. `Warning` rather than `Notice` because the record contradicts
        // itself on its face, which is not a matter of taste.
        severity: LintSeverity::Warning,
        message,
    })
}

impl PassportService {
    /// Re-run the plausibility lint against a passport and persist the refreshed
    /// result. A no-op (returns the passport unchanged) when there is nothing to
    /// report — see [`compute_lint`].
    ///
    /// Unlike every other mutating method in this module, this does **not**
    /// append an audit entry or emit an event: lint findings are advisory
    /// only (never gate publish, never change status or the compliance
    /// determination), so a re-check reads closer to a recompute-on-read
    /// than a state transition worth auditing.
    ///
    /// Works regardless of passport status. A re-check on an already-published
    /// passport does not retroactively affect its `jws_signature` — that JWS
    /// is a frozen signature over whatever `lint_result` looked like at
    /// publish time (see `publish`'s audit-entry snapshot, which evidence
    /// export reads instead of the live row).
    ///
    /// # Errors
    ///
    /// Returns `DppError::NotFound` if the id is unknown.
    #[tracing::instrument(skip(self), fields(passport_id = %id))]
    pub async fn relint(&self, id: PassportId) -> Result<Passport, DppError> {
        let passport = self.find_by_id(id).await?;

        let Some(lint_result) = compute_lint(&passport) else {
            return Ok(passport);
        };

        self.repo
            .patch_fields(id, serde_json::json!({ "lintResult": lint_result }))
            .await
    }
}

#[cfg(test)]
mod tests {
    //! What the envelope-level lineage check reports, and when.
    //!
    //! `dpp-core` owns the rule itself and tests it exhaustively; these pin the
    //! wiring, which is the part that can silently not run.

    use dpp_domain::passport::{DerivationRef, LifeStatus, PassportRef, SecondLifeOperation};

    use super::compute_lint;

    fn edge(operation: SecondLifeOperation) -> DerivationRef {
        DerivationRef {
            reference: PassportRef {
                uri: "https://id.example/dpp/019723f4-1a2b-7c3d-8e4f-5a6b7c8d9e0f".to_owned(),
                public_jws_hash: "a".repeat(64),
            },
            operation,
        }
    }

    fn codes(passport: &dpp_domain::Passport) -> Vec<String> {
        compute_lint(passport)
            .map(|r| r.findings.into_iter().map(|f| f.code).collect())
            .unwrap_or_default()
    }

    #[test]
    fn a_status_no_edge_supports_is_reported() {
        let mut p = crate::public_view::tests::stub_passport();
        p.life_status = Some(LifeStatus::Remanufactured);
        p.derived_from = vec![edge(SecondLifeOperation::Repurposing)];

        assert!(
            codes(&p).contains(&"lineage.life_status_unsupported".to_owned()),
            "a 'remanufactured' claim on a 'repurposing'-only edge must be reported"
        );
    }

    #[test]
    fn a_supported_status_is_not_reported() {
        let mut p = crate::public_view::tests::stub_passport();
        p.life_status = Some(LifeStatus::Repurposed);
        p.derived_from = vec![edge(SecondLifeOperation::Repurposing)];

        assert!(
            !codes(&p).contains(&"lineage.life_status_unsupported".to_owned()),
            "a status its own edge supports must not be reported"
        );
    }

    #[test]
    fn an_original_that_claims_a_predecessor_is_reported() {
        let mut p = crate::public_view::tests::stub_passport();
        p.life_status = Some(LifeStatus::Original);
        p.derived_from = vec![edge(SecondLifeOperation::Remanufacturing)];

        assert!(
            codes(&p).contains(&"lineage.life_status_unsupported".to_owned()),
            "an 'original' unit is not the output of an operation performed on something else"
        );
    }

    /// The check must not depend on the passport having product group data.
    ///
    /// `LintResult::compute` is handed only `product_group_data`, so the obvious
    /// wiring — append to whatever the pack produced — reports nothing at all
    /// for a passport that carries none. That is a fail-open: the envelope
    /// fields are there and contradict each other either way.
    #[test]
    fn the_envelope_check_runs_without_product_group_data() {
        let mut p = crate::public_view::tests::stub_passport();
        p.product_group_data = None;
        p.life_status = Some(LifeStatus::Remanufactured);
        p.derived_from = vec![edge(SecondLifeOperation::Repurposing)];

        assert!(
            codes(&p).contains(&"lineage.life_status_unsupported".to_owned()),
            "a passport with no product group data must still be checked"
        );
    }

    /// A clean passport with nothing to say leaves any existing result alone
    /// rather than replacing it with an empty one.
    #[test]
    fn nothing_to_report_and_no_product_group_data_yields_no_result() {
        let mut p = crate::public_view::tests::stub_passport();
        p.product_group_data = None;
        p.life_status = None;
        p.derived_from = Vec::new();

        assert!(compute_lint(&p).is_none());
    }
}
