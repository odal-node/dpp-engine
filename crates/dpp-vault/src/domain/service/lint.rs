//! `relint` — on-demand plausibility-lint re-check (`POST /dpp/{dppId}/lint`).

use dpp_domain::domain::{
    error::DppError,
    passport::{Passport, PassportId},
};

use super::PassportService;

impl PassportService {
    /// Re-run the plausibility lint pack against a passport's current sector
    /// data and persist the refreshed result. A no-op (returns the passport
    /// unchanged) when it carries no sector data.
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

        let Some(sector_data) = passport.sector_data.as_ref() else {
            return Ok(passport);
        };
        let lint_result = dpp_domain::LintResult::compute(sector_data);

        self.repo
            .patch_fields(id, serde_json::json!({ "lintResult": lint_result }))
            .await
    }
}
