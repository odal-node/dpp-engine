//! Read paths: fetch by id/GTIN, paginated list, count, and audit history.

use dpp_domain::{
    error::DppError,
    passport::{Passport, PassportId},
    product::ProductIdentity,
    status::PassportStatus,
};
use dpp_types::audit::PassportAuditEntry;

use super::PassportService;

impl PassportService {
    /// Fetch a passport by id regardless of status.
    ///
    /// # Errors
    ///
    /// Returns `DppError::NotFound` if the id is unknown.
    pub async fn find_by_id(&self, id: PassportId) -> Result<Passport, DppError> {
        match self.repo.find_by_id(id).await? {
            Some(p) => Ok(p),
            None => Err(DppError::NotFound(id.to_string())),
        }
    }

    /// Fetch a published passport by id, or `None` if unpublished or unknown.
    pub async fn find_published(&self, id: PassportId) -> Result<Option<Passport>, DppError> {
        self.repo.find_published_by_id(id).await
    }

    /// Fetch a published passport by GS1 GTIN (O(n) scan — see `PgPassportRepo`).
    ///
    /// **Not for a public route.** It folds "no such GTIN" and "suspended" into
    /// the same `None`, so a caller cannot serve `410 Gone` for a recall. Use
    /// [`find_by_gtin_any_status`](Self::find_by_gtin_any_status) there.
    pub async fn find_published_by_gtin(&self, gtin: &str) -> Result<Option<Passport>, DppError> {
        self.repo.find_published_by_gtin(gtin).await
    }

    /// Fetch a passport by GS1 GTIN regardless of status, so the caller can
    /// distinguish a missing product from a recalled one.
    pub async fn find_by_gtin_any_status(&self, gtin: &str) -> Result<Option<Passport>, DppError> {
        self.repo.find_by_gtin_any_status(gtin).await
    }

    /// Fetch a passport by exact compound identity (product group, GTIN, batch),
    /// across `Draft` and `Published` — the import delta-matcher's lookup.
    pub async fn find_by_identity(
        &self,
        identity: &ProductIdentity,
    ) -> Result<Option<Passport>, DppError> {
        self.repo.find_by_identity(identity).await
    }

    /// Fetch a passport in any status, including `Archived`. Returns `None` if unknown.
    pub async fn find_by_id_any_status(
        &self,
        id: PassportId,
    ) -> Result<Option<Passport>, DppError> {
        self.repo.find_by_id_any_status(id).await
    }

    /// Paginated list of passports with optional status, text, and facility filter.
    pub async fn list(
        &self,
        status: Option<PassportStatus>,
        q: Option<&str>,
        facility_id: Option<&str>,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<Passport>, DppError> {
        self.repo.list(status, q, facility_id, limit, offset).await
    }

    /// Count passports, optionally filtered by status and/or facility.
    pub async fn count(
        &self,
        status: Option<PassportStatus>,
        facility_id: Option<&str>,
    ) -> Result<u64, DppError> {
        self.repo.count(status, facility_id).await
    }

    /// Return the append-only audit trail for a passport.
    ///
    /// Verifies the passport exists first so an unknown id returns
    /// `DppError::NotFound` rather than an empty list.
    pub async fn history(&self, id: PassportId) -> Result<Vec<PassportAuditEntry>, DppError> {
        // Verify the passport exists so an unknown id returns 404 (consistent
        // with GET /dpp/{id}); otherwise the handler's NotFound branch is dead
        // and a nonexistent passport would return `200 []`.
        self.find_by_id(id).await?;
        self.audit.list_by_passport(&id.to_string()).await
    }

    /// Every archived version of a passport, oldest first.
    ///
    /// ✅ COMPLIANCE-PIN: EN 18221:2026 clause 4.2.
    ///
    /// Verifies the passport exists first, for the same reason [`Self::history`]
    /// does: otherwise an unknown id returns `200 []`, which reads as "this
    /// passport has never changed" rather than "there is no such passport".
    ///
    /// # Errors
    ///
    /// `NotFound` for an unknown id; otherwise the store's own failure.
    pub async fn versions(
        &self,
        id: PassportId,
    ) -> Result<Vec<dpp_types::audit::PassportVersion>, DppError> {
        self.find_by_id(id).await?;
        self.versions
            .as_ref()
            .ok_or_else(|| DppError::Internal("version archive not configured".into()))?
            .versions(&id.to_string())
            .await
    }

    /// The version that was current at `at`.
    ///
    /// ✅ COMPLIANCE-PIN: EN 18221:2026 clause 4.2 — *"the archived version
    /// corresponding to a given point in time shall be retrievable"*.
    ///
    /// `None` means no archived version covers that moment, which is not a
    /// failure: the passport had not changed by then, or `at` is after its most
    /// recent change. In both cases the live record is the state at that time,
    /// and saying so is the caller's job rather than this one's — returning the
    /// live record from a route named for archived versions would make "which
    /// version is this" unanswerable.
    ///
    /// # Errors
    ///
    /// `NotFound` for an unknown id; otherwise the store's own failure.
    pub async fn version_at(
        &self,
        id: PassportId,
        at: chrono::DateTime<chrono::Utc>,
    ) -> Result<Option<dpp_types::audit::PassportVersion>, DppError> {
        self.find_by_id(id).await?;
        self.versions
            .as_ref()
            .ok_or_else(|| DppError::Internal("version archive not configured".into()))?
            .version_at(&id.to_string(), at)
            .await
    }
}
