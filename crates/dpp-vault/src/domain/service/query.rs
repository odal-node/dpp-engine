//! Read paths: fetch by id/GTIN, paginated list, count, and audit history.

use dpp_domain::domain::{
    error::DppError,
    passport::{Passport, PassportId},
    product_identity::ProductIdentity,
    status::PassportStatus,
};
use dpp_types::audit::AuditEntry;

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
    pub async fn find_published_by_gtin(&self, gtin: &str) -> Result<Option<Passport>, DppError> {
        self.repo.find_published_by_gtin(gtin).await
    }

    /// Fetch a passport by exact compound identity (sector, GTIN, batch),
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
    pub async fn history(&self, id: PassportId) -> Result<Vec<AuditEntry>, DppError> {
        // Verify the passport exists so an unknown id returns 404 (consistent
        // with GET /dpp/{id}); otherwise the handler's NotFound branch is dead
        // and a nonexistent passport would return `200 []`.
        self.find_by_id(id).await?;
        self.audit.list_by_passport(&id.to_string()).await
    }
}
