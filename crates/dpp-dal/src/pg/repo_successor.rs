//! The published passport that replaced a retired one.
//!
//! One indexed query. `supersedes_id` has been a real column on `odal.passport`
//! since migration `0004`, with `idx_passport_supersedes` over it — so the
//! lookup a scanned carrier needs was a query nobody had written rather than
//! data nobody had kept.

use async_trait::async_trait;
use sqlx::Row;

use dpp_domain::{DppError, passport::Passport, passport::PassportId};
use dpp_types::successor::SuccessorLookup;

use super::{PgDal, db_err};

/// PostgreSQL-backed successor lookup.
pub struct PgSuccessorRepo {
    dal: PgDal,
    lenses: dpp_domain::schemas::LensRegistry,
    catalog: dpp_domain::catalog::ProductGroupCatalog,
}

impl PgSuccessorRepo {
    /// Construct a repo sharing the given pool handle.
    #[must_use]
    pub fn new(dal: PgDal) -> Self {
        Self {
            dal,
            lenses: dpp_domain::schemas::LensRegistry::new(),
            catalog: dpp_domain::catalog::ProductGroupCatalog::new(),
        }
    }
}

#[async_trait]
impl SuccessorLookup for PgSuccessorRepo {
    async fn successor_of(&self, id: PassportId) -> Result<Option<Passport>, DppError> {
        // `status = 'active'` is the published one, and the filter is the point
        // rather than an optimisation: an unpublished successor has no public
        // view, so sending a carrier to it would answer a scan with a `404` one
        // step further along. Until it publishes, the predecessor's own frozen
        // view is the best thing there is.
        //
        // `published_at DESC` decides nothing in a healthy estate — the supersede
        // route checks that the successor names this passport, and amend mints
        // exactly one — but a tie has to resolve somewhere, and the newest is the
        // only answer that is not arbitrary.
        let row = sqlx::query(
            "SELECT doc FROM odal.passport
              WHERE supersedes_id = $1 AND status = 'active'
              ORDER BY published_at DESC NULLS LAST
              LIMIT 1",
        )
        .bind(id.0)
        .fetch_optional(self.dal.pool())
        .await
        .map_err(db_err)?;

        row.map(|r| {
            Passport::from_stored(
                r.get::<serde_json::Value, _>("doc"),
                &self.lenses,
                &self.catalog,
            )
        })
        .transpose()
    }
}
