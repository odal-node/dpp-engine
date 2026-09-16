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

/// How many links the successor walk follows before giving up.
///
/// A product amended a few times is ordinary; one amended thirty-two is either a
/// cycle or a chain nothing should be walking inside a public read. The cap is a
/// bound on work reachable by an unauthenticated request, not a policy about how
/// often a passport may be corrected.
const MAX_SUCCESSOR_HOPS: u32 = 32;

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
        // 🚨 **The chain is walked, not stepped.** A product amended twice gives
        // `A → B → C`, and by then `B` is itself `superseded` — so a query for
        // the *active* row naming `A` finds nothing, and `A`'s printed carrier
        // goes back to serving `A`. That is the original defect one amendment
        // further along, which is the first thing this has to get right.
        //
        // Each hop therefore takes whatever row names the previous one, active
        // or not, and stops at the first that is published.
        let mut at = id.0;
        let mut hops = 0_u32;

        loop {
            // `published_at DESC, id DESC` — the second is not decoration.
            // Nothing in the schema stops two active rows sharing a
            // `supersedes_id`: two concurrent amendments can each read the
            // predecessor as published, mint a successor, and retire it
            // afterwards. `published_at` can then tie, and a tie with no
            // tie-breaker resolves however the planner feels — a carrier landing
            // on a different passport between two reads is worse than one
            // landing on an arbitrary but stable choice.
            let Some(row) = sqlx::query(
                "SELECT id, doc, status FROM odal.passport
                  WHERE supersedes_id = $1
                  ORDER BY published_at DESC NULLS LAST, id DESC
                  LIMIT 1",
            )
            .bind(at)
            .fetch_optional(self.dal.pool())
            .await
            .map_err(db_err)?
            else {
                // Nothing supersedes it. The caller keeps serving the record it
                // was asked about, which is what this route did before.
                return Ok(None);
            };

            let status: String = row.try_get("status").map_err(db_err)?;
            if status == "active" {
                return Passport::from_stored(
                    row.try_get::<serde_json::Value, _>("doc").map_err(db_err)?,
                    &self.lenses,
                    &self.catalog,
                )
                .map(Some);
            }

            // Not published, for either of two reasons with one answer: a
            // successor not published yet has no public view to send a scan to,
            // and one that is itself superseded has its own successor further
            // along. The next hop tells them apart — it finds a row, or it does
            // not.
            at = row.try_get::<uuid::Uuid, _>("id").map_err(db_err)?;

            hops += 1;
            if hops >= MAX_SUCCESSOR_HOPS {
                // A cycle, or a chain longer than any real product's. Stopping is
                // the safe end: the caller serves the record that was asked for,
                // which is true and verifiable, rather than spinning on a
                // malformed chain inside an unauthenticated public read.
                tracing::warn!(
                    passport_id = %id,
                    hops,
                    "successor chain did not reach a published record within the hop cap — \
                     serving the passport that was asked for"
                );
                return Ok(None);
            }
        }
    }
}
