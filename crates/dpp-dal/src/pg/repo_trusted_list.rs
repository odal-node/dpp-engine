//! The trusted lists this node has verified, and the territories it could not.
//!
//! One row per territory the EU list of trusted lists names, in exactly one of
//! two states. Keeping those apart is the whole point: a qualification verdict
//! of "no list names this issuer" is a statement about the Union only while no
//! territory is recorded unavailable, and Germany is unavailable today.
//!
//! See `ops/pg/0039_trusted_list_cache.sql` for the shape and the reasoning,
//! and `dpp_types::trust::TrustedListStore` for what a caller may assume.

use std::collections::BTreeMap;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::Row;

use dpp_domain::DppError;
use dpp_types::trust::{CachedTrustedList, TrustedListStore};

use super::{PgDal, db_err};

/// PostgreSQL-backed trusted-list cache.
pub struct PgTrustedListRepo {
    dal: PgDal,
}

impl PgTrustedListRepo {
    /// Construct a repo sharing the given pool handle.
    pub fn new(dal: PgDal) -> Self {
        Self { dal }
    }
}

#[async_trait]
impl TrustedListStore for PgTrustedListRepo {
    async fn load(&self) -> Result<BTreeMap<String, CachedTrustedList>, DppError> {
        let rows = sqlx::query(
            "SELECT territory, content, signed_by, verified_at, unavailable_reason
               FROM odal.trusted_list_cache",
        )
        .fetch_all(self.dal.pool())
        .await
        .map_err(db_err)?;

        let mut out = BTreeMap::new();
        for row in rows {
            let territory: String = row.try_get("territory").map_err(db_err)?;
            let reason: Option<String> = row.try_get("unavailable_reason").map_err(db_err)?;

            // The migration's CHECK makes these two states exclusive and
            // exhaustive, so reading the reason first is enough to tell them
            // apart. A row that somehow satisfied neither is read as
            // unavailable rather than skipped: dropping it would shrink the
            // named-territory set, and a verdict would then claim a width it
            // does not have — which is the one failure this table exists to
            // prevent.
            let entry = match reason {
                Some(reason) => CachedTrustedList::Unavailable { reason },
                None => {
                    let content: Option<serde_json::Value> =
                        row.try_get("content").map_err(db_err)?;
                    let signed_by: Option<String> = row.try_get("signed_by").map_err(db_err)?;
                    let verified_at: Option<DateTime<Utc>> =
                        row.try_get("verified_at").map_err(db_err)?;
                    match (content, signed_by, verified_at) {
                        (Some(content), Some(signed_by), Some(verified_at)) => {
                            CachedTrustedList::Verified {
                                content,
                                signed_by,
                                verified_at,
                            }
                        }
                        _ => CachedTrustedList::Unavailable {
                            reason: "the cached row is neither verified nor marked unavailable"
                                .to_owned(),
                        },
                    }
                }
            };
            out.insert(territory, entry);
        }
        Ok(out)
    }

    async fn put(&self, territory: &str, entry: &CachedTrustedList) -> Result<(), DppError> {
        // Both branches write every column, so a territory moving between the
        // two states leaves nothing of the other behind. Writing only the
        // columns a state uses would leave a stale `content` beside a fresh
        // `unavailable_reason` and trip the migration's CHECK — which is the
        // constraint doing its job, and not a failure worth discovering in
        // production.
        let (content, signed_by, verified_at, reason) = match entry {
            CachedTrustedList::Verified {
                content,
                signed_by,
                verified_at,
            } => (
                Some(content.clone()),
                Some(signed_by.clone()),
                Some(*verified_at),
                None,
            ),
            CachedTrustedList::Unavailable { reason } => (None, None, None, Some(reason.clone())),
        };

        sqlx::query(
            r#"INSERT INTO odal.trusted_list_cache
                   (territory, content, signed_by, verified_at, unavailable_reason)
               VALUES ($1, $2, $3, $4, $5)
               ON CONFLICT (territory) DO UPDATE SET
                   content            = $2,
                   signed_by          = $3,
                   verified_at        = $4,
                   unavailable_reason = $5,
                   updated_at         = now()"#,
        )
        .bind(territory)
        .bind(content)
        .bind(signed_by)
        .bind(verified_at)
        .bind(reason)
        .execute(self.dal.pool())
        .await
        .map_err(db_err)?;
        Ok(())
    }
}
