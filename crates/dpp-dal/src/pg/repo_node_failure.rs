//! `NodeFailureCounter` on PostgreSQL: the failures this node has counted, kept
//! across restarts (`ops/pg/0048`).

use async_trait::async_trait;
use sqlx::Row;

use dpp_domain::DppError;
use dpp_types::node_failure::{FailureCounts, FailureKind, Failures, NodeFailureCounter};

use super::{PgDal, db_err};

/// PostgreSQL implementation of [`NodeFailureCounter`].
pub struct PgNodeFailureRepo {
    dal: PgDal,
}

impl PgNodeFailureRepo {
    /// Construct a repo sharing the given pool handle.
    pub fn new(dal: PgDal) -> Self {
        Self { dal }
    }
}

/// The name a kind is stored under. The CHECK in `ops/pg/0048` lists the same two.
fn name_of(kind: FailureKind) -> &'static str {
    match kind {
        FailureKind::Signing => "signing",
        FailureKind::RulesetLoad => "ruleset_load",
    }
}

#[async_trait]
impl NodeFailureCounter for PgNodeFailureRepo {
    async fn record(&self, kind: FailureKind) -> Result<(), DppError> {
        // One statement: the first failure creates the row and later ones add to
        // it, so two failures of the same kind racing each other cannot lose one.
        sqlx::query(
            "INSERT INTO odal.node_failure_counter (name, failures, last_failed_at) \
             VALUES ($1, 1, now()) \
             ON CONFLICT (name) DO UPDATE \
             SET failures = odal.node_failure_counter.failures + 1, \
                 last_failed_at = EXCLUDED.last_failed_at",
        )
        .bind(name_of(kind))
        .execute(self.dal.pool())
        .await
        .map_err(db_err)?;
        Ok(())
    }

    async fn counts(&self) -> Result<FailureCounts, DppError> {
        let rows =
            sqlx::query("SELECT name, failures, last_failed_at FROM odal.node_failure_counter")
                .fetch_all(self.dal.pool())
                .await
                .map_err(db_err)?;
        let mut counts = FailureCounts::default();
        for row in rows {
            let name: String = row.get("name");
            let failures = Failures {
                total: row.get("failures"),
                last_at: Some(row.get("last_failed_at")),
            };
            match name.as_str() {
                "signing" => counts.signing = failures,
                "ruleset_load" => counts.ruleset_load = failures,
                _ => {}
            }
        }
        Ok(counts)
    }
}
