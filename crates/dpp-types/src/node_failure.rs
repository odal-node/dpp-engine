//! Refusals this node has counted, kept in the database so a restart does not
//! clear them.
//!
//! The Prometheus counters for the same refusals reset when the process restarts.
//! The node-health route answers a monitor that reads the value rather than its
//! change, so the count it serves is kept where a restart cannot reach it. The
//! PostgreSQL implementation is `dpp-dal`'s `PgNodeFailureRepo` (`ops/pg/0048`).

use async_trait::async_trait;
use dpp_domain::DppError;

/// The refusal a count is kept for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureKind {
    /// A publish refused because a passport could not be signed.
    Signing,
    /// A Compliance Current ruleset bundle refused on load.
    RulesetLoad,
}

/// Every kind's count since the node was first started.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FailureCounts {
    /// Publishes refused for a signature.
    pub signing: i64,
    /// Ruleset bundles refused on load.
    pub ruleset_load: i64,
}

/// The durable refusal counts.
#[async_trait]
pub trait NodeFailureCounter: Send + Sync {
    /// Count one refusal of the given kind.
    async fn record(&self, kind: FailureKind) -> Result<(), DppError>;

    /// The counts so far, for every kind.
    async fn counts(&self) -> Result<FailureCounts, DppError>;
}
