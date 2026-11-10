//! `NodeSignals` on PostgreSQL: outcomes of the node's own work that leave no
//! other trace, kept across restarts (`ops/pg/0048`).

use std::collections::HashMap;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::Row;

use dpp_domain::DppError;
use dpp_types::node_signal::{NodeSignals, Outcome, Signal, SignalState};

use super::{PgDal, db_err};

/// PostgreSQL implementation of [`NodeSignals`].
pub struct PgNodeSignalRepo {
    dal: PgDal,
}

impl PgNodeSignalRepo {
    /// Construct a repo sharing the given pool handle.
    pub fn new(dal: PgDal) -> Self {
        Self { dal }
    }
}

#[async_trait]
impl NodeSignals for PgNodeSignalRepo {
    async fn record(&self, signal: Signal, outcome: Outcome) -> Result<(), DppError> {
        // One statement either way: the first outcome creates the row and later
        // ones update it, so two failures racing each other cannot lose one.
        let sql = match outcome {
            Outcome::Failed => {
                "INSERT INTO odal.node_signal (name, failures, last_failed_at) \
                 VALUES ($1, 1, now()) \
                 ON CONFLICT (name) DO UPDATE \
                 SET failures = odal.node_signal.failures + 1, \
                     last_failed_at = EXCLUDED.last_failed_at"
            }
            Outcome::Succeeded => {
                "INSERT INTO odal.node_signal (name, last_succeeded_at) \
                 VALUES ($1, now()) \
                 ON CONFLICT (name) DO UPDATE \
                 SET last_succeeded_at = EXCLUDED.last_succeeded_at"
            }
        };
        sqlx::query(sql)
            .bind(signal.name())
            .execute(self.dal.pool())
            .await
            .map_err(db_err)?;
        Ok(())
    }

    async fn states(&self) -> Result<Vec<(Signal, SignalState)>, DppError> {
        let rows = sqlx::query(
            "SELECT name, failures, last_failed_at, last_succeeded_at FROM odal.node_signal",
        )
        .fetch_all(self.dal.pool())
        .await
        .map_err(db_err)?;

        // A name this node does not know was written by a newer one; skip it.
        let mut stored: HashMap<Signal, SignalState> = HashMap::new();
        for row in rows {
            let name: String = row.get("name");
            if let Some(signal) = Signal::from_name(&name) {
                stored.insert(
                    signal,
                    SignalState {
                        failures: row.get("failures"),
                        last_failed_at: row.get::<Option<DateTime<Utc>>, _>("last_failed_at"),
                        last_succeeded_at: row.get::<Option<DateTime<Utc>>, _>("last_succeeded_at"),
                    },
                );
            }
        }
        Ok(Signal::ALL
            .into_iter()
            .map(|signal| (signal, stored.remove(&signal).unwrap_or_default()))
            .collect())
    }
}
