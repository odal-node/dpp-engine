//! `OperatorService` — load and update the node's operator configuration.

use std::sync::Arc;

use dpp_domain::domain::error::DppError;
use dpp_types::operator::{OperatorConfig, OperatorConfigRepository, UpdateOperatorConfig};

/// Application service for operator configuration.
///
/// Reads and merges operator branding and compliance settings persisted in the
/// `operator_config` table. Always called with `STANDALONE_OPERATOR_ID` — the
/// `operator_id` parameter is a provenance constant, not a scoping key.
pub struct OperatorService {
    pub repo: Arc<dyn OperatorConfigRepository>,
}

impl OperatorService {
    /// Construct with the given repository adapter.
    pub fn new(repo: Arc<dyn OperatorConfigRepository>) -> Self {
        Self { repo }
    }

    /// Return the operator config for `operator_id`.
    ///
    /// Returns an empty `OperatorConfig` (no error) when no row exists yet,
    /// keeping dashboard form binding simple.
    pub async fn get(&self, operator_id: &str) -> Result<OperatorConfig, DppError> {
        match self.repo.get(operator_id).await? {
            Some(cfg) => Ok(cfg),
            None => Ok(OperatorConfig::empty(operator_id)),
        }
    }

    /// Merge-patch the operator config and persist; creates the row if absent.
    pub async fn update(
        &self,
        operator_id: &str,
        patch: UpdateOperatorConfig,
    ) -> Result<OperatorConfig, DppError> {
        let mut cfg = self
            .repo
            .get(operator_id)
            .await?
            .unwrap_or_else(|| OperatorConfig::empty(operator_id));
        patch.apply(&mut cfg);
        self.repo.upsert(cfg).await
    }
}
