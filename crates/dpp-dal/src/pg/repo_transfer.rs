//! `TransferStore` on PostgreSQL — one transfer chain per passport (`ops/pg/0017`).

use async_trait::async_trait;
use sqlx::Row;

use dpp_domain::{
    DppError,
    domain::{passport::PassportId, transfer::TransferChain},
};
use dpp_types::TransferStore;

use super::{PgDal, db_err};

/// PostgreSQL implementation of [`TransferStore`].
pub struct PgTransferRepo {
    dal: PgDal,
}

impl PgTransferRepo {
    /// Construct a repo sharing the given pool handle.
    pub fn new(dal: PgDal) -> Self {
        Self { dal }
    }
}

#[async_trait]
impl TransferStore for PgTransferRepo {
    async fn get_chain(&self, passport_id: PassportId) -> Result<Option<TransferChain>, DppError> {
        let row = sqlx::query("SELECT chain FROM odal.passport_transfer WHERE passport_id = $1")
            .bind(passport_id.0)
            .fetch_optional(self.dal.pool())
            .await
            .map_err(db_err)?;
        row.map(|r| {
            serde_json::from_value(r.get::<serde_json::Value, _>("chain"))
                .map_err(|e| DppError::Internal(format!("deserialize transfer chain: {e}")))
        })
        .transpose()
    }

    async fn save_chain(&self, chain: &TransferChain) -> Result<(), DppError> {
        let doc = serde_json::to_value(chain)
            .map_err(|e| DppError::Internal(format!("serialize transfer chain: {e}")))?;
        sqlx::query(
            r#"INSERT INTO odal.passport_transfer (passport_id, chain, updated_at)
               VALUES ($1, $2, now())
               ON CONFLICT (passport_id)
               DO UPDATE SET chain = EXCLUDED.chain, updated_at = now()"#,
        )
        .bind(chain.passport_id.0)
        .bind(&doc)
        .execute(self.dal.pool())
        .await
        .map_err(db_err)?;
        Ok(())
    }
}
