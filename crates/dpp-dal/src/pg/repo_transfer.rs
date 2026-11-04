//! `TransferStore` on PostgreSQL — one transfer chain per passport (`ops/pg/0017`).

use async_trait::async_trait;
use sqlx::Row;

use dpp_domain::{DppError, passport::PassportId, transfer::TransferChain};
use dpp_types::TransferStore;
use dpp_types::transfer::{VersionedChain, stale_chain};

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
    async fn get_chain(&self, passport_id: PassportId) -> Result<Option<VersionedChain>, DppError> {
        let row = sqlx::query(
            "SELECT chain, revision FROM odal.passport_transfer WHERE passport_id = $1",
        )
        .bind(passport_id.0)
        .fetch_optional(self.dal.pool())
        .await
        .map_err(db_err)?;
        row.map(|r| {
            let chain = serde_json::from_value(r.get::<serde_json::Value, _>("chain"))
                .map_err(|e| DppError::Internal(format!("deserialize transfer chain: {e}")))?;
            Ok(VersionedChain {
                chain,
                revision: Some(r.get::<i64, _>("revision")),
            })
        })
        .transpose()
    }

    async fn save_chain(&self, chain: &TransferChain) -> Result<(), DppError> {
        upsert_chain(self.dal.pool(), chain).await
    }
}

fn chain_doc(chain: &TransferChain) -> Result<serde_json::Value, DppError> {
    serde_json::to_value(chain)
        .map_err(|e| DppError::Internal(format!("serialize transfer chain: {e}")))
}

/// Write `chain` whole, as the passport's transfer chain, whatever is stored.
///
/// For [`TransferStore::save_chain`] and the registry transfer outbox, which
/// write the chain beside what the handover owes. It bumps the revision, so a
/// lifecycle step that read the chain before this write is refused by
/// [`write_chain_over`].
pub(crate) async fn upsert_chain<'e>(
    executor: impl sqlx::PgExecutor<'e>,
    chain: &TransferChain,
) -> Result<(), DppError> {
    let doc = chain_doc(chain)?;
    sqlx::query(
        r#"INSERT INTO odal.passport_transfer (passport_id, chain, updated_at)
           VALUES ($1, $2, now())
           ON CONFLICT (passport_id)
           DO UPDATE SET chain = EXCLUDED.chain,
                         revision = passport_transfer.revision + 1,
                         updated_at = now()"#,
    )
    .bind(chain.passport_id.0)
    .bind(&doc)
    .execute(executor)
    .await
    .map_err(db_err)?;
    Ok(())
}

/// Write `chain` whole, over the revision it was read at, and refuse with
/// [`stale_chain`] when the stored row is no longer at that revision.
///
/// The state-change log's write, so the one every lifecycle step takes. The
/// check is the statement's own `WHERE`: a row another transaction holds is
/// waited for and then tested at the revision it left, so two writers that read
/// the same revision cannot both match it. A chain read as absent writes only
/// where there is still no row, for the same reason.
pub(crate) async fn write_chain_over<'e>(
    executor: impl sqlx::PgExecutor<'e>,
    over: &VersionedChain,
) -> Result<(), DppError> {
    let doc = chain_doc(&over.chain)?;
    let id = over.chain.passport_id.0;
    let written = match over.revision {
        None => {
            sqlx::query(
                r#"INSERT INTO odal.passport_transfer (passport_id, chain, updated_at)
                   VALUES ($1, $2, now())
                   ON CONFLICT (passport_id) DO NOTHING"#,
            )
            .bind(id)
            .bind(&doc)
            .execute(executor)
            .await
        }
        Some(revision) => {
            sqlx::query(
                r#"UPDATE odal.passport_transfer
                   SET chain = $2, revision = revision + 1, updated_at = now()
                   WHERE passport_id = $1 AND revision = $3"#,
            )
            .bind(id)
            .bind(&doc)
            .bind(revision)
            .execute(executor)
            .await
        }
    }
    .map_err(db_err)?
    .rows_affected();
    if written == 0 {
        return Err(stale_chain());
    }
    Ok(())
}
