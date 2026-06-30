//! Shared `PgDal` connection pool handle and migration runner.

use sqlx::postgres::{PgPool, PgPoolOptions};
use sqlx::{Postgres, Transaction};

use dpp_domain::DppError;

use super::db_err;

/// Shared Postgres handle. Cloning is cheap (the pool is internally Arc'd).
#[derive(Clone)]
pub struct PgDal {
    pool: PgPool,
}

impl PgDal {
    /// Connect as the app role.
    ///
    /// Does NOT run schema migrations — migrations require DDL privileges that
    /// `odal_app` does not have. Call [`PgDal::migrate`] first (as a privileged
    /// role) or run them via ops tooling before starting the node.
    ///
    /// Single-tenant: there is one operator per node, so there is no
    /// operator-isolation boundary to enforce in-process — tenant isolation is
    /// an infrastructure concern (one node per operator). The DB carries no RLS.
    pub async fn connect(database_url: &str) -> Result<Self, DppError> {
        let pool = PgPoolOptions::new()
            .max_connections(10)
            .connect(database_url)
            .await
            .map_err(db_err)?;

        Ok(Self { pool })
    }

    /// Run embedded sqlx migrations via a **privileged** connection URL.
    ///
    /// Must be called before [`PgDal::connect`] on a fresh database — typically
    /// from a separate migration step that connects as the `postgres` superuser
    /// or the `odal_migrate` DDL role. The app role (`odal_app`) cannot run DDL.
    ///
    /// Idempotent: sqlx tracks applied migrations in `_sqlx_migrations` and
    /// skips any that are already applied.
    pub async fn migrate(migration_url: &str) -> Result<(), DppError> {
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(migration_url)
            .await
            .map_err(db_err)?;

        sqlx::migrate!("../../ops/pg")
            .run(&pool)
            .await
            .map_err(|e| DppError::Internal(format!("migration: {e}")))?;

        pool.close().await;
        Ok(())
    }

    /// Raw pool handle — for repo methods that acquire connections without
    /// wrapping them in an explicit transaction.
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Cheap liveness probe: runs `SELECT 1` to confirm the DB is reachable.
    ///
    /// # Errors
    /// Returns `DppError::Internal` if the query fails.
    pub async fn ping(&self) -> Result<(), DppError> {
        sqlx::query("SELECT 1")
            .execute(&self.pool)
            .await
            .map(|_| ())
            .map_err(db_err)
    }

    /// Begin a plain transaction. Used by the read-merge-write and multi-step
    /// write paths that need atomicity (no operator context — single-tenant).
    pub async fn begin(&self) -> Result<Transaction<'static, Postgres>, DppError> {
        self.pool.begin().await.map_err(db_err)
    }
}
