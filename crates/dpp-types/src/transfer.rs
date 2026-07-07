//! Persistence port for transfer-of-responsibility chains.
//!
//! The core `TransferChain` (dual-signed provenance of who is responsible for a
//! passport over its life) is a domain type; this port persists one chain per
//! passport. The Postgres implementation lives in `dpp-dal::pg::repo_transfer`.
//!
//! # Why this port lives here and not in core's `dpp-domain::ports`
//!
//! `TransferChain` itself is core (the standard defines its shape). *Storing*
//! one chain per passport is an operational choice this deployment makes, the
//! same way `RegistrySyncOutbox` is engine-side — the port stays here, next to
//! that one, rather than promoted to core.

use async_trait::async_trait;

use dpp_domain::{
    DppError,
    domain::{passport::PassportId, transfer::TransferChain},
};

/// Persists a passport's transfer chain (one per passport).
#[async_trait]
pub trait TransferStore: Send + Sync {
    /// Load the chain for a passport, if any transfers exist yet.
    async fn get_chain(&self, passport_id: PassportId) -> Result<Option<TransferChain>, DppError>;

    /// Upsert the chain (append-only at the domain layer — a full replace here
    /// is safe because the in-memory chain only ever grows).
    async fn save_chain(&self, chain: &TransferChain) -> Result<(), DppError>;
}
