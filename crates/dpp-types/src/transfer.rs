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

use dpp_domain::{DppError, passport::PassportId, transfer::TransferChain};

/// A transfer chain and the revision of the stored row it was read from.
///
/// Every lifecycle step reads the chain, changes it in memory and writes it back
/// whole, with a signature in between that takes time. Two requests that read
/// the same chain would each write one the other had not seen, and the second
/// write would replace the first. A write over a chain therefore names the
/// revision it read, and [`StateChangeLog`](crate::state_change::StateChangeLog)
/// refuses it with [`stale_chain`] when the row has been written since.
#[derive(Debug, Clone)]
pub struct VersionedChain {
    /// The chain as read, or as changed since.
    pub chain: TransferChain,
    /// The revision of the row `chain` was read from; `None` for a chain with no
    /// row yet, which is how the first transfer on a passport begins.
    pub revision: Option<i64>,
}

impl VersionedChain {
    /// A chain with no stored row, to be written for the first time.
    #[must_use]
    pub fn unstored(chain: TransferChain) -> Self {
        Self {
            chain,
            revision: None,
        }
    }
}

/// The refusal for a chain write that another request got in front of.
///
/// A `Validation`, so the four transfer routes answer it as they answer every
/// other transfer the chain's current state does not allow, and it is not
/// retried for the caller: whether the transfer still makes sense after the
/// other request is the caller's decision.
#[must_use]
pub fn stale_chain() -> DppError {
    DppError::Validation(
        "the transfer chain was changed by another request while this one was running; \
         read it again and retry"
            .into(),
    )
}

/// Persists a passport's transfer chain (one per passport).
#[async_trait]
pub trait TransferStore: Send + Sync {
    /// Load the chain for a passport, if any transfers exist yet, with the
    /// revision a later write over it must still find.
    async fn get_chain(&self, passport_id: PassportId) -> Result<Option<VersionedChain>, DppError>;

    /// Upsert the chain (append-only at the domain layer — a full replace here
    /// is safe because the in-memory chain only ever grows).
    ///
    /// **Unconditional**: it writes over whatever is stored. A lifecycle step
    /// does not call this; it commits through
    /// [`StateChangeLog`](crate::state_change::StateChangeLog), which checks the
    /// revision it read. Every write, this one included, bumps the revision, so
    /// a step that read before it is refused.
    async fn save_chain(&self, chain: &TransferChain) -> Result<(), DppError>;
}
