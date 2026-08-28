//! The crate's error type — what is true of sealing regardless of backend.
//!
//! `SealPort` returns `DppError`, which is deliberately coarse — every adapter
//! collapses into `DppError::Internal` at that boundary. This type exists on the
//! near side of it so a failure is classified *once*, where it happened, rather
//! than reconstructed from a string by whoever reads the log.
//!
//! A backend's own failure modes are its own business and live in its module;
//! they arrive here already classified and already rendered, as
//! [`SealError::Backend`]. What stays here is only what any backend can hit:
//! configuration, transport, and an operation nobody implements.

use dpp_domain::error::DppError;

#[derive(Debug, thiserror::Error)]
pub enum SealError {
    /// Configuration is absent, partial, or names something unusable.
    #[error("seal configuration: {0}")]
    Config(String),

    /// The request never completed: DNS, connection, TLS, or timeout.
    ///
    /// Not a backend fault and not ours — nothing reached the far side, so
    /// there is no status and no body to classify against.
    #[error("seal transport: {0}")]
    Transport(String),

    /// A backend failed in a way only that backend can describe.
    ///
    /// Carried as its rendered message rather than as a type: nothing outside
    /// this crate matches on the cause, and lifting every backend's variants
    /// into a shared enum would put each provider's vocabulary — status codes,
    /// skew windows, rate limits — in front of code that must stay ignorant of
    /// which backend is wired.
    #[error("{0}")]
    Backend(String),

    /// An operation this adapter does not implement, stated rather than faked.
    #[error("{0}")]
    Unsupported(&'static str),
}

impl From<SealError> for DppError {
    fn from(e: SealError) -> Self {
        DppError::Internal(e.to_string())
    }
}
