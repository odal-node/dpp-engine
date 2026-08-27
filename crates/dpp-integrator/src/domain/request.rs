//! The typed request shape row validators produce, and the error they report.

/// Row-level validation error returned to the caller.
#[derive(Debug, Clone)]
pub struct RowError {
    pub row: usize,
    pub field: String,
    pub message: String,
}

/// The body sent to `POST /api/v1/dpp` on the vault service.
///
/// The vault's type, not a copy of it. It was a copy, kept in step by a comment
/// saying so, and the copy was four fields short — see the type for which and
/// what it cost.
pub use dpp_types::CreatePassportRequest;
