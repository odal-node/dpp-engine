//! Finding the passport that replaced another one.
//!
//! # Why this is a port here and not a method on `PassportRepository`
//!
//! `PassportRepository` belongs to `dpp-core`, which is deliberately
//! product-agnostic: it models what a passport *is*, and the question this asks
//! — *which record should a scanned carrier land on now* — is about how a
//! deployment serves them. The engine already keeps two other read concerns on
//! this side for the same reason (the archived-version store and the seal
//! inspector), so this follows them rather than widening a core port.
//!
//! It is also cheap to answer here: `odal.passport` carries `supersedes_id` as a
//! real column with an index on it (`idx_passport_supersedes`, migration
//! `0004`), so the lookup that was missing was a query nobody had written, not
//! data nobody had stored.

use async_trait::async_trait;

use dpp_domain::{DppError, passport::Passport, passport::PassportId};

/// Reads the successor of a retired passport.
///
/// ✅ Regulation (EU) 2024/1781 (ESPR) Art. 9(1): the data carrier on a product
/// links to *the* digital product passport for that product. A carrier is
/// printed once and cannot be recalled, so the record it lands on has to stay
/// the current one as the passport is amended over the product's life.
#[async_trait]
pub trait SuccessorLookup: Send + Sync {
    /// The published passport that declares `id` as the one it supersedes.
    ///
    /// `None` when nothing supersedes it — the passport was retired without a
    /// replacement (end of life, retention elapsed), or the successor exists and
    /// is not published yet. **Both are correctly `None`**: an unpublished
    /// successor has no public view to send anybody to.
    ///
    /// Only one can be returned, and only one should exist. `supersedesId` is
    /// declared by the successor and checked by the supersede route, so two
    /// published passports claiming the same predecessor is a state the write
    /// paths do not produce; an implementation that finds several answers with
    /// the newest rather than guessing.
    ///
    /// # Errors
    ///
    /// Propagates the store's own failure.
    async fn successor_of(&self, id: PassportId) -> Result<Option<Passport>, DppError>;
}
