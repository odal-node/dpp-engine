//! Unsold consumer goods — the ESPR Art. 24 disclosure and its port.
//!
//! # Why this is not a passport
//!
//! There is no digital product passport anywhere in Art. 24 or Art. 25. The
//! subject of Art. 24 is **an operator over a financial year**, its medium is
//! the operator's own website, and its trigger is *discarding unsold stock* —
//! none of which is a product placed on the market. So this is an
//! operator-scoped record with its own table and its own routes, and it does
//! not go through the passport lifecycle: nothing here is signed, sealed,
//! retention-locked or registered.
//!
//! > **Art. 24(1):** "Economic operators that discard unsold consumer products …
//! > shall disclose: (a) the number and weight of unsold consumer products
//! > discarded per year, differentiated per type or category of products; (b)
//! > the reasons …; (c) the proportion … delivered … to undergo … preparing for
//! > reuse … recycling, other recovery … and disposal …; (d) measures taken and
//! > measures planned…"
//!
//! # The disclosure is dpp-core's, whole
//!
//! Commission Implementing Regulation (EU) 2026/2 prescribes the format: one
//! disclosure per undertaking per financial year, carrying the disclosing
//! entity and its EUID, the Annex I table of discarded lines (CN category,
//! units and weight with their estimate markers, packaging, the reason under
//! Delegated Regulation (EU) 2026/296, the treatment split), and the measures
//! taken and planned. dpp-domain models it as [`UnsoldGoodsReport`], and this
//! module stores that type as it is rather than a shape of its own, so the act
//! has one home in the code.

use async_trait::async_trait;
use chrono::{DateTime, NaiveDate, Utc};
use serde::Serialize;

use dpp_domain::{DppError, UnsoldGoodsReport};

/// One financial year's disclosure, as stored.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UnsoldGoodsDisclosure {
    /// The disclosure itself.
    pub report: UnsoldGoodsReport,
    /// Who recorded the stored version: the API caller's user id.
    pub recorded_by: String,
    /// When the financial year was first recorded.
    pub created_at: DateTime<Utc>,
    /// When the stored version was recorded. Equal to `created_at` until the
    /// year is recorded again.
    pub updated_at: DateTime<Utc>,
}

/// Persistence for Art. 24 disclosures, one per financial year.
#[async_trait]
pub trait UnsoldGoodsStore: Send + Sync {
    /// Store `report` as the disclosure for its financial year, replacing the
    /// one already stored for the year that starts on the same day.
    ///
    /// # Errors
    /// Database failures, including the table's check that the year ends after
    /// it starts.
    async fn put(
        &self,
        report: &UnsoldGoodsReport,
        recorded_by: &str,
    ) -> Result<UnsoldGoodsDisclosure, DppError>;

    /// The disclosure for the financial year that starts on `start`, if one is
    /// stored.
    ///
    /// # Errors
    /// Database failures.
    async fn get(&self, start: NaiveDate) -> Result<Option<UnsoldGoodsDisclosure>, DppError>;

    /// Every stored disclosure, the latest financial year first.
    ///
    /// # Errors
    /// Database failures.
    async fn list(&self) -> Result<Vec<UnsoldGoodsDisclosure>, DppError>;
}
