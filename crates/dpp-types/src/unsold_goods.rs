//! Unsold consumer goods — the ESPR Art. 24 disclosure record and its port.
//!
//! # Why this is not a passport
//!
//! There is no digital product passport anywhere in Art. 24 or Art. 25. The
//! subject of Art. 24 is **an operator over a financial year**, its medium is
//! the operator's own website, and its trigger is *discarding unsold stock* —
//! none of which is a product placed on the market. So this is an
//! operator-scoped record with its own table and its own routes, and it is
//! deliberately not modelled as a product group with passports.
//!
//! > **Art. 24(1):** "Economic operators that discard unsold consumer products …
//! > shall disclose: (a) the number and weight of unsold consumer products
//! > discarded per year, differentiated per type or category of products; (b)
//! > the reasons …; (c) the proportion … delivered … to undergo … preparing for
//! > reuse … recycling, other recovery … and disposal …; (d) measures taken and
//! > measures planned…"
//!
//! Art. 25 is the other half: from **19 July 2026** the destruction of unsold
//! consumer products listed in Annex VII is prohibited. That is why
//! [`Destination::ExemptDestruction`] is the one destination that must carry a
//! justification — recording a destruction without saying why it is exempt
//! records a prohibited act as though it were routine.
//!
//! # What the categories are, and what they are not
//!
//! [`ProductCategory`] serves Art. 24(1)(a)'s "differentiated per type or
//! category of products", which prescribes no vocabulary and leaves the
//! categorisation to the operator. It is **not** Annex VII ban scope. Annex VII
//! gives two *code-valued* headings — apparel and clothing accessories (`4203`,
//! `61`, `62`, `6504`, `6505`) and footwear (`6401`–`6405`) — matched by CN
//! prefix, with clothing accessories *inside* the first heading rather than
//! beside it. Reading this enum as that list would get both the count and the
//! shape of the headings wrong.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use dpp_domain::DppError;

/// How the discarded goods were categorised, for Art. 24(1)(a).
///
/// The operator's own categorisation — see the module header on why this is not
/// Annex VII scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ProductCategory {
    Apparel,
    Footwear,
    HomeTextile,
    Accessories,
    Other,
}

/// Why the goods went unsold, for Art. 24(1)(b).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum DiscardReason {
    EndOfSeason,
    QualityDefect,
    PackagingDefect,
    OverProduction,
    CustomerReturn,
    Other,
}

/// Where the goods went, for Art. 24(1)(c).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Destination {
    Donation,
    Recycling,
    Repurposing,
    SupplierReturn,
    /// Destruction claimed under an Art. 25 exemption. The only destination
    /// that requires a justification, because it is the only one recording an
    /// act that is otherwise prohibited.
    ExemptDestruction,
}

impl ProductCategory {
    /// The DB string, which is what the table's `CHECK` constraint allowlists.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Apparel => "apparel",
            Self::Footwear => "footwear",
            Self::HomeTextile => "homeTextile",
            Self::Accessories => "accessories",
            Self::Other => "other",
        }
    }
}

impl DiscardReason {
    /// The DB string, which is what the table's `CHECK` constraint allowlists.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EndOfSeason => "endOfSeason",
            Self::QualityDefect => "qualityDefect",
            Self::PackagingDefect => "packagingDefect",
            Self::OverProduction => "overProduction",
            Self::CustomerReturn => "customerReturn",
            Self::Other => "other",
        }
    }
}

impl Destination {
    /// The DB string, which is what the table's `CHECK` constraint allowlists.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Donation => "donation",
            Self::Recycling => "recycling",
            Self::Repurposing => "repurposing",
            Self::SupplierReturn => "supplierReturn",
            Self::ExemptDestruction => "exemptDestruction",
        }
    }

    /// Whether recording this destination requires an Art. 25 justification.
    #[must_use]
    pub fn requires_justification(self) -> bool {
        matches!(self, Self::ExemptDestruction)
    }
}

/// One disclosure line: a category of goods discarded in a reporting period.
///
/// A report is many of these, not one row — Art. 24(1) asks for the figures
/// "differentiated per type or category of products", and separately per reason
/// and destination, which a single aggregate row cannot express.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateUnsoldGoodsEntry {
    /// The financial year the goods were discarded in, as `YYYY`. Art. 24(1)
    /// discloses "the preceding financial year", annually.
    pub reporting_period: String,
    /// How many products. Art. 24(1)(a) asks for the number **and** the weight;
    /// this is the half `0008` had no column for.
    pub unit_count: i64,
    /// Their total weight in kilograms.
    pub volume_kg: f64,
    pub product_category: ProductCategory,
    pub reason: DiscardReason,
    pub destination: Destination,
    /// Why this destruction is exempt from the Art. 25 ban. Required when
    /// `destination` is `exemptDestruction`, refused otherwise — a
    /// justification attached to a donation describes nothing.
    #[serde(default)]
    pub destruction_justification: Option<String>,
    /// ISO 3166-1 alpha-2 country the goods were disposed of in.
    pub country_of_disposal: String,
}

/// A stored disclosure line.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UnsoldGoodsEntry {
    pub id: Uuid,
    pub reporting_period: String,
    /// `None` only for a row written before the count had a column.
    pub unit_count: Option<i64>,
    pub volume_kg: f64,
    pub product_category: String,
    pub reason: String,
    pub destination: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destruction_justification: Option<String>,
    pub country_of_disposal: String,
    /// The operator the report is about — this node's own, taken from its
    /// operator config rather than from the request. Report *content*, not a
    /// tenant key: the node is single-tenant and there is nothing to scope.
    pub operator_name: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// Persistence for Art. 24 disclosure lines.
#[async_trait]
pub trait UnsoldGoodsStore: Send + Sync {
    /// Record one line.
    ///
    /// # Errors
    /// Database failures, including the table's `CHECK` constraints.
    async fn create(
        &self,
        entry: &CreateUnsoldGoodsEntry,
        operator_id: &str,
        operator_name: Option<&str>,
    ) -> Result<UnsoldGoodsEntry, DppError>;

    /// Every line, newest first, optionally narrowed to one reporting period.
    ///
    /// # Errors
    /// Database failures.
    async fn list(&self, reporting_period: Option<&str>)
    -> Result<Vec<UnsoldGoodsEntry>, DppError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Exempt destruction is the one destination that must be explained, and
    /// the rest must not be — a justification on a donation is noise in a legal
    /// disclosure.
    #[test]
    fn only_exempt_destruction_needs_a_justification() {
        assert!(Destination::ExemptDestruction.requires_justification());
        for d in [
            Destination::Donation,
            Destination::Recycling,
            Destination::Repurposing,
            Destination::SupplierReturn,
        ] {
            assert!(
                !d.requires_justification(),
                "{d:?} is not a destruction and needs no exemption"
            );
        }
    }

    /// Every DB string here is allowlisted by a `CHECK` constraint in
    /// `ops/pg/0008`, so a mismatch is a runtime insert failure rather than a
    /// compile error. Pinned so the two are compared somewhere.
    #[test]
    fn the_db_strings_match_the_check_constraints() {
        let sql = include_str!("../../../ops/pg/0008_unsold_goods_report.sql");
        for s in [
            ProductCategory::Apparel.as_str(),
            ProductCategory::Footwear.as_str(),
            ProductCategory::HomeTextile.as_str(),
            ProductCategory::Accessories.as_str(),
            ProductCategory::Other.as_str(),
            DiscardReason::EndOfSeason.as_str(),
            DiscardReason::QualityDefect.as_str(),
            DiscardReason::PackagingDefect.as_str(),
            DiscardReason::OverProduction.as_str(),
            DiscardReason::CustomerReturn.as_str(),
            DiscardReason::Other.as_str(),
            Destination::Donation.as_str(),
            Destination::Recycling.as_str(),
            Destination::Repurposing.as_str(),
            Destination::SupplierReturn.as_str(),
            Destination::ExemptDestruction.as_str(),
        ] {
            assert!(
                sql.contains(&format!("'{s}'")),
                "`{s}` is not in the migration's CHECK allowlist, so writing it would fail"
            );
        }
    }

    /// The wire form is what an API client sends, and it is `camelCase` like
    /// everything else here — not the DB string by coincidence.
    #[test]
    fn the_wire_form_is_camel_case() {
        let wire = |v: serde_json::Value| v.as_str().expect("string").to_owned();
        assert_eq!(
            wire(serde_json::to_value(ProductCategory::HomeTextile).unwrap()),
            "homeTextile"
        );
        assert_eq!(
            wire(serde_json::to_value(Destination::ExemptDestruction).unwrap()),
            "exemptDestruction"
        );
        assert_eq!(
            wire(serde_json::to_value(DiscardReason::EndOfSeason).unwrap()),
            "endOfSeason"
        );
    }
}
