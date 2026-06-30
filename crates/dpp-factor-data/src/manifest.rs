//! Dataset manifest — provenance record for a loaded factor table.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Provenance record for a licensed LCI factor table.
///
/// Stored alongside the encrypted table in the factor data bucket.
/// The `table_hash` field is what appears in `CalculationReceipt` —
/// a notified body can verify integrity without seeing the licensed values.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FactorDatasetManifest {
    /// Machine-readable dataset identifier (e.g. `"ecoinvent-3.10"`).
    pub dataset_id: String,
    /// Version string of the dataset.
    pub version: String,
    /// SHA-256 hex digest of the full serialised factor table.
    /// Sealed into `CalculationReceipt.factor_table_hash` at calculation time.
    pub table_hash: String,
    /// Identifier linking this manifest to the signed licence document.
    pub license_id: String,
    /// Human-readable source description (e.g. `"ecoinvent Centre, Switzerland"`).
    pub source: String,
    /// Timestamp when the dataset was retrieved from the licensor.
    pub retrieved_at: DateTime<Utc>,
}
