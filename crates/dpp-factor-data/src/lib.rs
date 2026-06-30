//! Licensed LCI emission factor data store for Odal Node.
//!
//! Implements `dpp_calc::FactorProvider` for real licensed datasets (ecoinvent,
//! EF, Sphera). The `dpp-calc` crate defines the trait and the open methodology;
//! this crate holds the proprietary data layer so no licensed bytes ever appear
//! in the Apache-2.0 `dpp-calc` crate.
//!
//! # What ships now
//!
//! Only `GhostFactorProvider` (returns `FactorNotFound` for every lookup) and
//! the supporting types (`FactorDatasetManifest`, `FactorStore`). No ecoinvent
//! or EF data is bundled here — that is gated behind signing a dataset licence
//! and answering the open questions in `docs/analysis/PRE-LAUNCH-CRATES-SEAL-AND-FACTOR.md` §6.5.
//!
//! # Licence warning
//!
//! DO NOT bundle or expose raw factor tables. See §6.3 of the crate proposal
//! for the ecoinvent/EF redistribution constraints that apply to this crate.

pub mod manifest;
pub mod store;

pub use manifest::FactorDatasetManifest;
pub use store::FactorStore;

use dpp_calc::{error::CalcError, factor::FactorProvider};

/// Stub `FactorProvider` that returns `FactorNotFound` for every lookup.
///
/// Ships in place of the real `LicensedFactorProvider` until a dataset licence
/// is signed and the S3-backed store is stood up. All receipts produced with
/// this provider will carry `dataset_id = "ghost"` and a synthetic `table_hash`,
/// making it trivially identifiable in audit logs.
pub struct GhostFactorProvider;

impl FactorProvider for GhostFactorProvider {
    fn dataset_id(&self) -> &str {
        "ghost"
    }

    fn dataset_version(&self) -> &str {
        "0.0.0"
    }

    fn gwp100(&self, activity_uuid: &str) -> Result<f64, CalcError> {
        Err(CalcError::FactorNotFound(format!(
            "GhostFactorProvider: no real factor data loaded (activity: {activity_uuid})"
        )))
    }

    fn table_hash(&self) -> &str {
        "GHOST-TABLE-HASH-0000000000000000000000000000000000000000000000000000000000000000"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ghost_dataset_id_is_ghost() {
        assert_eq!(GhostFactorProvider.dataset_id(), "ghost");
    }

    #[test]
    fn ghost_gwp100_returns_factor_not_found() {
        let err = GhostFactorProvider
            .gwp100("some-activity-uuid")
            .unwrap_err();
        assert!(matches!(err, CalcError::FactorNotFound(_)));
    }

    #[test]
    fn ghost_table_hash_is_identifiable() {
        assert!(GhostFactorProvider.table_hash().starts_with("GHOST-"));
    }
}
