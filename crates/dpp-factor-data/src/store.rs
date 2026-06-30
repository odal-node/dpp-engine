//! `FactorStore` trait — abstracts where encrypted factor tables come from.

use crate::manifest::FactorDatasetManifest;

/// Retrieves and decrypts a licensed factor table from storage.
///
/// The real implementation pulls from a private S3-compatible bucket with
/// KMS envelope encryption (see `docs/analysis/PRE-LAUNCH-CRATES-SEAL-AND-FACTOR.md` §6.4).
/// Never writes plaintext to disk; zeroize the decrypted buffer on drop.
pub trait FactorStore: Send + Sync {
    type Error: std::error::Error + Send + Sync + 'static;

    /// Fetch and decrypt the factor table for the given dataset, returning
    /// the raw bytes and the manifest that describes it.
    fn load(
        &self,
        dataset_id: &str,
    ) -> impl std::future::Future<Output = Result<(Vec<u8>, FactorDatasetManifest), Self::Error>> + Send;
}
