//! Canonical public (redacted) passport view.
//!
//! Single source of truth for what the unauthenticated `/public/dpp/{id}` route
//! serves **and** what `publicJwsSignature` is signed over at publish time.
//! Keeping the two identical is what lets anyone verify the public passport
//! against the operator DID without a trusted resolver.

use std::sync::OnceLock;

use serde_json::Value;

use dpp_crypto::access::{SectorAccessPolicy, filter_by_access_tier};
use dpp_domain::{AccessTier, SectorCatalog};

/// Embedded sector catalog, built once (used to resolve per-field access tiers).
fn catalog() -> &'static SectorCatalog {
    static CATALOG: OnceLock<SectorCatalog> = OnceLock::new();
    CATALOG.get_or_init(SectorCatalog::new)
}

/// Build the public-read redaction policy for a sector: the sector-agnostic
/// passport defaults plus the sector's own per-field tiers from the catalog.
pub fn public_policy(sector_key: &str) -> SectorAccessPolicy {
    let mut policy = SectorAccessPolicy::passport_default();
    if let Some(sector_policy) = SectorAccessPolicy::from_catalog(catalog(), sector_key) {
        policy.field_tiers.extend(sector_policy.field_tiers);
    }
    policy
}

/// Redact a full passport JSON value to its **Public**-tier view — exactly what
/// the public endpoint serves. `publicJwsSignature` itself is absent at signing
/// time (the field is `None` and skips serialisation), so the proof never signs
/// over itself.
pub fn public_view(full: &Value, sector_key: &str) -> Value {
    let policy = public_policy(sector_key);
    filter_by_access_tier(full, &policy, AccessTier::Public).filtered_data
}
