//! Canonical public (redacted) passport view.
//!
//! Single source of truth for what the unauthenticated `/public/dpp/{id}` route
//! serves **and** what `publicJwsSignature` is signed over at publish time.
//! Keeping the two identical is what lets anyone verify the public passport
//! against the operator DID without a trusted resolver.
//!
//! ⬅️ Core-candidate: the redaction contract (which fields are public per
//! access tier) is part of what the DPP standard promises third parties, not
//! an operational choice this deployment makes — a plausible future home is
//! `dpp-domain` alongside `AccessTier`. Not moved yet; recorded for the next
//! core breaking revision.

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
/// the public endpoint serves *and* what `publicJwsSignature` is signed over.
/// `publicJwsSignature` itself is absent at signing time (the field is `None` and
/// skips serialisation), so the proof never signs over itself.
pub fn public_view(full: &Value, sector_key: &str) -> Value {
    let policy = public_policy(sector_key);
    let mut view = filter_by_access_tier(full, &policy, AccessTier::Public).filtered_data;

    // Fail closed for an unrecognised sector: with no catalog descriptor there is
    // no field-tier policy for its `sectorData`, so the default-Public pass above
    // would leak potentially professional/confidential fields. Keep only the
    // `sector` tag. Parity with the resolver's RT2-5 backstop, so the signed-and-
    // served view is identical whether reached directly or via the resolver.
    if catalog().get(sector_key).is_none()
        && let Some(obj) = view.as_object_mut()
        && let Some(sd) = obj.get("sectorData")
        && sd
            .get("sector")
            .and_then(Value::as_str)
            .is_some_and(|s| !s.is_empty())
    {
        let tag = sd.get("sector").cloned().unwrap_or(Value::Null);
        obj.insert("sectorData".into(), serde_json::json!({ "sector": tag }));
    }
    view
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn unknown_sector_fails_closed_keeping_only_the_tag() {
        // A sector the catalog does not know: with no field-tier policy we must
        // not pass its sectorData through at Public tier (parity with resolver RT2-5).
        let full = json!({
            "id": "x",
            "productName": "Widget",
            "facility": { "value": "4012345000009", "name": "Plant" },
            "sectorData": {
                "sector": "totallyMadeUpSector",
                "supplierCostEur": 12.50,
                "internalNotes": "trade secret"
            }
        });
        let view = public_view(&full, "totallyMadeUpSector");
        let sd = &view["sectorData"];
        assert_eq!(sd["sector"], json!("totallyMadeUpSector"));
        assert!(sd.get("supplierCostEur").is_none(), "leaked: {sd}");
        assert!(sd.get("internalNotes").is_none(), "leaked: {sd}");
        // Non-sector public fields (Annex III facility) are unaffected.
        assert_eq!(view["facility"]["value"], json!("4012345000009"));
    }

    #[test]
    fn known_sector_keeps_public_fields() {
        let full = json!({
            "id": "x",
            "productName": "EcoBattery",
            "sectorData": { "sector": "battery", "gtin": "09506000134352" }
        });
        let view = public_view(&full, "battery");
        // A known sector is filtered by its policy, not blanket-redacted.
        assert_eq!(view["sectorData"]["gtin"], json!("09506000134352"));
        assert_eq!(view["sectorData"]["sector"], json!("battery"));
    }
}
