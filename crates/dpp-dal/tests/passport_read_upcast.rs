//! Reproduces odal-node/dpp-core#94 / odal-node/dpp-engine#81 directly: a
//! textile document written under the old `countryOfManufacturing` key used
//! to 500 with `missing field` the instant a node linked a `dpp-domain`
//! version that renamed it, because `PgPassportRepo::read_doc` handed the raw
//! document straight to `serde_json::from_value`. `read_doc` now goes through
//! `Passport::from_stored`, which upcasts through the registered lens chain
//! first.
//!
//! Pure in-memory check on the same function `read_doc` delegates to — no
//! Docker/Postgres required.

use dpp_domain::Passport;
use dpp_domain::catalog::SectorCatalog;
use dpp_domain::domain::error::DppError;
use dpp_domain::schemas::lens::LensRegistry;
use serde_json::json;

fn old_textile_doc() -> serde_json::Value {
    json!({
        "id": "019f3aa5-579d-73c1-a3e6-a8002df5e06b",
        "sector": "textile",
        "status": "draft",
        "batchId": null,
        "version": 1,
        "createdAt": "2026-07-01T00:00:00Z",
        "updatedAt": "2026-07-01T00:00:00Z",
        "materials": [],
        "qrCodeUrl": null,
        "sectorData": {
            "sector": "textile",
            "gtin": "09506000134352",
            "careInstructions": "Hand wash cold.",
            "fibreComposition": [{ "pct": 100.0, "fibre": "linen" }],
            "countryOfManufacturing": "BD",
            "chemicalComplianceStandard": "EU REACH Annex XVII"
        },
        "co2ePerUnit": null,
        "productName": "Example Linen Shirt",
        "publishedAt": null,
        "jwsSignature": null,
        "manufacturer": { "name": "Example Clothing GmbH", "address": "DE", "didWebUrl": null },
        "schemaVersion": "1.1.0",
        "retentionLocked": false
    })
}

#[test]
fn a_document_written_under_the_old_country_key_reads_successfully() {
    let lenses = LensRegistry::new();
    let catalog = SectorCatalog::new();

    let passport = Passport::from_stored(old_textile_doc(), &lenses, &catalog)
        .expect("the registered textile 1.1.0 -> 1.2.0 lens must bridge this document");

    let Some(dpp_domain::domain::sector::SectorData::Textile(textile)) = passport.sector_data
    else {
        panic!("expected textile sector data");
    };
    assert_eq!(textile.country_of_origin, "BD");
}

#[test]
fn a_document_no_lens_can_bridge_fails_typed_not_panicked() {
    // Same document, but recorded at 1.0.0 — today's registry has no lens
    // leaving textile 1.0.0 at all, so this cannot be upgraded. Must come
    // back as a distinguishable, typed refusal, not a raw serde panic and not
    // a silent pass-through.
    let mut doc = old_textile_doc();
    doc["schemaVersion"] = json!("1.0.0");

    let lenses = LensRegistry::new();
    let catalog = SectorCatalog::new();
    let err = Passport::from_stored(doc, &lenses, &catalog)
        .expect_err("no lens chain reaches the current textile schema from 1.0.0");

    assert!(
        matches!(err, DppError::SchemaIncompatible(_)),
        "expected a typed SchemaIncompatible refusal, got: {err}"
    );
}
