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
use dpp_domain::catalog::ProductGroupCatalog;
use dpp_domain::error::DppError;
use dpp_domain::schemas::lens::LensRegistry;
use serde_json::json;

fn old_textile_doc() -> serde_json::Value {
    json!({
        "id": "019f3aa5-579d-73c1-a3e6-a8002df5e06b",
        "productGroup": "textile",
        "status": "draft",
        "batchId": null,
        "version": 1,
        "createdAt": "2026-07-01T00:00:00Z",
        "updatedAt": "2026-07-01T00:00:00Z",
        "materials": [],
        "qrCodeUrl": null,
        "productGroupData": {
            "productGroup": "textile",
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
    let catalog = ProductGroupCatalog::new();

    let passport = Passport::from_stored(old_textile_doc(), &lenses, &catalog)
        .expect("the registered textile 1.1.0 -> 1.2.0 lens must bridge this document");

    let Some(dpp_domain::product_group::ProductGroupData::Textile(textile)) =
        passport.product_group_data
    else {
        panic!("expected textile product_group data");
    };
    assert_eq!(textile.country_of_origin, "BD");
}

#[test]
fn a_document_no_lens_can_bridge_fails_typed_not_panicked() {
    // Same document, recorded at a version the registry has no lens leaving.
    // Must come back as a distinguishable, typed refusal — not a raw serde
    // panic, and not a silent pass-through.
    //
    // This used to use 1.0.0, which dpp-core has since bridged: it added a
    // textile 1.0.0 -> 1.1.0 lens precisely so a v1.0.0 document has a path to
    // the current schema. The behaviour under test is the refusal, not that one
    // particular version is unreachable, so it now names a version that has
    // never existed rather than one core has since rescued.
    let mut doc = old_textile_doc();
    doc["schemaVersion"] = json!("0.9.0");

    let lenses = LensRegistry::new();
    let catalog = ProductGroupCatalog::new();
    let err = Passport::from_stored(doc, &lenses, &catalog)
        .expect_err("no lens chain reaches the current textile schema from 1.0.0");

    assert!(
        matches!(err, DppError::SchemaIncompatible(_)),
        "expected a typed SchemaIncompatible refusal, got: {err}"
    );
}
