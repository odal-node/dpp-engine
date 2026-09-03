//! Capture a frozen stored-document fixture, for `dpp-dal`'s compatibility guard.
//!
//! `passport_doc_compat.rs` freezes one real stored `doc` per shipped product group
//! schema version and asserts it still reads under the `dpp-domain` this
//! workspace builds against. Its convention is that a fixture is **captured
//! from a real document**, and this is what does the capturing.
//!
//! # Why not write the JSON by hand
//!
//! A document authored from the current structs deserialises back into those
//! structs by construction, so the guard would pass tautologically and catch
//! nothing — it would look like coverage and be none. What makes a fixture
//! evidence is that the system produced it: the body below is a *request*, and
//! everything the guard actually inspects (`schemaVersion`, `publishedAt`,
//! `retentionLocked`, `version`, the stamped facility and operator identifiers,
//! the serde shape of `productGroupData`) is written by the create and publish paths,
//! not by this file.
//!
//! # What these fixtures are not
//!
//! The harness signs with `MockIdentity`, so `jwsSignature` and every entry in
//! `disclosureSignatures` carry `test-header` / `test-sig` around a real
//! payload, and `complianceResult` reports `PASSTHROUGH_NO_VALIDATION` because
//! no product group plugin is loaded. Immaterial to the guard — it asks whether a
//! stored document still deserialises, and those are a `String` and a struct
//! either way — but a captured document should not be mistaken for a
//! cryptographically meaningful one. If a future check needs a real signature,
//! it needs a real signer, not this file.
//!
//! # Running it
//!
//! ```sh
//! just capture-fixture battery
//! ```
//!
//! Ignored by default: it writes into the source tree, which no ordinary test
//! run should do. It is a tool that happens to be shaped like a test, because
//! the harness it needs — real Postgres, a real vault, a real signer — is the
//! test harness.
//!
//! # When to run it
//!
//! When a product group's `schema_version` moves, **before** bumping `dpp-domain`. A
//! fixture captured after the bump freezes the new shape and can only catch the
//! bump after next; that is still worth having, but it is not the guard the
//! convention asks for.

#![cfg(feature = "integration-tests")]
// A complete industrial battery is 38 mandatory fields; `serde_json::json!`
// recurses once per token and the default limit of 128 cannot expand it.
#![recursion_limit = "256"]

mod helpers;

use dpp_dal::pg::sqlx;
use helpers::{TestClient, make_jwt, seed_complete_operator, start_postgres, start_vault};
use serde_json::{Value, json};

/// Where `passport_doc_compat.rs` looks: `{catalog_key}/v{version}.json`.
fn fixture_path(product_group: &str, version: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../dpp-dal/tests/fixtures/passport_docs")
        .join(product_group)
        .join(format!("v{version}.json"))
}

/// Create → publish → read the stored `doc` back out of Postgres, and write it
/// where the guard will find it.
///
/// The document is read from the `doc` column rather than from the publish
/// response, because the column is what a node actually reads on the next boot
/// and is therefore what the guard is about. A response body has already been
/// through a serialisation the stored row does not share.
async fn capture(product_group: &str, body: Value) {
    let pg = start_postgres().await;
    let base = start_vault(pg.dal.clone()).await;
    // Publishing an in-force product group requires a complete operator (Annex III
    // facility + Art. 13 identifier), and those get stamped onto the passport —
    // so a fixture captured without them would be missing fields every real
    // published document carries.
    seed_complete_operator(&pg.dal).await;
    let client = TestClient::new(&base, make_jwt("00000000-0000-0000-0000-0000000f1x00"));

    let resp = client.post_json("/api/v1/dpp", body).await;
    let status = resp.status();
    // Read the body as text and assert the status *before* parsing. Parsing
    // first turns any non-JSON error response into "expected value at line 1
    // column 1", which says nothing about what the node refused — and a create
    // that fails is the normal way this harness fails.
    let raw = resp.text().await.unwrap_or_default();
    assert_eq!(status, 201, "create failed ({status}): {raw}");
    let created: Value = serde_json::from_str(&raw)
        .unwrap_or_else(|e| panic!("create returned non-JSON: {e}: {raw}"));
    let id = created["id"].as_str().expect("created passport has an id");

    let resp = client
        .post_json(&format!("/api/v1/dpp/{id}/publish"), json!({}))
        .await;
    let status = resp.status();
    let published = resp.text().await.unwrap_or_default();
    assert_eq!(status, 200, "publish failed: {published}");

    let doc: Value = sqlx::query_scalar("SELECT doc FROM odal.passport WHERE id::text = $1")
        .bind(id)
        .fetch_one(pg.dal.pool())
        .await
        .expect("the published passport must be readable from its row");

    let version = doc["schemaVersion"]
        .as_str()
        .expect("a stored passport always carries its schema version");
    let path = fixture_path(product_group, version);

    // Refuse to overwrite. A frozen document is evidence about the release that
    // produced it; replacing one silently would destroy that, and the guard's
    // whole premise is that these files do not change after capture.
    assert!(
        !path.exists(),
        "{} already exists — a frozen fixture is never re-captured. Delete it \
         deliberately if it is genuinely wrong.",
        path.display()
    );
    std::fs::create_dir_all(path.parent().expect("fixture path has a parent"))
        .expect("create the product_group's fixture directory");
    std::fs::write(
        &path,
        format!(
            "{}\n",
            serde_json::to_string_pretty(&doc).expect("re-serialise the stored doc")
        ),
    )
    .expect("write the fixture");

    println!("captured {} -> {}", product_group, path.display());
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "writes a fixture into the source tree; run via `just capture-fixture`"]
async fn capture_battery() {
    // Carries the full set the Battery Regulation makes mandatory for an
    // industrial battery, not the minimum that validates. A fixture is more
    // useful the more fields it exercises — every field present is one a future
    // non-additive change can be caught on — and a passport missing mandatory
    // content is not a document this product group should be freezing as typical.
    capture(
        "battery",
        json!({
            // NMC rather than LFP: the four `recycledContent*` figures are all
            // mandatory for an industrial battery, and core refuses a positive
            // declaration for a metal the chemistry does not contain — LFP has
            // no cobalt and no nickel, so an LFP passport cannot carry the full
            // mandatory set at all. Lead stays 0.0, which is not a declaration.
            "productName": "GridCell IND-48/100",
            "manufacturer": {
                "name": "GreenCell GmbH",
                "address": "Industriestrasse 4, 10115 Berlin, DE",
                "didWebUrl": "https://greencell.example.com/.well-known/did.json"
            },
            "materials": [
                {"name": "Lithium", "weightKg": 0.8, "recycledPct": 12.5, "countryOfOrigin": "CL"},
                {"name": "Cobalt", "weightKg": 0.3, "recycledPct": 16.0, "countryOfOrigin": "CD"}
            ],
            "batchId": "LOT-2026-08",
            "commodityCode": "85076000",
            "productGroupData": {
                "productGroup": "battery",
                "gtin": "09506000134352",
                "batteryType": "industrial",
                "batteryChemistry": "NMC",
                "batteryPassportNumber": "BP-2026-000123",
                "batteryModelId": "IND-48/100-A",
                "manufacturingPlace": "Berlin, DE",
                "manufacturingDate": "2026-06-15T00:00:00Z",
                "batteryWeightKg": 24.5,
                "nominalVoltageV": 48.0,
                "minimalVoltageV": 40.0,
                "maximumVoltageV": 54.6,
                "nominalCapacityAh": 100.0,
                "co2ePerUnitKg": 39.1,
                "originalPowerCapabilityW": 4800.0,
                "powerLimitMinW": 200.0,
                "powerLimitMaxW": 5200.0,
                "expectedLifetimeCycles": 3500,
                "expectedLifetimeReferenceTest": "IEC 61427-2:2015 cycle endurance",
                "recycledContentCobaltPct": 16.0,
                "recycledContentLithiumPct": 12.5,
                "recycledContentNickelPct": 6.0,
                "recycledContentLeadPct": 0.0,
                "renewableContentPct": 8.0,
                "usableExtinguishingAgent": "Water, CO2, ABC dry powder",
                "hazardousSubstances": [
                    {"name": "Lithium hexafluorophosphate", "casNumber": "21324-40-3", "concentrationPct": 1.2}
                ],
                "criticalRawMaterials": [
                    {"name": "Cobalt", "casNumber": "7440-48-4", "weightGrams": 300.0},
                    {"name": "Lithium", "casNumber": "7439-93-2", "weightGrams": 800.0}
                ],
                "batteryStatus": "original",
                "internalCellResistanceMohm": 1.4,
                "internalPackResistanceMohm": 12.0,
                "notInUseTemperatureRange": {"minC": -20.0, "maxC": 60.0},
                "notInUseTemperatureReferenceTest": "IEC 62660-1:2018 storage",
                "cathodeMaterial": [{"name": "LiNiMnCoO2", "weightPct": 32.0}],
                "anodeMaterial": [{"name": "Graphite", "weightPct": 18.0}],
                "electrolyteMaterial": [{"name": "LiPF6 in EC/DMC", "weightPct": 11.0}],
                "componentPartNumbers": ["CELL-21700-A", "BMS-4820"],
                "sparePartsContacts": "parts@greencell.example.com",
                "disassemblyInstructionsUrl": "https://greencell.example.com/disassembly/ind-48",
                "safetyMeasures": "Isolate before servicing; do not puncture",
                "testReportResults": "IEC 62619:2022 — pass",
                "markingInformation": "CE, separate-collection symbol, capacity label",
                "euDeclarationOfConformity": "https://greencell.example.com/doc/ind-48.pdf",
                "wasteBatteryInformation": "Return to an authorised collection point",
                "placedOnMarketDate": "2026-07-15"
            }
        }),
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "writes a fixture into the source tree; run via `just capture-fixture`"]
async fn capture_textile() {
    capture(
        "textile",
        json!({
            "productName": "Organic Cotton Tee",
            "manufacturer": {
                "name": "Sample Textiles Co.",
                "address": "Via Roma 12, 20121 Milano, IT"
            },
            "materials": [{"name": "Cotton", "weightKg": 0.22}],
            "productGroupData": {
                "productGroup": "textile",
                "gtin": "09506000134369",
                "fibreComposition": [
                    {"fibre": "cotton", "pct": 95.0},
                    {"fibre": "elastane", "pct": 5.0}
                ],
                "countryOfOrigin": "IT",
                "careInstructions": "Machine wash cold, line dry",
                "chemicalComplianceStandard": "OEKO-TEX 100",
                "recycledContentPct": 30.0,
                "carbonFootprintKgCo2e": 4.2,
                "waterUseLitres": 1800.0,
                "microplasticSheddingMgPerWash": 12.0,
                "expectedWashCycles": 50,
                "countryOfRawMaterialOrigin": "IN",
                "productWeightGrams": 220.0,
                "sparePartsAvailable": false,
                "recyclabilityClass": "B",
                "endOfLifeInstructions": "Return to a textile collection point",
                "disassemblyInstructions": "Remove label and neck tape before recycling"
            }
        }),
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "writes a fixture into the source tree; run via `just capture-fixture`"]
async fn capture_electronics() {
    capture(
        "electronics",
        json!({
            "productName": "Aurora S1 Smartphone",
            "manufacturer": {
                "name": "Aurora Devices BV",
                "address": "Keizersgracht 100, 1015 Amsterdam, NL"
            },
            "materials": [{"name": "Aluminium", "weightKg": 0.06, "recycledPct": 80.0}],
            "productGroupData": {
                "productGroup": "electronics",
                "gtin": "09506000134376",
                // Closed to Regulation (EU) 2023/1670 Art. 1(1)'s four device
                // types as of electronics v1.2.0.
                "productCategory": "smartphone",
                "energyEfficiencyClass": "B",
                "co2ePerUnitKg": 52.4,
                "sparePartsAvailable": true,
                "repairManualUrl": "https://aurora.example.com/repair/s1",
                "disassemblyInstructionsUrl": "https://aurora.example.com/disassembly/s1",
                "rohsCompliant": true,
                "recycledContentPct": 22.0,
                "standbyPowerW": 0.15,
                "expectedLifetimeYears": 7,
                "firmwareUpdateUntil": "2033-09-01T00:00:00Z"
            }
        }),
    )
    .await;
}

// ─── The remaining shipped product groups ────────────────────────────────────
//
// One per product group the catalog ships, because
// `every_shipped_product_group_has_a_fixture_for_its_current_version` requires
// one and there is no way to satisfy it except by capturing a real document.
// Each body carries the schema's required set with plausible values; a fixture
// is evidence about the *envelope* the write path produces, so what matters is
// that a real create and publish accepted it, not that the numbers are
// interesting.

#[tokio::test(flavor = "multi_thread")]
#[ignore = "writes a fixture into the source tree; run via `just capture-fixture`"]
async fn capture_aluminium() {
    capture(
        "aluminium",
        json!({
            "productName": "Rolled Aluminium Coil 1050A",
            "manufacturer": {
                "name": "Sample Light Metals AS",
                "address": "Havnegata 4, 6600 Sunndalsora, NO"
            },
            "materials": [{"name": "Aluminium", "weightKg": 1000.0}],
            "productGroupData": {
                "productGroup": "aluminium",
                "gtin": "09506000200019",
                "alloyGrade": "1050A",
                "productionRoute": "secondary-recycled",
                "co2ePerTonneKg": 4200.0,
                "recycledContentPct": 75.0,
                "countryOfOrigin": "NO"
            }
        }),
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "writes a fixture into the source tree; run via `just capture-fixture`"]
async fn capture_construction() {
    capture(
        "construction",
        json!({
            "productName": "CEM II/A-S 42,5 N Cement",
            "manufacturer": {
                "name": "Sample Baustoffe GmbH",
                "address": "Industriestrasse 8, 45307 Essen, DE"
            },
            "materials": [{"name": "Clinker", "weightKg": 800.0}],
            "productGroupData": {
                "productGroup": "construction",
                "gtin": "09506000200026",
                "productFamily": "cement",
                "countryOfOrigin": "DE",
                "co2ePerFunctionalUnitKg": 620.0,
                "functionalUnit": "1 tonne of cement"
            }
        }),
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "writes a fixture into the source tree; run via `just capture-fixture`"]
async fn capture_detergent() {
    capture(
        "detergent",
        json!({
            "productName": "Concentrated Laundry Liquid 1.5L",
            "manufacturer": {
                "name": "Sample Home Care SA",
                "address": "Rue de Nivelles 22, 1400 Nivelles, BE"
            },
            "materials": [{"name": "Water", "weightKg": 1.1}],
            "productGroupData": {
                "productGroup": "detergent",
                "gtin": "09506000200033",
                "productType": "laundry",
                "format": "liquid",
                // Every surfactant must be readily biodegradable — `false` is a
                // NON_COMPLIANT trigger, so a compliant fixture cannot carry one.
                "surfactants": [
                    {
                        "name": "Sodium Laureth Sulfate",
                        "biodegradable": true,
                        "concentrationBand": "5-15%"
                    },
                    {
                        "name": "Cocamidopropyl Betaine",
                        "biodegradable": true,
                        "concentrationBand": "<5%"
                    }
                ],
                "countryOfOrigin": "BE"
            }
        }),
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "writes a fixture into the source tree; run via `just capture-fixture`"]
async fn capture_furniture() {
    capture(
        "furniture",
        json!({
            "productName": "Oak Dining Chair",
            "manufacturer": {
                "name": "Sample Mobler ApS",
                "address": "Havnevej 3, 7100 Vejle, DK"
            },
            "materials": [{"name": "Oak", "weightKg": 6.4}],
            "productGroupData": {
                "productGroup": "furniture",
                "gtin": "09506000200040",
                "productType": "chair",
                "primaryMaterial": "solid-wood",
                "countryOfOrigin": "DK"
            }
        }),
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "writes a fixture into the source tree; run via `just capture-fixture`"]
async fn capture_mattress() {
    capture(
        "mattress",
        json!({
            "productName": "Pocket Sprung Mattress 160x200",
            "manufacturer": {
                "name": "Sample Sleep Systems Oy",
                "address": "Tehtaankatu 12, 15140 Lahti, FI"
            },
            "materials": [{"name": "Steel springs", "weightKg": 14.0}],
            "productGroupData": {
                "productGroup": "mattress",
                "gtin": "09506000200057",
                "primaryMaterial": "mixed",
                "countryOfOrigin": "FI"
            }
        }),
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "writes a fixture into the source tree; run via `just capture-fixture`"]
async fn capture_steel() {
    capture(
        "steel",
        json!({
            "productName": "Hot Rolled Coil S235JR",
            "manufacturer": {
                "name": "Sample Stal AB",
                "address": "Jarnvagsgatan 1, 613 31 Oxelosund, SE"
            },
            "materials": [{"name": "Steel", "weightKg": 1000.0}],
            "productGroupData": {
                "productGroup": "steel",
                "gtin": "09506000200064",
                "co2ePerTonneSteel": 1850.0,
                "recycledScrapContentPct": 42.0,
                "productCategory": "flat",
                "countryOfOrigin": "SE",
                "productionRoute": "electric-arc"
            }
        }),
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "writes a fixture into the source tree; run via `just capture-fixture`"]
async fn capture_toy() {
    capture(
        "toy",
        json!({
            "productName": "Wooden Stacking Rings",
            "manufacturer": {
                "name": "Sample Spielwaren GmbH",
                "address": "Spielstrasse 5, 90762 Fuerth, DE"
            },
            "materials": [{"name": "Beech", "weightKg": 0.4}],
            "productGroupData": {
                "productGroup": "toy",
                "gtin": "09506000200071",
                "ageGroup": "0-3",
                "primaryMaterial": "wood",
                "ceMarking": true,
                "countryOfOrigin": "DE"
            }
        }),
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "writes a fixture into the source tree; run via `just capture-fixture`"]
async fn capture_tyre() {
    capture(
        "tyre",
        json!({
            "productName": "205/55 R16 91V Summer Tyre",
            "manufacturer": {
                "name": "Sample Pneumatici SpA",
                "address": "Via Gomma 40, 20126 Milano, IT"
            },
            "materials": [{"name": "Natural rubber", "weightKg": 3.1}],
            "productGroupData": {
                "productGroup": "tyre",
                "gtin": "09506000200088",
                "tyreClass": "C1",
                "fuelEfficiencyClass": "B",
                "wetGripClass": "A",
                "externalRollingNoiseDb": 69.0
            }
        }),
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "writes a fixture into the source tree; run via `just capture-fixture`"]
async fn capture_unsold_goods() {
    // Shaped unlike every other product group: an Art. 24 disclosure is about an
    // undertaking's financial year, not a product, so there is no GTIN and the
    // payload is the Annex I return itself.
    capture(
        "unsold-goods",
        json!({
            "productName": "Unsold consumer goods disclosure FY2026",
            "manufacturer": {
                "name": "Sample Retail Group NV",
                "address": "Keizersgracht 100, 1015 CS Amsterdam, NL"
            },
            "materials": [],
            "productGroupData": {
                "productGroup": "unsold-goods",
                "entity": {
                    "name": "Sample Retail Group NV",
                    "identifier": {"type": "euid", "value": "NLNHR.12345678"},
                    "scope": {"type": "standalone"}
                },
                "financialYear": {"start": "2026-01-01", "end": "2026-12-31"},
                "lines": [
                    {
                        "cnCategories": ["6109"],
                        "description": "Cotton T-shirts, returned and unsellable",
                        "unitsDiscarded": {"value": 1240},
                        "weightKg": {"value": 248},
                        "packagingIncluded": false,
                        "reason": "damagedOrContaminated",
                        // Whole percentages: the Rust field is a `u8`, and the
                        // five must sum to 100 — total destruction is derived
                        // from recycling + other recovery + disposal, not filed.
                        "treatment": {
                            "preparingForReusePct": 10,
                            "recyclingPct": 60,
                            "otherRecoveryPct": 20,
                            "disposalPct": 5,
                            "unknownPct": 5
                        }
                    }
                ],
                "measuresTaken": "Donation agreements with two national charities; returns triaged for resale before disposal.",
                "measuresPlanned": "Extend the donation route to all seasonal lines and introduce repair for damaged returns."
            }
        }),
    )
    .await;
}
