//! Capture a frozen stored-document fixture, for `dpp-dal`'s compatibility guard.
//!
//! `passport_doc_compat.rs` freezes one real stored `doc` per shipped sector
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
//! the serde shape of `sectorData`) is written by the create and publish paths,
//! not by this file.
//!
//! # What these fixtures are not
//!
//! The harness signs with `MockIdentity`, so `jwsSignature` and every entry in
//! `disclosureSignatures` carry `test-header` / `test-sig` around a real
//! payload, and `complianceResult` reports `PASSTHROUGH_NO_VALIDATION` because
//! no sector plugin is loaded. Immaterial to the guard — it asks whether a
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
//! When a sector's `schema_version` moves, **before** bumping `dpp-domain`. A
//! fixture captured after the bump freezes the new shape and can only catch the
//! bump after next; that is still worth having, but it is not the guard the
//! convention asks for.

#![cfg(feature = "integration-tests")]

mod helpers;

use dpp_dal::pg::sqlx;
use helpers::{TestClient, make_jwt, seed_complete_operator, start_postgres, start_vault};
use serde_json::{Value, json};

/// Where `passport_doc_compat.rs` looks: `{catalog_key}/v{version}.json`.
fn fixture_path(sector: &str, version: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../dpp-dal/tests/fixtures/passport_docs")
        .join(sector)
        .join(format!("v{version}.json"))
}

/// Create → publish → read the stored `doc` back out of Postgres, and write it
/// where the guard will find it.
///
/// The document is read from the `doc` column rather than from the publish
/// response, because the column is what a node actually reads on the next boot
/// and is therefore what the guard is about. A response body has already been
/// through a serialisation the stored row does not share.
async fn capture(sector: &str, body: Value) {
    let pg = start_postgres().await;
    let base = start_vault(pg.dal.clone()).await;
    // Publishing an in-force sector requires a complete operator (Annex III
    // facility + Art. 13 identifier), and those get stamped onto the passport —
    // so a fixture captured without them would be missing fields every real
    // published document carries.
    seed_complete_operator(&pg.dal).await;
    let client = TestClient::new(&base, make_jwt("00000000-0000-0000-0000-0000000f1x00"));

    let resp = client.post_json("/api/v1/dpp", body).await;
    let status = resp.status();
    let created: Value = resp.json().await.expect("create returned JSON");
    assert_eq!(status, 201, "create failed: {created}");
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
    let path = fixture_path(sector, version);

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
        .expect("create the sector's fixture directory");
    std::fs::write(
        &path,
        format!(
            "{}\n",
            serde_json::to_string_pretty(&doc).expect("re-serialise the stored doc")
        ),
    )
    .expect("write the fixture");

    println!("captured {} -> {}", sector, path.display());
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "writes a fixture into the source tree; run via `just capture-fixture`"]
async fn capture_battery() {
    // Carries the full set the Battery Regulation makes mandatory for an
    // industrial battery, not the minimum that validates. A fixture is more
    // useful the more fields it exercises — every field present is one a future
    // non-additive change can be caught on — and a passport missing mandatory
    // content is not a document this sector should be freezing as typical.
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
            "sectorData": {
                "sector": "battery",
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
            "sectorData": {
                "sector": "textile",
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
            "sectorData": {
                "sector": "electronics",
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
