//! Integration tests for battery sector DPP lifecycle.

#![cfg(feature = "integration-tests")]
// A complete industrial battery is 38 mandatory fields, and `serde_json::json!`
// recurses once per token — the default limit of 128 is not enough to expand a
// body that size.
#![recursion_limit = "256"]

mod helpers;

use helpers::{TestClient, make_jwt, seed_complete_operator, start_postgres, start_vault};

#[tokio::test(flavor = "multi_thread")]
async fn test_battery_create_publish_resolve() {
    let pg = start_postgres().await;
    let vault_url = start_vault(pg.dal.clone()).await;
    seed_complete_operator(&pg.dal).await;
    let token = make_jwt("00000000-0000-0000-0000-000000000001");
    let client = TestClient::new(&vault_url, &token);

    // 1. POST /api/v1/dpp — battery sector with all 12 mandatory fields
    let create_body = serde_json::json!({
        "productName": "EcoBattery LFP 3000",
        "manufacturer": {
            "name": "GreenCell GmbH",
            "address": "Prenzlauer Berg, Berlin, DE"
        },
        "materials": [
            {"name": "Lithium Iron Phosphate", "weightKg": 1.2}
        ],
        // The complete content the Battery Regulation makes mandatory for an
        // industrial battery — 38 fields, not the six that merely satisfy the
        // schema. This is the one test whose subject *is* a battery passport, so
        // it publishes a complete one; the other suites use `portable`, which the
        // Commission's guidance does not cover and which is therefore ungated.
        //
        // NMC rather than LFP: cobalt and nickel recycled content are mandatory
        // here, and core refuses a positive declaration for a metal the
        // chemistry does not contain. An LFP industrial battery cannot satisfy
        // both rules at once.
        "sectorData": {
            "sector": "battery",
            "gtin": "09506000134352",
            "batteryType": "industrial",
            "batteryChemistry": "NMC",
            "batteryPassportNumber": "BP-2026-000042",
            "batteryModelId": "GC-IND-48/100",
            "manufacturingPlace": "Berlin, DE",
            "manufacturingDate": "2026-06-15T00:00:00Z",
            "batteryStatus": "original",
            "batteryWeightKg": 24.5,
            "nominalVoltageV": 48.0,
            "minimalVoltageV": 40.0,
            "maximumVoltageV": 54.6,
            "nominalCapacityAh": 100.0,
            "co2ePerUnitKg": 45.2,
            "originalPowerCapabilityW": 4800.0,
            "powerLimitMinW": 200.0,
            "powerLimitMaxW": 5200.0,
            "internalCellResistanceMohm": 1.4,
            "internalPackResistanceMohm": 12.0,
            "notInUseTemperatureRange": {"minC": -20.0, "maxC": 60.0},
            "notInUseTemperatureReferenceTest": "IEC 62660-1:2018 storage",
            "expectedLifetimeCycles": 3000,
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
                {"name": "Cobalt", "casNumber": "7440-48-4", "weightGrams": 300.0}
            ],
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
            "wasteBatteryInformation": "Return to an authorised collection point"
        }
    });

    let resp = client.post_json("/api/v1/dpp", create_body).await;
    assert_eq!(resp.status(), 201, "Failed to create battery passport");

    let passport: serde_json::Value = resp.json().await.expect("parse response");
    let id = passport["id"]
        .as_str()
        .expect("id missing from create response");

    // 2. GET /api/v1/dpp/{id} — assert draft status
    let resp = client.get(&format!("/api/v1/dpp/{id}")).await;
    assert_eq!(resp.status(), 200);

    let draft: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(draft["status"], "draft");

    // 3. POST /api/v1/dpp/{id}/publish — assert 200
    let resp = client
        .post_json(&format!("/api/v1/dpp/{id}/publish"), serde_json::json!({}))
        .await;
    assert_eq!(resp.status(), 200, "Failed to publish passport");

    let published: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(published["status"], "active");
    assert!(
        published["jwsSignature"].is_string(),
        "jws_signature should be set"
    );

    // 4. GET via public endpoint /public/dpp/{id} — assert GTIN matches
    let resp = client.get(&format!("/public/dpp/{id}")).await;
    assert_eq!(resp.status(), 200);

    let public: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        public["sectorData"]["gtin"], "09506000134352",
        "GTIN mismatch"
    );
}

/// A first publish is refused when the battery omits content its category makes
/// mandatory, and the refusal names every missing field at once.
///
/// The gate lives in `dpp-domain` and is reachable only through
/// `Passport::transition_to` — it is private, so a consumer cannot call it
/// directly and cannot decline to call it while still transitioning. This test
/// exists because the engine previously did decline it, by setting `status`,
/// `published_at` and `retention_locked` by hand and never transitioning at all.
#[tokio::test(flavor = "multi_thread")]
async fn an_incomplete_industrial_battery_cannot_be_published() {
    let pg = start_postgres().await;
    let vault_url = start_vault(pg.dal.clone()).await;
    seed_complete_operator(&pg.dal).await;
    let token = make_jwt("00000000-0000-0000-0000-0000000ba11e");
    let client = TestClient::new(&vault_url, &token);

    // Valid against the schema — the six required fields are all present — and
    // still missing most of what the Battery Regulation requires of an
    // industrial battery. Schema validity and regulatory completeness are
    // different questions, which is the whole reason for a separate gate.
    let resp = client
        .post_json(
            "/api/v1/dpp",
            serde_json::json!({
                "productName": "Incomplete Industrial Cell",
                "manufacturer": {"name": "GreenCell GmbH", "address": "Berlin, DE"},
                "materials": [{"name": "Lithium", "weightKg": 0.8}],
                "sectorData": {
                    "sector": "battery",
                    "gtin": "09506000134352",
                    "batteryType": "industrial",
                    "batteryChemistry": "NMC",
                    "nominalVoltageV": 48.0,
                    "nominalCapacityAh": 100.0,
                    "co2ePerUnitKg": 45.2
                }
            }),
        )
        .await;
    assert_eq!(resp.status(), 201, "create is not the gate — publish is");
    let id = resp.json::<serde_json::Value>().await.unwrap()["id"]
        .as_str()
        .expect("created passport has an id")
        .to_owned();

    let resp = client
        .post_json(&format!("/api/v1/dpp/{id}/publish"), serde_json::json!({}))
        .await;
    assert_eq!(
        resp.status(),
        422,
        "an industrial battery missing mandatory content must not publish"
    );
    let body = resp.text().await.unwrap_or_default();
    assert!(
        body.contains("mandatory") && body.contains("industrial"),
        "the refusal must say what is wrong and for which category: {body}"
    );
    // Reported together, not one per attempt: an operator fixing these one at a
    // time would need a publish round-trip per field.
    for field in [
        "batteryPassportNumber",
        "manufacturingPlace",
        "cathodeMaterial",
    ] {
        assert!(
            body.contains(field),
            "every missing field is named at once; `{field}` is absent from: {body}"
        );
    }

    // A refused first publish must leave nothing behind. `retention_locked` is
    // permanent, so setting it on a failed attempt would make the passport
    // unrepairable — it could never be edited into the state that would let it
    // publish.
    let resp = client.get(&format!("/api/v1/dpp/{id}")).await;
    let after: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(after["status"], "draft", "a refused publish leaves a draft");
    assert!(
        after["publishedAt"].is_null(),
        "a refused publish must not stamp publishedAt"
    );
    assert!(
        after["retentionLocked"] == serde_json::Value::Bool(false)
            || after["retentionLocked"].is_null(),
        "a refused publish must not retention-lock the passport: {after}"
    );
}

/// A portable battery publishes without the industrial content set, because the
/// Commission's guidance covers electric-vehicle, LMT and industrial batteries
/// only. Core declines to invent a requirement its source does not state, and
/// this pins that the engine inherits the same scope rather than over-applying
/// the gate to every battery.
#[tokio::test(flavor = "multi_thread")]
async fn a_portable_battery_is_outside_the_mandatory_content_scope() {
    let pg = start_postgres().await;
    let vault_url = start_vault(pg.dal.clone()).await;
    seed_complete_operator(&pg.dal).await;
    let token = make_jwt("00000000-0000-0000-0000-0000000ba11f");
    let client = TestClient::new(&vault_url, &token);

    let resp = client
        .post_json(
            "/api/v1/dpp",
            serde_json::json!({
                "productName": "Portable Cell",
                "manufacturer": {"name": "GreenCell GmbH", "address": "Berlin, DE"},
                "materials": [{"name": "Lithium", "weightKg": 0.02}],
                "sectorData": {
                    "sector": "battery",
                    "gtin": "09506000134352",
                    "batteryType": "portable",
                    "batteryChemistry": "LFP",
                    "nominalVoltageV": 3.7,
                    "nominalCapacityAh": 2.5,
                    "co2ePerUnitKg": 1.8
                }
            }),
        )
        .await;
    assert_eq!(resp.status(), 201);
    let id = resp.json::<serde_json::Value>().await.unwrap()["id"]
        .as_str()
        .expect("created passport has an id")
        .to_owned();

    let resp = client
        .post_json(&format!("/api/v1/dpp/{id}/publish"), serde_json::json!({}))
        .await;
    assert_eq!(
        resp.status(),
        200,
        "portable is ungated — a real hole in the source, not in this engine: {}",
        resp.text().await.unwrap_or_default()
    );
}
