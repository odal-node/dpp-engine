//! Integration tests for ComplianceStrategy behavior.

#![cfg(feature = "integration-tests")]

mod helpers;

use helpers::{TestClient, make_jwt, start_postgres, start_vault};

#[tokio::test(flavor = "multi_thread")]
async fn test_passthrough_battery_stores_result() {
    let pg = start_postgres().await;
    let vault_url = start_vault(pg.dal.clone()).await;
    let token = make_jwt("00000000-0000-0000-0000-000000000004");
    let client = TestClient::new(&vault_url, &token);

    let body = serde_json::json!({
        "productName": "Compliance Battery",
        "productCategory": "BATTERY",
        "manufacturer": {"name": "Compliance Inc", "address": "Test City"},
        "materials": [{"name": "Lithium", "weightKg": 1.2}],
        "schemaVersion": "1.0.0",
        "sectorData": {
            "sector": "battery",
            "gtin": "09506000134352",
            "batteryChemistry": "NMC",
            "nominalVoltageV": 24.0,
            "nominalCapacityAh": 80.0,
            "expectedLifetimeCycles": 2000,
            "co2ePerUnitKg": 55.3
        }
    });

    let resp = client.post_json("/api/v1/dpp", body).await;
    assert_eq!(resp.status(), 201);

    let passport: serde_json::Value = resp.json().await.unwrap();
    let id = passport["id"].as_str().unwrap();

    // GET and check compliance_result.co2e_score matches co2ePerUnitKg
    let resp = client.get(&format!("/api/v1/dpp/{id}")).await;
    assert_eq!(resp.status(), 200);

    let dpp: serde_json::Value = resp.json().await.unwrap();
    // PassthroughRegistry maps the battery's co2ePerUnitKg into the passport's
    // co2ePerUnit (the platform does not surface a separate complianceResult).
    assert_eq!(
        dpp["co2ePerUnit"]["valueKg"].as_f64().unwrap(),
        55.3,
        "co2ePerUnit should match manufacturer-supplied value"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_passthrough_textile_stores_result() {
    let pg = start_postgres().await;
    let vault_url = start_vault(pg.dal.clone()).await;
    let token = make_jwt("00000000-0000-0000-0000-000000000005");
    let client = TestClient::new(&vault_url, &token);

    let body = serde_json::json!({
        "productName": "Compliance Textile",
        "productCategory": "TEXTILE",
        "manufacturer": {"name": "Textile Compliance Ltd", "address": "UK"},
        "materials": [{"name": "Cotton", "weightKg": 0.15}],
        "schemaVersion": "1.0.0",
        "sectorData": {
            "sector": "textile",
            "gtin": "09506000134352",
            "fibreComposition": [
                {"fibre": "wool", "pct": 100.0}
            ],
            "countryOfManufacturing": "GB",
            "careInstructions": "Hand wash, dry flat",
            "chemicalComplianceStandard": "OEKO-TEX 100",
            "carbonFootprintKgCo2e": 12.7
        }
    });

    let resp = client.post_json("/api/v1/dpp", body).await;
    assert_eq!(resp.status(), 201);

    let passport: serde_json::Value = resp.json().await.unwrap();
    let id = passport["id"].as_str().unwrap();

    // GET and check compliance_result.co2e_score matches carbonFootprintKgCo2e
    let resp = client.get(&format!("/api/v1/dpp/{id}")).await;
    assert_eq!(resp.status(), 200);

    let dpp: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        dpp["co2ePerUnit"]["valueKg"].as_f64().unwrap(),
        12.7,
        "co2ePerUnit should match carbonFootprintKgCo2e"
    );
}
