//! Integration tests for validation failure scenarios.
//!
//! Each payload deserialises into the core `SectorData` (so the request reaches
//! the handler's `validate_sector_data`) but violates a schema / cross-field
//! rule, so the vault must reject it with HTTP 422. Bodies are read as text
//! because the rejection may come from the JSON extractor (plain text) or the
//! handler's RFC-style error (JSON) depending on the failure.

#![cfg(feature = "integration-tests")]

mod helpers;

use helpers::{TestClient, make_jwt, start_postgres, start_vault};

#[tokio::test(flavor = "multi_thread")]
async fn test_battery_invalid_gtin() {
    let pg = start_postgres().await;
    let vault_url = start_vault(pg.dal.clone()).await;
    let token = make_jwt("00000000-0000-0000-0000-000000000006");
    let client = TestClient::new(&vault_url, &token);

    // Battery with a malformed GTIN ("123") → 422.
    let body = serde_json::json!({
        "productName": "Battery with bad GTIN",
        "productCategory": "BATTERY",
        "manufacturer": {"name": "Test Inc", "address": "Test City"},
        "materials": [{"name": "Lithium", "weightKg": 1.0}],
        "schemaVersion": "1.0.0",
        "sectorData": {
            "sector": "battery",
            "gtin": "123",
            "batteryChemistry": "Li-ion",
            "nominalVoltageV": 12.0,
            "nominalCapacityAh": 40.0,
            "expectedLifetimeCycles": 1000,
            "co2ePerUnitKg": 30.0
        }
    });

    let resp = client.post_json("/api/v1/dpp", body).await;
    assert_eq!(resp.status(), 422, "Expected 422 for invalid GTIN");
    let message = resp.text().await.unwrap_or_default().to_lowercase();
    assert!(
        message.contains("gtin"),
        "Error message should mention 'gtin': {message}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_textile_fibre_sum_invalid() {
    let pg = start_postgres().await;
    let vault_url = start_vault(pg.dal.clone()).await;
    let token = make_jwt("00000000-0000-0000-0000-000000000007");
    let client = TestClient::new(&vault_url, &token);

    // Fibre percentages sum to 90, not 100 → cross-field validation 422.
    let body = serde_json::json!({
        "productName": "Invalid Fibre Textile",
        "productCategory": "TEXTILE",
        "manufacturer": {"name": "BadTextile Inc", "address": "Test"},
        "materials": [{"name": "Cotton", "weightKg": 0.1}],
        "schemaVersion": "1.0.0",
        "sectorData": {
            "sector": "textile",
            "fibreComposition": [
                {"fibre": "cotton", "pct": 50.0},
                {"fibre": "polyester", "pct": 40.0}
            ],
            "countryOfManufacturing": "GB",
            "careInstructions": "Wash cold",
            "chemicalComplianceStandard": "OEKO-TEX 100"
        }
    });

    let resp = client.post_json("/api/v1/dpp", body).await;
    assert_eq!(resp.status(), 422, "Expected 422 for invalid fibre sum");
    let message = resp.text().await.unwrap_or_default().to_lowercase();
    assert!(
        message.contains("100") || message.contains("fibre") || message.contains("percentage"),
        "Error should mention fibre percentage sum: {message}"
    );
}

// F9 regression: co2ePerUnit and repairabilityScore must be finite and in range.
#[tokio::test(flavor = "multi_thread")]
async fn test_negative_co2e_rejected() {
    let pg = start_postgres().await;
    let vault_url = start_vault(pg.dal.clone()).await;
    let token = make_jwt("00000000-0000-0000-0000-00000000000a");
    let client = TestClient::new(&vault_url, &token);

    let resp = client
        .post_json(
            "/api/v1/dpp",
            serde_json::json!({
                "productName": "Battery",
                "manufacturer": {"name": "Test", "address": "Test City"},
                "materials": [],
                "schemaVersion": "1.0.0",
                "co2ePerUnit": -1.5
            }),
        )
        .await;

    assert_eq!(resp.status(), 422, "negative co2ePerUnit must return 422");
}

#[tokio::test(flavor = "multi_thread")]
async fn test_repairability_score_above_100_rejected() {
    let pg = start_postgres().await;
    let vault_url = start_vault(pg.dal.clone()).await;
    let token = make_jwt("00000000-0000-0000-0000-00000000000b");
    let client = TestClient::new(&vault_url, &token);

    let resp = client
        .post_json(
            "/api/v1/dpp",
            serde_json::json!({
                "productName": "Product",
                "manufacturer": {"name": "Test", "address": "Test City"},
                "materials": [],
                "schemaVersion": "1.0.0",
                "repairabilityScore": 150.0
            }),
        )
        .await;

    assert_eq!(
        resp.status(),
        422,
        "repairabilityScore > 100 must return 422"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_textile_empty_care_instructions() {
    let pg = start_postgres().await;
    let vault_url = start_vault(pg.dal.clone()).await;
    let token = make_jwt("00000000-0000-0000-0000-000000000008");
    let client = TestClient::new(&vault_url, &token);

    // careInstructions present but empty → schema minLength violation → 422.
    let body = serde_json::json!({
        "productName": "Textile No Care",
        "productCategory": "TEXTILE",
        "manufacturer": {"name": "Textile Co", "address": "Test"},
        "materials": [{"name": "Cotton", "weightKg": 0.2}],
        "schemaVersion": "1.0.0",
        "sectorData": {
            "sector": "textile",
            "fibreComposition": [
                {"fibre": "cotton", "pct": 100.0}
            ],
            "countryOfManufacturing": "GB",
            "careInstructions": "",
            "chemicalComplianceStandard": "OEKO-TEX 100"
        }
    });

    let resp = client.post_json("/api/v1/dpp", body).await;
    assert_eq!(
        resp.status(),
        422,
        "Expected 422 for empty care instructions"
    );
    let message = resp.text().await.unwrap_or_default().to_lowercase();
    assert!(
        message.contains("care") || message.contains("length") || message.contains("short"),
        "Error should mention care instructions: {message}"
    );
}
