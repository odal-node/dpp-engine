//! Integration tests for textile sector DPP lifecycle.

#![cfg(feature = "integration-tests")]

mod helpers;

use helpers::{TestClient, make_jwt, seed_complete_operator, start_postgres, start_vault};

#[tokio::test(flavor = "multi_thread")]
async fn test_textile_create_publish_resolve() {
    let pg = start_postgres().await;
    let vault_url = start_vault(pg.dal.clone()).await;
    seed_complete_operator(&pg.dal).await;
    let token = make_jwt("00000000-0000-0000-0000-000000000002");
    let client = TestClient::new(&vault_url, &token);

    // 1. POST /api/v1/dpp — textile sector with all required fields
    let create_body = serde_json::json!({
        "productName": "Organic Cotton T-Shirt",
        "productCategory": "TEXTILE",
        "manufacturer": {
            "name": "EcoTextile Ltd",
            "address": "Manchester, UK"
        },
        "materials": [
            {"name": "Organic Cotton", "weightKg": 0.2}
        ],
        "schemaVersion": "1.0.0",
        "sectorData": {
            "sector": "textile",
            "gtin": "09506000134352",
            "fibreComposition": [
                {"fibre": "cotton", "pct": 95.0},
                {"fibre": "elastane", "pct": 5.0}
            ],
            "countryOfManufacturing": "GB",
            "careInstructions": "Wash at 30°C",
            "chemicalComplianceStandard": "OEKO-TEX 100"
        }
    });

    let resp = client.post_json("/api/v1/dpp", create_body).await;
    assert_eq!(resp.status(), 201, "Failed to create textile passport");

    let passport: serde_json::Value = resp.json().await.unwrap();
    let id = passport["id"].as_str().unwrap();

    // 2. POST /api/v1/dpp/{id}/publish — assert 200
    let resp = client
        .post_json(&format!("/api/v1/dpp/{id}/publish"), serde_json::json!({}))
        .await;
    assert_eq!(resp.status(), 200, "Failed to publish textile passport");

    // 3. GET /public/dpp/{id} — assert sector: textile and fibreComposition present
    let resp = client.get(&format!("/public/dpp/{id}")).await;
    assert_eq!(resp.status(), 200);

    let public: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        public["sectorData"]["sector"], "textile",
        "Expected textile sector data"
    );
    assert!(
        public["sectorData"]["fibreComposition"].is_array(),
        "fibreComposition missing"
    );

    let fibres = public["sectorData"]["fibreComposition"].as_array().unwrap();
    assert_eq!(fibres.len(), 2, "Expected 2 fibre entries");
}
