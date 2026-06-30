//! Integration tests for battery sector DPP lifecycle.

#![cfg(feature = "integration-tests")]

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
        "productCategory": "BATTERY",
        "manufacturer": {
            "name": "GreenCell GmbH",
            "address": "Prenzlauer Berg, Berlin, DE"
        },
        "materials": [
            {"name": "Lithium Iron Phosphate", "weightKg": 1.2}
        ],
        "schemaVersion": "1.0.0",
        "sectorData": {
            "sector": "battery",
            "gtin": "09506000134352",
            "batteryChemistry": "LFP",
            "nominalVoltageV": 48.0,
            "nominalCapacityAh": 100.0,
            "expectedLifetimeCycles": 3000,
            "co2ePerUnitKg": 45.2
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
