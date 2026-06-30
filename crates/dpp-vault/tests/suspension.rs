//! Integration test for suspension lifecycle.

#![cfg(feature = "integration-tests")]

mod helpers;

use helpers::{TestClient, make_jwt, seed_complete_operator, start_postgres, start_vault};

#[tokio::test(flavor = "multi_thread")]
async fn test_suspension_flow() {
    let pg = start_postgres().await;
    let vault_url = start_vault(pg.dal.clone()).await;
    seed_complete_operator(&pg.dal).await;
    let token = make_jwt("00000000-0000-0000-0000-000000000003");
    let client = TestClient::new(&vault_url, &token);

    // 1. Create and publish a DPP
    let body = serde_json::json!({
        "productName": "Suspension Test Product",
        "productCategory": "BATTERY",
        "manufacturer": {"name": "Suspend Inc", "address": "Test"},
        "materials": [{"name": "Nickel", "weightKg": 0.5}],
        "schemaVersion": "1.0.0",
        "sectorData": {
            "sector": "battery",
            "gtin": "09506000134352",
            "batteryChemistry": "NiMH",
            "nominalVoltageV": 12.0,
            "nominalCapacityAh": 40.0,
            "expectedLifetimeCycles": 1000,
            "co2ePerUnitKg": 20.0
        }
    });

    let resp = client.post_json("/api/v1/dpp", body).await;
    assert_eq!(resp.status(), 201);

    let passport: serde_json::Value = resp.json().await.unwrap();
    let id = passport["id"].as_str().unwrap();

    // Publish it
    let resp = client
        .post_json(&format!("/api/v1/dpp/{id}/publish"), serde_json::json!({}))
        .await;
    assert_eq!(resp.status(), 200);

    // 2. POST /api/v1/dpp/{id}/suspend → 200
    let resp = client
        .post_json(&format!("/api/v1/dpp/{id}/suspend"), serde_json::json!({}))
        .await;
    assert_eq!(resp.status(), 200, "Failed to suspend passport");

    let suspended: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(suspended["status"], "suspended");

    // 3. GET /public/dpp/{id} → 410 Gone
    let resp = client.get(&format!("/public/dpp/{id}")).await;
    assert_eq!(
        resp.status(),
        410,
        "Suspended passport should return 410 Gone"
    );

    // The resolver returns an RFC 7807 Problem (the legacy `error` code field was
    // dropped); the suspension signal is the 410 status plus the `detail` message.
    let error: serde_json::Value = resp.json().await.unwrap();
    assert!(
        error["detail"]
            .as_str()
            .unwrap_or("")
            .to_lowercase()
            .contains("suspended"),
        "Problem detail should indicate suspension, got: {error}"
    );
}
