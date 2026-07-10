//! Integration test for plausibility-lint findings: computed at create,
//! surfaced in the API response, never gate publish, and refreshable on
//! demand via `POST /dpp/{dppId}/lint` — even on an already-published DPP.

#![cfg(feature = "integration-tests")]

mod helpers;

use helpers::{TestClient, make_jwt, seed_complete_operator, start_postgres, start_vault};

#[tokio::test(flavor = "multi_thread")]
async fn lint_findings_surface_and_never_block_publish() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let pg = start_postgres().await;
    let vault_url = start_vault(pg.dal.clone()).await;
    seed_complete_operator(&pg.dal).await;
    let token = make_jwt("00000000-0000-0000-0000-000000000006");
    let client = TestClient::new(&vault_url, &token);

    // ratedEnergyWh (500.0) is wildly inconsistent with nominalVoltageV *
    // nominalCapacityAh (3.7 * 10.0 = 37.0) — deliberately triggers
    // battery.energy_capacity_mismatch.
    let body = serde_json::json!({
        "productName": "Lint Test Battery",
        "productCategory": "BATTERY",
        "manufacturer": {"name": "Lint Inc", "address": "Test City"},
        "materials": [{"name": "Lithium", "weightKg": 1.2}],
        "schemaVersion": "2.0.0",
        "sectorData": {
            "sector": "battery",
            "gtin": "09506000134352",
            "batteryChemistry": "LFP",
            "nominalVoltageV": 3.7,
            "nominalCapacityAh": 10.0,
            "expectedLifetimeCycles": 500,
            "co2ePerUnitKg": 5.0,
            "ratedEnergyWh": 500.0
        }
    });

    let resp = client.post_json("/api/v1/dpp", body).await;
    assert_eq!(resp.status(), 201);
    let passport: serde_json::Value = resp.json().await.unwrap();
    let id = passport["id"].as_str().unwrap();

    // 1. Findings surface on create, tagged with the pack version.
    assert_eq!(passport["lintResult"]["packVersion"], "1.0.0");
    let findings = passport["lintResult"]["findings"]
        .as_array()
        .expect("findings array");
    assert!(
        findings
            .iter()
            .any(|f| f["code"] == "battery.energy_capacity_mismatch"),
        "expected energy/capacity mismatch finding, got: {findings:?}"
    );

    // 2. GET reflects the same findings.
    let resp = client.get(&format!("/api/v1/dpp/{id}")).await;
    assert_eq!(resp.status(), 200);
    let fetched: serde_json::Value = resp.json().await.unwrap();
    assert!(
        fetched["lintResult"]["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["code"] == "battery.energy_capacity_mismatch")
    );

    // 3. Publish succeeds despite the findings — the non-blocking assertion.
    let resp = client
        .post_json(&format!("/api/v1/dpp/{id}/publish"), serde_json::json!({}))
        .await;
    assert_eq!(
        resp.status(),
        200,
        "publish must succeed with only advisory lint findings present"
    );
    let published: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(published["status"], "active");
    assert!(
        published["lintResult"]["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["code"] == "battery.energy_capacity_mismatch"),
        "findings survive publish"
    );

    // 4. POST /dpp/{id}/lint re-checks even an already-published passport.
    let resp = client
        .post_json(&format!("/api/v1/dpp/{id}/lint"), serde_json::json!({}))
        .await;
    assert_eq!(resp.status(), 200);
    let relinted: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(relinted["status"], "active");
    assert_eq!(relinted["lintResult"]["packVersion"], "1.0.0");
    assert!(
        relinted["lintResult"]["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["code"] == "battery.energy_capacity_mismatch")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn clean_sector_data_produces_no_findings() {
    let pg = start_postgres().await;
    let vault_url = start_vault(pg.dal.clone()).await;
    seed_complete_operator(&pg.dal).await;
    let token = make_jwt("00000000-0000-0000-0000-000000000007");
    let client = TestClient::new(&vault_url, &token);

    let body = serde_json::json!({
        "productName": "Clean Battery",
        "productCategory": "BATTERY",
        "manufacturer": {"name": "Clean Inc", "address": "Test City"},
        "materials": [{"name": "Lithium", "weightKg": 1.2}],
        "schemaVersion": "2.0.0",
        "sectorData": {
            "sector": "battery",
            "gtin": "09506000134352",
            "batteryChemistry": "LFP",
            "nominalVoltageV": 3.7,
            "nominalCapacityAh": 10.0,
            "expectedLifetimeCycles": 500,
            "co2ePerUnitKg": 5.0
        }
    });

    let resp = client.post_json("/api/v1/dpp", body).await;
    assert_eq!(resp.status(), 201);
    let passport: serde_json::Value = resp.json().await.unwrap();

    assert_eq!(passport["lintResult"]["packVersion"], "1.0.0");
    // `findings` is omitted entirely (skip_serializing_if = "Vec::is_empty")
    // when there are none — absent, not an empty array.
    assert!(passport["lintResult"]["findings"].is_null());
}
