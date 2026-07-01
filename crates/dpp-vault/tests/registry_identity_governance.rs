//! Integration tests for the registry-identity governance rules:
//!   * publish is gated on Annex III facility + operator identifier for in-force
//!     sectors, backfilling from the current defaults first (finding #2);
//!   * the default facility can't be retired while alternatives exist (finding #3);
//!   * the append-only audit trail is retrievable via the API (finding #5).

#![cfg(feature = "integration-tests")]

mod helpers;

use helpers::{TestClient, make_jwt, seed_operator_config, start_postgres, start_vault};
use serde_json::json;

fn battery_body() -> serde_json::Value {
    json!({
        "productName": "EcoBattery LFP 3000",
        "manufacturer": { "name": "GreenCell GmbH", "address": "Berlin, DE" },
        "sectorData": {
            "sector": "battery",
            "gtin": "09506000134352",
            "batteryChemistry": "LFP",
            "nominalVoltageV": 48.0,
            "nominalCapacityAh": 100.0,
            "expectedLifetimeCycles": 3000,
            "co2ePerUnitKg": 45.2
        }
    })
}

async fn add_default_facility(client: &TestClient) {
    let resp = client
        .post_json(
            "/api/v1/facilities",
            json!({
                "name": "Default Plant", "identifierScheme": "gln",
                "identifierValue": "4012345000009", "country": "DE", "isDefault": true
            }),
        )
        .await;
    assert_eq!(resp.status(), 201);
    let resp = client
        .post_json(
            "/api/v1/operator-identifiers",
            json!({ "scheme": "vat", "value": "DE123456789", "isPrimary": true }),
        )
        .await;
    assert_eq!(resp.status(), 201);
}

#[tokio::test(flavor = "multi_thread")]
async fn publish_is_blocked_without_annexiii_identity_then_backfills() {
    let pg = start_postgres().await;
    seed_operator_config(&pg.dal).await; // operator config only — no facility yet
    let vault_url = start_vault(pg.dal.clone()).await;
    let client = TestClient::new(
        &vault_url,
        &make_jwt("00000000-0000-0000-0000-000000000001"),
    );

    // Create a battery passport while no default facility/identifier is configured.
    let resp = client.post_json("/api/v1/dpp", battery_body()).await;
    assert_eq!(resp.status(), 201);
    let id = resp.json::<serde_json::Value>().await.unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();

    // Publish must be refused — battery is in-force and the DPP lacks Annex III identity.
    let resp = client
        .post_json(&format!("/api/v1/dpp/{id}/publish"), json!({}))
        .await;
    assert_eq!(
        resp.status(),
        422,
        "publish must be blocked without a facility/operator identifier"
    );

    // Configure the defaults, then re-publish: the gate backfills from them.
    add_default_facility(&client).await;
    let resp = client
        .post_json(&format!("/api/v1/dpp/{id}/publish"), json!({}))
        .await;
    assert!(
        resp.status().is_success(),
        "publish should succeed once defaults exist (backfilled): {}",
        resp.status()
    );

    // The published passport now carries the backfilled Annex III identity.
    let dpp = client
        .get(&format!("/api/v1/dpp/{id}"))
        .await
        .json::<serde_json::Value>()
        .await
        .unwrap();
    assert_eq!(dpp["facility"]["value"], "4012345000009");
    assert_eq!(dpp["operatorIdentifier"], "DE123456789");
}

#[tokio::test(flavor = "multi_thread")]
async fn default_facility_cannot_be_retired_while_alternatives_exist() {
    let pg = start_postgres().await;
    seed_operator_config(&pg.dal).await;
    let vault_url = start_vault(pg.dal.clone()).await;
    let client = TestClient::new(
        &vault_url,
        &make_jwt("00000000-0000-0000-0000-000000000001"),
    );

    // Facility A (default) and B (secondary).
    let a = client
        .post_json(
            "/api/v1/facilities",
            json!({ "name": "A", "identifierScheme": "gln",
                    "identifierValue": "4012345000009", "country": "DE", "isDefault": true }),
        )
        .await;
    let a_id = a.json::<serde_json::Value>().await.unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let b = client
        .post_json(
            "/api/v1/facilities",
            json!({ "name": "B", "identifierScheme": "gln",
                    "identifierValue": "4000001000005", "country": "DE" }),
        )
        .await;
    let b_id = b.json::<serde_json::Value>().await.unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();

    // Retiring the default while B exists is refused.
    let resp = client.delete(&format!("/api/v1/facilities/{a_id}")).await;
    assert_eq!(
        resp.status(),
        422,
        "retiring the default facility with alternatives must be blocked"
    );

    // Promote B, then A (no longer default) can be retired.
    let resp = client
        .post_json(&format!("/api/v1/facilities/{b_id}/default"), json!({}))
        .await;
    assert_eq!(resp.status(), 204);
    let resp = client.delete(&format!("/api/v1/facilities/{a_id}")).await;
    assert_eq!(resp.status(), 204, "a non-default facility can be retired");
}

#[tokio::test(flavor = "multi_thread")]
async fn sole_facility_can_be_retired_even_if_default() {
    let pg = start_postgres().await;
    seed_operator_config(&pg.dal).await;
    let vault_url = start_vault(pg.dal.clone()).await;
    let client = TestClient::new(
        &vault_url,
        &make_jwt("00000000-0000-0000-0000-000000000001"),
    );

    let f = client
        .post_json(
            "/api/v1/facilities",
            json!({ "name": "Only", "identifierScheme": "gln",
                    "identifierValue": "4012345000009", "country": "DE", "isDefault": true }),
        )
        .await;
    let id = f.json::<serde_json::Value>().await.unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();

    // Nothing to promote → retiring the sole (default) facility is allowed.
    let resp = client.delete(&format!("/api/v1/facilities/{id}")).await;
    assert_eq!(resp.status(), 204);
}

#[tokio::test(flavor = "multi_thread")]
async fn facility_audit_endpoint_returns_the_trail() {
    let pg = start_postgres().await;
    seed_operator_config(&pg.dal).await;
    let vault_url = start_vault(pg.dal.clone()).await;
    let client = TestClient::new(
        &vault_url,
        &make_jwt("00000000-0000-0000-0000-000000000001"),
    );

    let f = client
        .post_json(
            "/api/v1/facilities",
            json!({ "name": "Plant", "identifierScheme": "gln",
                    "identifierValue": "4012345000009", "country": "DE", "isDefault": true }),
        )
        .await;
    let id = f.json::<serde_json::Value>().await.unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();

    // An explicit set-default adds a second audit row.
    let resp = client
        .post_json(&format!("/api/v1/facilities/{id}/default"), json!({}))
        .await;
    assert_eq!(resp.status(), 204);

    let resp = client.get(&format!("/api/v1/facilities/{id}/audit")).await;
    assert_eq!(resp.status(), 200);
    let trail: serde_json::Value = resp.json().await.unwrap();
    let actions: Vec<&str> = trail
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["action"].as_str().unwrap())
        .collect();
    assert_eq!(actions, vec!["added", "set_default"]);
    assert_eq!(trail[0]["entityType"], "facility");
    assert!(trail[0]["actor"].is_string());
}
