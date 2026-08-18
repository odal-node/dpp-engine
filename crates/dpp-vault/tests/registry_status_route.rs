//! Integration test for the operator-facing registry surface:
//! `GET /api/v1/dpp/{dppId}/registry` and `GET /api/v1/registry`.
//!
//! Registration is the legal obligation the system exists to discharge. Until
//! these routes existed, its state was reachable only through outbox tables,
//! Prometheus gauges and log lines — none of which an operator can see. These
//! tests pin the two answers that matter: what a passport's registration is
//! doing, and what across the estate needs a human.

#![cfg(feature = "integration-tests")]

mod helpers;

use helpers::{TestClient, make_jwt, seed_operator_config, start_postgres, start_vault};

/// A published passport reports a real registration position, and the rollup
/// counts it.
#[tokio::test(flavor = "multi_thread")]
async fn a_published_passport_reports_its_registration() {
    let pg = start_postgres().await;
    seed_operator_config(&pg.dal).await;
    let vault_url = start_vault(pg.dal.clone()).await;
    let token = make_jwt("00000000-0000-0000-0000-000000000001");
    let client = TestClient::new(&vault_url, &token);

    // Battery is an in-force sector, so publish requires the Annex III facility
    // and the Art. 13 operator identifier. Seed both through the API, exactly as
    // an operator would.
    let resp = client
        .post_json(
            "/api/v1/facilities",
            serde_json::json!({
                "name": "Default Plant",
                "identifierScheme": "gln",
                "identifierValue": "4012345000009",
                "country": "DE",
                "isDefault": true
            }),
        )
        .await;
    assert_eq!(resp.status(), 201, "facility create should succeed");

    let resp = client
        .post_json(
            "/api/v1/operator-identifiers",
            serde_json::json!({ "scheme": "vat", "value": "DE123456789", "isPrimary": true }),
        )
        .await;
    assert_eq!(
        resp.status(),
        201,
        "operator identifier create should succeed"
    );

    let resp = client
        .post_json(
            "/api/v1/dpp",
            serde_json::json!({
                "productName": "Registry Surface Battery",
                "sector": "battery",
                "manufacturer": { "name": "TestCorp GmbH", "address": "Berlin, DE" },
                "commodityCode": "85076000",
                // A battery passport can no longer publish with no sector data
                // at all — the mandatory-content gate refuses it before asking
                // which fields are missing. Portable is outside the guidance's
                // scope, so this carries the schema minimum and nothing more:
                // the subject here is the registry surface, not battery content.
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
    assert_eq!(resp.status(), 201, "create should succeed");
    let created: serde_json::Value = resp.json().await.unwrap();
    let id = created["id"].as_str().expect("id").to_owned();

    // Before publish there is no registration owed — and that is reported as
    // absence, not as a registration in some pending limbo.
    let resp = client.get(&format!("/api/v1/dpp/{id}/registry")).await;
    assert_eq!(resp.status(), 200);
    let view: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(view["configured"], true);
    assert!(
        view.get("registration").is_none(),
        "an unpublished passport owes no registration: {view}"
    );

    let resp = client
        .post_json(&format!("/api/v1/dpp/{id}/publish"), serde_json::json!({}))
        .await;
    assert_eq!(resp.status(), 200, "publish should succeed: {resp:?}");

    // After publish the registration is queued and visible.
    let resp = client.get(&format!("/api/v1/dpp/{id}/registry")).await;
    assert_eq!(resp.status(), 200);
    let view: serde_json::Value = resp.json().await.unwrap();
    let registration = &view["registration"];
    assert_eq!(
        registration["status"], "pending",
        "a freshly published passport owes a registration: {view}"
    );
    assert_eq!(registration["attempts"], 0);
    assert_eq!(
        registration["stalled"], false,
        "nothing has been attempted yet, so nothing is stalled"
    );

    // And the rollup sees it.
    let resp = client.get("/api/v1/registry").await;
    assert_eq!(resp.status(), 200);
    let rollup: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(rollup["configured"], true);
    assert_eq!(rollup["registrations"]["pending"], 1);
    assert_eq!(rollup["registrations"]["registered"], 0);
    assert_eq!(rollup["registrations"]["stalled"], 0);
    // The transfer queue exists and is empty — reported, not omitted.
    assert_eq!(rollup["transfers"]["pending"], 0);
}

/// The commodity code accepted at create is what the passport carries, so the
/// registration built from it can state the product's tariff classification.
#[tokio::test(flavor = "multi_thread")]
async fn a_commodity_code_survives_to_the_passport() {
    let pg = start_postgres().await;
    seed_operator_config(&pg.dal).await;
    let vault_url = start_vault(pg.dal.clone()).await;
    let token = make_jwt("00000000-0000-0000-0000-000000000001");
    let client = TestClient::new(&vault_url, &token);

    let resp = client
        .post_json(
            "/api/v1/dpp",
            serde_json::json!({
                "productName": "Tariff-classified Battery",
                "sector": "battery",
                "manufacturer": { "name": "TestCorp GmbH", "address": "Berlin, DE" },
                "commodityCode": "8507600090"
            }),
        )
        .await;
    assert_eq!(resp.status(), 201);
    let created: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        created["commodityCode"], "8507600090",
        "the TARIC-10 code must round-trip: {created}"
    );
}

/// A malformed tariff code is refused when the draft is created, not months
/// later when the registry rejects the registration.
#[tokio::test(flavor = "multi_thread")]
async fn a_malformed_commodity_code_is_refused_at_create() {
    let pg = start_postgres().await;
    seed_operator_config(&pg.dal).await;
    let vault_url = start_vault(pg.dal.clone()).await;
    let token = make_jwt("00000000-0000-0000-0000-000000000001");
    let client = TestClient::new(&vault_url, &token);

    for bad in ["8507", "8507 60 00", "not-a-code"] {
        let resp = client
            .post_json(
                "/api/v1/dpp",
                serde_json::json!({
                    "productName": "Bad Tariff Code",
                    "sector": "battery",
                    "manufacturer": { "name": "TestCorp GmbH", "address": "Berlin, DE" },
                    "commodityCode": bad
                }),
            )
            .await;
        assert_eq!(
            resp.status(),
            422,
            "commodity code {bad:?} must be refused at create"
        );
    }
}
