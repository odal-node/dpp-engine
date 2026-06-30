//! Integration tests for `dpp-vault`.
//!
//! Run with:
//! ```sh
//! cargo test -p dpp-vault --features integration-tests -- --nocapture
//! ```
//!
//! Requires Docker — each test spins up a fresh PostgreSQL container via
//! testcontainers, applies migrations, and starts the vault Axum server on a
//! random port.

#![cfg(feature = "integration-tests")]

mod helpers;

use helpers::{TestClient, make_jwt, seed_complete_operator, start_postgres, start_vault};

fn operator_a() -> String {
    "00000000-0000-0000-0000-000000000001".to_owned()
}

fn sample_passport() -> serde_json::Value {
    serde_json::json!({
        "productName": "Eco Battery Pack",
        "productCategory": "BATTERY",
        "manufacturer": {
            "name": "GreenCell GmbH",
            "address": "Berlin, DE"
        },
        "materials": [
            {"name": "Lithium", "weightKg": 0.8}
        ],
        "schemaVersion": "1.0.0",
        // Publish-time validation (1.3) requires valid sector data.
        "sectorData": {
            "sector": "battery",
            "gtin": "09506000134352",
            "batteryChemistry": "NiMH",
            "nominalVoltageV": 12.0,
            "nominalCapacityAh": 40.0,
            "expectedLifetimeCycles": 1000,
            "co2ePerUnitKg": 20.0
        }
    })
}

// ---------------------------------------------------------------------------
// Round-trip: create → read
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn create_then_read_round_trip() {
    let pg = start_postgres().await;
    let base_url = start_vault(pg.dal.clone()).await;
    let token = make_jwt(&operator_a());
    let client = TestClient::new(&base_url, &token);

    let resp = client.post_json("/api/v1/dpp", sample_passport()).await;
    assert_eq!(resp.status(), 201, "create should return 201");

    let created: serde_json::Value = resp.json().await.unwrap();
    let id = created["id"].as_str().expect("response should contain id");
    assert_eq!(created["productName"], "Eco Battery Pack");
    assert_eq!(created["status"], "draft");

    let resp = client.get(&format!("/api/v1/dpp/{id}")).await;
    assert_eq!(resp.status(), 200, "read should return 200");

    let fetched: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(fetched["id"], id);
    assert_eq!(fetched["productName"], "Eco Battery Pack");
}

// ---------------------------------------------------------------------------
// Publish flow
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn publish_sets_status_and_jws_signature() {
    let pg = start_postgres().await;
    let base_url = start_vault(pg.dal.clone()).await;
    seed_complete_operator(&pg.dal).await;
    let token = make_jwt(&operator_a());
    let client = TestClient::new(&base_url, &token);

    let resp = client.post_json("/api/v1/dpp", sample_passport()).await;
    assert_eq!(resp.status(), 201);

    let created: serde_json::Value = resp.json().await.unwrap();
    let id = created["id"].as_str().unwrap();

    let resp = client
        .post_json(&format!("/api/v1/dpp/{id}/publish"), serde_json::json!({}))
        .await;
    assert_eq!(resp.status(), 200, "publish should return 200");

    let published: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(published["status"], "active");
    assert!(
        published["jwsSignature"].is_string(),
        "jwsSignature should be set after publishing"
    );
    assert!(
        published["qrCodeUrl"].is_string(),
        "qrCodeUrl should be set after publishing"
    );
}

// ---------------------------------------------------------------------------
// Invalid state transitions
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn cannot_update_published_passport() {
    let pg = start_postgres().await;
    let base_url = start_vault(pg.dal.clone()).await;
    seed_complete_operator(&pg.dal).await;
    let token = make_jwt(&operator_a());
    let client = TestClient::new(&base_url, &token);

    let resp = client.post_json("/api/v1/dpp", sample_passport()).await;
    assert_eq!(resp.status(), 201);

    let created: serde_json::Value = resp.json().await.unwrap();
    let id = created["id"].as_str().unwrap();

    let resp = client
        .post_json(&format!("/api/v1/dpp/{id}/publish"), serde_json::json!({}))
        .await;
    assert_eq!(resp.status(), 200, "publish should succeed");

    let resp = client
        .put_json(
            &format!("/api/v1/dpp/{id}"),
            serde_json::json!({"productName": "Tampered Name"}),
        )
        .await;
    assert_eq!(
        resp.status(),
        409,
        "updating a published passport should return 409 CONFLICT"
    );
}

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn unauthenticated_request_returns_401() {
    let pg = start_postgres().await;
    let base_url = start_vault(pg.dal.clone()).await;

    let resp = reqwest::Client::new()
        .get(format!("{base_url}/api/v1/dpps"))
        .send()
        .await
        .expect("HTTP request failed");

    assert_eq!(resp.status(), 401, "missing token should return 401");
}
