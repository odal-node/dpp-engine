//! Integration tests for authentication and authorization.

#![cfg(feature = "integration-tests")]

mod helpers;

use helpers::{TestClient, make_expired_jwt, make_jwt, start_postgres, start_vault};

#[tokio::test(flavor = "multi_thread")]
async fn test_jwt_valid() {
    let pg = start_postgres().await;
    let vault_url = start_vault(pg.dal.clone()).await;
    let token = make_jwt("00000000-0000-0000-0000-000000000010");
    let client = TestClient::new(&vault_url, &token);

    let body = serde_json::json!({
        "productName": "Auth Test Product",
        "productCategory": "BATTERY",
        "manufacturer": {"name": "Auth Inc", "address": "Auth City"},
        "materials": [{"name": "Steel", "weightKg": 1.0}],
        "schemaVersion": "1.0.0"
    });

    let resp = client.post_json("/api/v1/dpp", body).await;
    assert_eq!(
        resp.status(),
        201,
        "Valid JWT should allow passport creation"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_jwt_expired() {
    let pg = start_postgres().await;
    let vault_url = start_vault(pg.dal.clone()).await;
    let expired_token = make_expired_jwt("00000000-0000-0000-0000-000000000011");
    let client = TestClient::new(&vault_url, &expired_token);

    let body = serde_json::json!({
        "productName": "Expired Token Product",
        "productCategory": "BATTERY",
        "manufacturer": {"name": "Exp Inc", "address": "Exp City"},
        "materials": [{"name": "Copper", "weightKg": 0.5}],
        "schemaVersion": "1.0.0"
    });

    let resp = client.post_json("/api/v1/dpp", body).await;
    assert_eq!(resp.status(), 401, "Expired JWT should return 401");
}

#[tokio::test(flavor = "multi_thread")]
async fn test_no_auth() {
    let pg = start_postgres().await;
    let vault_url = start_vault(pg.dal.clone()).await;
    let client = TestClient::new(&vault_url, "");

    let body = serde_json::json!({
        "productName": "No Auth Product",
        "productCategory": "BATTERY",
        "manufacturer": {"name": "NoAuth Inc", "address": "NoAuth City"},
        "materials": [{"name": "Aluminum", "weightKg": 2.0}],
        "schemaVersion": "1.0.0"
    });

    let resp = client.post_no_auth("/api/v1/dpp", body).await;
    assert_eq!(resp.status(), 401, "Missing auth should return 401");
}
