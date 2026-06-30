#![cfg(feature = "integration-tests")]

mod helpers;
use helpers::{TestClient, make_jwt, start_postgres, start_vault};

fn op() -> String {
    "00000000-0000-0000-0000-000000000001".to_owned()
}

#[tokio::test(flavor = "multi_thread")]
async fn get_operator_returns_empty_config_on_fresh_db() {
    let pg = start_postgres().await;
    let base = start_vault(pg.dal.clone()).await;
    let client = TestClient::new(&base, make_jwt(&op()));

    let resp = client.get("/api/v1/operator").await;
    assert_eq!(resp.status(), 200);
    // Empty config is always returned (never 404).
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body.is_object());
}

#[tokio::test(flavor = "multi_thread")]
async fn patch_operator_updates_and_round_trips() {
    let pg = start_postgres().await;
    let base = start_vault(pg.dal.clone()).await;
    let client = TestClient::new(&base, make_jwt(&op()));

    let resp = client
        .patch_json(
            "/api/v1/operator",
            serde_json::json!({
                "legalName": "Acme Legal GmbH",
                "address": "Unter den Linden 1, Berlin",
                "country": "DE",
                "contactEmail": "admin@acme.example"
            }),
        )
        .await;
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["legalName"], "Acme Legal GmbH");
    assert_eq!(body["country"], "DE");

    // Verify persisted with a GET.
    let resp = client.get("/api/v1/operator").await;
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["legalName"], "Acme Legal GmbH");
    assert_eq!(body["contactEmail"], "admin@acme.example");
}

#[tokio::test(flavor = "multi_thread")]
async fn patch_operator_is_idempotent() {
    let pg = start_postgres().await;
    let base = start_vault(pg.dal.clone()).await;
    let client = TestClient::new(&base, make_jwt(&op()));

    let patch = serde_json::json!({"legalName": "Same Name", "country": "AT"});
    client.patch_json("/api/v1/operator", patch.clone()).await;
    let resp = client.patch_json("/api/v1/operator", patch).await;
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["legalName"], "Same Name");
}
