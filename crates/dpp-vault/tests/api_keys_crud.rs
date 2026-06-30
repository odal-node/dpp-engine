#![cfg(feature = "integration-tests")]

mod helpers;
use helpers::{TestClient, make_jwt, start_postgres, start_vault};

fn op() -> String {
    "00000000-0000-0000-0000-000000000001".to_owned()
}

#[tokio::test(flavor = "multi_thread")]
async fn list_returns_empty_on_fresh_db() {
    let pg = start_postgres().await;
    let base = start_vault(pg.dal.clone()).await;
    let client = TestClient::new(&base, make_jwt(&op()));

    let resp = client.get("/api/v1/api-keys").await;
    assert_eq!(resp.status(), 200);
    let keys: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(keys, serde_json::json!([]));
}

#[tokio::test(flavor = "multi_thread")]
async fn create_key_returns_secret_once() {
    let pg = start_postgres().await;
    let base = start_vault(pg.dal.clone()).await;
    let client = TestClient::new(&base, make_jwt(&op()));

    let resp = client
        .post_json("/api/v1/api-keys", serde_json::json!({"name": "ci-token"}))
        .await;
    assert_eq!(resp.status(), 201);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["secret"].as_str().unwrap().starts_with("odal_sk_"));
    assert_eq!(body["key"]["name"], "ci-token");
    assert!(body["key"]["isActive"].as_bool().unwrap());
}

#[tokio::test(flavor = "multi_thread")]
async fn create_then_list_shows_key() {
    let pg = start_postgres().await;
    let base = start_vault(pg.dal.clone()).await;
    let client = TestClient::new(&base, make_jwt(&op()));

    client
        .post_json("/api/v1/api-keys", serde_json::json!({"name": "my-key"}))
        .await;

    let resp = client.get("/api/v1/api-keys").await;
    assert_eq!(resp.status(), 200);
    let keys: Vec<serde_json::Value> = resp.json().await.unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0]["name"], "my-key");
    // Secret is NOT included in listing — only prefix is shown.
    assert!(keys[0].get("secret").is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn delete_key_removes_from_listing() {
    let pg = start_postgres().await;
    let base = start_vault(pg.dal.clone()).await;
    let client = TestClient::new(&base, make_jwt(&op()));

    let resp = client
        .post_json("/api/v1/api-keys", serde_json::json!({"name": "temp-key"}))
        .await;
    let body: serde_json::Value = resp.json().await.unwrap();
    let id = body["key"]["id"].as_str().unwrap();

    let resp = client.delete(&format!("/api/v1/api-keys/{id}")).await;
    assert_eq!(resp.status(), 204);

    let resp = client.get("/api/v1/api-keys").await;
    let keys: Vec<serde_json::Value> = resp.json().await.unwrap();
    assert!(keys.is_empty(), "revoked key should not appear in listing");
}

#[tokio::test(flavor = "multi_thread")]
async fn delete_invalid_uuid_returns_400() {
    let pg = start_postgres().await;
    let base = start_vault(pg.dal.clone()).await;
    let client = TestClient::new(&base, make_jwt(&op()));

    let resp = client.delete("/api/v1/api-keys/not-a-uuid").await;
    assert_eq!(resp.status(), 400);
}

#[tokio::test(flavor = "multi_thread")]
async fn delete_nonexistent_key_returns_404() {
    let pg = start_postgres().await;
    let base = start_vault(pg.dal.clone()).await;
    let client = TestClient::new(&base, make_jwt(&op()));

    let resp = client
        .delete("/api/v1/api-keys/00000000-0000-0000-0000-000000000099")
        .await;
    assert_eq!(resp.status(), 404);
}

#[tokio::test(flavor = "multi_thread")]
async fn create_with_empty_name_returns_422() {
    let pg = start_postgres().await;
    let base = start_vault(pg.dal.clone()).await;
    let client = TestClient::new(&base, make_jwt(&op()));

    let resp = client
        .post_json("/api/v1/api-keys", serde_json::json!({"name": ""}))
        .await;
    assert_eq!(resp.status(), 422);
}
