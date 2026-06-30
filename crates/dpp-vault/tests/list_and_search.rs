#![cfg(feature = "integration-tests")]

mod helpers;
use helpers::{TestClient, make_jwt, seed_complete_operator, start_postgres, start_vault};

fn op() -> String {
    "00000000-0000-0000-0000-000000000001".to_owned()
}

fn sample() -> serde_json::Value {
    serde_json::json!({
        "productName": "Widget Pro",
        "manufacturer": {"name": "ACME Corp", "address": "Berlin, DE"},
        "materials": [],
        "schemaVersion": "1.0.0"
    })
}

#[tokio::test(flavor = "multi_thread")]
async fn list_empty_db_returns_empty_array() {
    let pg = start_postgres().await;
    let base = start_vault(pg.dal.clone()).await;
    let client = TestClient::new(&base, make_jwt(&op()));

    let resp = client.get("/api/v1/dpps").await;
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["dpps"], serde_json::json!([]));
    assert_eq!(body["total"], 0);
    assert_eq!(body["limit"], 20);
    assert_eq!(body["skip"], 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn list_returns_all_created_passports() {
    let pg = start_postgres().await;
    let base = start_vault(pg.dal.clone()).await;
    let client = TestClient::new(&base, make_jwt(&op()));

    client.post_json("/api/v1/dpp", sample()).await;
    client.post_json("/api/v1/dpp", sample()).await;

    let resp = client.get("/api/v1/dpps").await;
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["total"], 2);
    assert_eq!(body["dpps"].as_array().unwrap().len(), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn list_filters_by_status() {
    let pg = start_postgres().await;
    let base = start_vault(pg.dal.clone()).await;
    seed_complete_operator(&pg.dal).await;
    let client = TestClient::new(&base, make_jwt(&op()));

    // Create two drafts, publish one.
    client.post_json("/api/v1/dpp", sample()).await;
    let resp = client.post_json("/api/v1/dpp", sample()).await;
    let id = resp.json::<serde_json::Value>().await.unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    client
        .post_json(&format!("/api/v1/dpp/{id}/publish"), serde_json::json!({}))
        .await;

    let resp = client.get("/api/v1/dpps?status=active").await;
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let items = body["dpps"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["status"], "active");

    let resp = client.get("/api/v1/dpps?status=draft").await;
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["dpps"].as_array().unwrap().len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn list_with_search_query_hits_endpoint() {
    let pg = start_postgres().await;
    let base = start_vault(pg.dal.clone()).await;
    let client = TestClient::new(&base, make_jwt(&op()));

    client
        .post_json(
            "/api/v1/dpp",
            serde_json::json!({
                "productName": "Xenon Laser Module",
                "manufacturer": {"name": "RayTech", "address": "Hamburg, DE"},
                "materials": [],
                "schemaVersion": "1.0.0"
            }),
        )
        .await;

    // The search path must be exercised; result count depends on repo implementation.
    let resp = client.get("/api/v1/dpps?q=xenon").await;
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["dpps"].is_array());
}

#[tokio::test(flavor = "multi_thread")]
async fn list_respects_limit_and_skip() {
    let pg = start_postgres().await;
    let base = start_vault(pg.dal.clone()).await;
    let client = TestClient::new(&base, make_jwt(&op()));

    for _ in 0..3 {
        client.post_json("/api/v1/dpp", sample()).await;
    }

    let resp = client.get("/api/v1/dpps?limit=2&skip=0").await;
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["dpps"].as_array().unwrap().len(), 2);
    assert_eq!(body["limit"], 2);

    let resp = client.get("/api/v1/dpps?limit=2&skip=2").await;
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["dpps"].as_array().unwrap().len(), 1);
    assert_eq!(body["skip"], 2);
}
