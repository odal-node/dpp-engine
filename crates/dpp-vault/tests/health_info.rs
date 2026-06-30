#![cfg(feature = "integration-tests")]

mod helpers;
use helpers::{start_postgres, start_vault};

#[tokio::test(flavor = "multi_thread")]
async fn health_returns_ok_status() {
    let pg = start_postgres().await;
    let base = start_vault(pg.dal.clone()).await;

    let resp = reqwest::get(format!("{base}/health")).await.unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "ok");
    assert!(body["version"].is_string());
}

#[tokio::test(flavor = "multi_thread")]
async fn ready_returns_ok_when_db_connected() {
    let pg = start_postgres().await;
    let base = start_vault(pg.dal.clone()).await;

    let resp = reqwest::get(format!("{base}/ready")).await.unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "ready");
    assert_eq!(body["db"], "ok");
}

#[tokio::test(flavor = "multi_thread")]
async fn info_returns_version_and_features() {
    let pg = start_postgres().await;
    let base = start_vault(pg.dal.clone()).await;

    let resp = reqwest::get(format!("{base}/api/v1/info")).await.unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(
        body["version"].is_string(),
        "version field should be present"
    );
    assert!(body["authMethods"].is_array());
    assert!(body["features"].is_array());
}
