#![cfg(feature = "integration-tests")]

mod helpers;
use helpers::{
    TestClient, make_jwt, seed_complete_operator, start_postgres, start_vault,
    start_vault_failing_signer,
};

fn op() -> String {
    "00000000-0000-0000-0000-000000000001".to_owned()
}

fn sample() -> serde_json::Value {
    serde_json::json!({
        "productName": "Test Widget",
        "manufacturer": {"name": "ACME Corp", "address": "Berlin, DE"},
        "materials": [],
        "schemaVersion": "1.0.0"
    })
}

const NONEXISTENT: &str = "00000000-0000-0000-0000-000000000099";
const INVALID_UUID: &str = "not-a-valid-uuid";

// ── Invalid UUID (parse_passport_id error path) ──────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn read_invalid_uuid_returns_400() {
    let pg = start_postgres().await;
    let base = start_vault(pg.dal.clone()).await;
    let client = TestClient::new(&base, make_jwt(&op()));
    assert_eq!(
        client
            .get(&format!("/api/v1/dpp/{INVALID_UUID}"))
            .await
            .status(),
        400
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn update_invalid_uuid_returns_400() {
    let pg = start_postgres().await;
    let base = start_vault(pg.dal.clone()).await;
    let client = TestClient::new(&base, make_jwt(&op()));
    assert_eq!(
        client
            .put_json(
                &format!("/api/v1/dpp/{INVALID_UUID}"),
                serde_json::json!({"productName": "X"}),
            )
            .await
            .status(),
        400
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn publish_invalid_uuid_returns_400() {
    let pg = start_postgres().await;
    let base = start_vault(pg.dal.clone()).await;
    let client = TestClient::new(&base, make_jwt(&op()));
    assert_eq!(
        client
            .post_json(
                &format!("/api/v1/dpp/{INVALID_UUID}/publish"),
                serde_json::json!({})
            )
            .await
            .status(),
        400
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn suspend_invalid_uuid_returns_400() {
    let pg = start_postgres().await;
    let base = start_vault(pg.dal.clone()).await;
    let client = TestClient::new(&base, make_jwt(&op()));
    assert_eq!(
        client
            .post_json(
                &format!("/api/v1/dpp/{INVALID_UUID}/suspend"),
                serde_json::json!({})
            )
            .await
            .status(),
        400
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn archive_invalid_uuid_returns_400() {
    let pg = start_postgres().await;
    let base = start_vault(pg.dal.clone()).await;
    let client = TestClient::new(&base, make_jwt(&op()));
    assert_eq!(
        client
            .post_json(
                &format!("/api/v1/dpp/{INVALID_UUID}/archive"),
                serde_json::json!({})
            )
            .await
            .status(),
        400
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn history_invalid_uuid_returns_400() {
    let pg = start_postgres().await;
    let base = start_vault(pg.dal.clone()).await;
    let client = TestClient::new(&base, make_jwt(&op()));
    assert_eq!(
        client
            .get(&format!("/api/v1/dpp/{INVALID_UUID}/history"))
            .await
            .status(),
        400
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn public_read_invalid_uuid_returns_400() {
    let pg = start_postgres().await;
    let base = start_vault(pg.dal.clone()).await;
    let resp = reqwest::get(format!("{base}/public/dpp/{INVALID_UUID}"))
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}

// ── Not-found paths ──────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn read_nonexistent_returns_404() {
    let pg = start_postgres().await;
    let base = start_vault(pg.dal.clone()).await;
    let client = TestClient::new(&base, make_jwt(&op()));
    assert_eq!(
        client
            .get(&format!("/api/v1/dpp/{NONEXISTENT}"))
            .await
            .status(),
        404
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn update_nonexistent_returns_404() {
    let pg = start_postgres().await;
    let base = start_vault(pg.dal.clone()).await;
    let client = TestClient::new(&base, make_jwt(&op()));
    assert_eq!(
        client
            .put_json(
                &format!("/api/v1/dpp/{NONEXISTENT}"),
                serde_json::json!({"productName": "X"}),
            )
            .await
            .status(),
        404
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn publish_nonexistent_returns_404() {
    let pg = start_postgres().await;
    let base = start_vault(pg.dal.clone()).await;
    seed_complete_operator(&pg.dal).await;
    let client = TestClient::new(&base, make_jwt(&op()));
    assert_eq!(
        client
            .post_json(
                &format!("/api/v1/dpp/{NONEXISTENT}/publish"),
                serde_json::json!({})
            )
            .await
            .status(),
        404
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn suspend_nonexistent_returns_404() {
    let pg = start_postgres().await;
    let base = start_vault(pg.dal.clone()).await;
    let client = TestClient::new(&base, make_jwt(&op()));
    assert_eq!(
        client
            .post_json(
                &format!("/api/v1/dpp/{NONEXISTENT}/suspend"),
                serde_json::json!({})
            )
            .await
            .status(),
        404
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn archive_nonexistent_returns_404() {
    let pg = start_postgres().await;
    let base = start_vault(pg.dal.clone()).await;
    let client = TestClient::new(&base, make_jwt(&op()));
    assert_eq!(
        client
            .post_json(
                &format!("/api/v1/dpp/{NONEXISTENT}/archive"),
                serde_json::json!({})
            )
            .await
            .status(),
        404
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn history_nonexistent_returns_404() {
    let pg = start_postgres().await;
    let base = start_vault(pg.dal.clone()).await;
    let client = TestClient::new(&base, make_jwt(&op()));
    assert_eq!(
        client
            .get(&format!("/api/v1/dpp/{NONEXISTENT}/history"))
            .await
            .status(),
        404
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn public_read_nonexistent_returns_404() {
    let pg = start_postgres().await;
    let base = start_vault(pg.dal.clone()).await;
    let resp = reqwest::get(format!("{base}/public/dpp/{NONEXISTENT}"))
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

// ── Invalid state transitions ────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn publish_already_published_returns_409() {
    let pg = start_postgres().await;
    let base = start_vault(pg.dal.clone()).await;
    seed_complete_operator(&pg.dal).await;
    let client = TestClient::new(&base, make_jwt(&op()));
    let id = create_and_publish(&client).await;

    // Published → Published is not a valid state-machine transition.
    let resp = client
        .post_json(&format!("/api/v1/dpp/{id}/publish"), serde_json::json!({}))
        .await;
    assert_eq!(resp.status(), 409);
}

#[tokio::test(flavor = "multi_thread")]
async fn suspend_draft_returns_409() {
    let pg = start_postgres().await;
    let base = start_vault(pg.dal.clone()).await;
    let client = TestClient::new(&base, make_jwt(&op()));

    let resp = client.post_json("/api/v1/dpp", sample()).await;
    let id = resp.json::<serde_json::Value>().await.unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();

    // Draft → Suspended is not a valid transition.
    let resp = client
        .post_json(&format!("/api/v1/dpp/{id}/suspend"), serde_json::json!({}))
        .await;
    assert_eq!(resp.status(), 409);
}

#[tokio::test(flavor = "multi_thread")]
async fn archive_already_archived_returns_409() {
    let pg = start_postgres().await;
    let base = start_vault(pg.dal.clone()).await;
    let client = TestClient::new(&base, make_jwt(&op()));

    let resp = client.post_json("/api/v1/dpp", sample()).await;
    let id = resp.json::<serde_json::Value>().await.unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();

    // Draft → Archived: valid (draft is not retention-locked).
    let r = client
        .post_json(&format!("/api/v1/dpp/{id}/archive"), serde_json::json!({}))
        .await;
    assert_eq!(r.status(), 200, "first archive of a draft should succeed");

    // Archived → Archived: invalid transition.
    let resp = client
        .post_json(&format!("/api/v1/dpp/{id}/archive"), serde_json::json!({}))
        .await;
    assert_eq!(resp.status(), 409);
}

#[tokio::test(flavor = "multi_thread")]
async fn archive_recently_published_returns_422_retention_guard() {
    let pg = start_postgres().await;
    let base = start_vault(pg.dal.clone()).await;
    seed_complete_operator(&pg.dal).await;
    let client = TestClient::new(&base, make_jwt(&op()));
    let id = create_and_publish(&client).await;

    // Published → Archived is a valid state-machine transition, but the ESPR
    // retention guard blocks it because published_at was just set (10-year lock).
    let resp = client
        .post_json(&format!("/api/v1/dpp/{id}/archive"), serde_json::json!({}))
        .await;
    assert_eq!(resp.status(), 422);
}

// ── Public read status-specific responses ────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn public_read_draft_returns_404() {
    let pg = start_postgres().await;
    let base = start_vault(pg.dal.clone()).await;
    let client = TestClient::new(&base, make_jwt(&op()));

    let resp = client.post_json("/api/v1/dpp", sample()).await;
    let id = resp.json::<serde_json::Value>().await.unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();

    let resp = reqwest::get(format!("{base}/public/dpp/{id}"))
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

#[tokio::test(flavor = "multi_thread")]
async fn public_read_suspended_returns_410_gone() {
    let pg = start_postgres().await;
    let base = start_vault(pg.dal.clone()).await;
    seed_complete_operator(&pg.dal).await;
    let client = TestClient::new(&base, make_jwt(&op()));
    let id = create_and_publish(&client).await;

    client
        .post_json(&format!("/api/v1/dpp/{id}/suspend"), serde_json::json!({}))
        .await;

    let resp = reqwest::get(format!("{base}/public/dpp/{id}"))
        .await
        .unwrap();
    assert_eq!(resp.status(), 410);
}

// ── Regression W-1: signing failure must be fail-closed ──────────────────────

/// When the identity service (signer) is unavailable, `POST /publish` must
/// return 5xx and the passport must remain in `draft` status with no
/// `jwsSignature` field.  Before the W-1 fix, the service published unsigned
/// passports (fail-open), which violated the proof-bound invariant and caused
/// the resolver to return 409 on every subsequent GET.
#[tokio::test(flavor = "multi_thread")]
async fn publish_with_failing_signer_returns_5xx_and_passport_stays_draft() {
    let pg = start_postgres().await;
    let base = start_vault_failing_signer(pg.dal.clone()).await;
    seed_complete_operator(&pg.dal).await;
    let client = TestClient::new(&base, make_jwt(&op()));

    // Create a draft — creation does not involve the signer.
    let resp = client.post_json("/api/v1/dpp", sample()).await;
    assert_eq!(
        resp.status(),
        201,
        "create must succeed regardless of signer"
    );
    let id = resp.json::<serde_json::Value>().await.unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();

    // Attempt to publish — the signer is broken, must fail closed.
    let publish_resp = client
        .post_json(&format!("/api/v1/dpp/{id}/publish"), serde_json::json!({}))
        .await;
    assert!(
        publish_resp.status().is_server_error(),
        "publish with broken signer must return 5xx, got {}",
        publish_resp.status()
    );

    // The passport must still be in draft with no JWS signature.
    let get_resp = client.get(&format!("/api/v1/dpp/{id}")).await;
    assert_eq!(get_resp.status(), 200);
    let body: serde_json::Value = get_resp.json().await.unwrap();
    assert_eq!(
        body["status"].as_str().unwrap_or(""),
        "draft",
        "passport must remain draft after failed publish"
    );
    assert!(
        body["jwsSignature"].is_null() || body.get("jwsSignature").is_none(),
        "jwsSignature must be absent/null on a draft passport"
    );
}

// ── Helper ───────────────────────────────────────────────────────────────────

async fn create_and_publish(client: &TestClient) -> String {
    let resp = client.post_json("/api/v1/dpp", sample()).await;
    let id = resp.json::<serde_json::Value>().await.unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    client
        .post_json(&format!("/api/v1/dpp/{id}/publish"), serde_json::json!({}))
        .await;
    id
}
