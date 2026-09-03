//! Integration test for suspension lifecycle.

#![cfg(feature = "integration-tests")]

mod helpers;

use helpers::{TestClient, make_jwt, seed_complete_operator, start_postgres, start_vault};

#[tokio::test(flavor = "multi_thread")]
async fn test_suspension_flow() {
    let pg = start_postgres().await;
    let vault_url = start_vault(pg.dal.clone()).await;
    seed_complete_operator(&pg.dal).await;
    let token = make_jwt("00000000-0000-0000-0000-000000000003");
    let client = TestClient::new(&vault_url, &token);

    // 1. Create and publish a DPP
    let body = serde_json::json!({
        "productName": "Suspension Test Product",
        "manufacturer": {"name": "Suspend Inc", "address": "Test"},
        "materials": [{"name": "Nickel", "weightKg": 0.5}],
        "productGroupData": {
            "productGroup": "battery",
            "gtin": "09506000134352",
            "batteryChemistry": "NiMH",
            "batteryType": "portable",
            "nominalVoltageV": 12.0,
            "nominalCapacityAh": 40.0,
            "expectedLifetimeCycles": 1000,
            "co2ePerUnitKg": 20.0
        }
    });

    let resp = client.post_json("/api/v1/dpp", body).await;
    assert_eq!(resp.status(), 201);

    let passport: serde_json::Value = resp.json().await.unwrap();
    let id = passport["id"].as_str().unwrap();

    // Publish it
    let resp = client
        .post_json(&format!("/api/v1/dpp/{id}/publish"), serde_json::json!({}))
        .await;
    assert_eq!(resp.status(), 200);

    // 2. POST /api/v1/dpp/{id}/suspend → 200
    let resp = client
        .post_json(&format!("/api/v1/dpp/{id}/suspend"), serde_json::json!({}))
        .await;
    assert_eq!(resp.status(), 200, "Failed to suspend passport");

    let suspended: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(suspended["status"], "suspended");

    // 3. GET /public/dpp/{id} → 410 Gone
    let resp = client.get(&format!("/public/dpp/{id}")).await;
    assert_eq!(
        resp.status(),
        410,
        "Suspended passport should return 410 Gone"
    );

    // The resolver returns an RFC 7807 Problem (the legacy `error` code field was
    // dropped); the suspension signal is the 410 status plus the `detail` message.
    let error: serde_json::Value = resp.json().await.unwrap();
    assert!(
        error["detail"]
            .as_str()
            .unwrap_or("")
            .to_lowercase()
            .contains("suspended"),
        "Problem detail should indicate suspension, got: {error}"
    );
}

/// An end-of-life passport stays publicly readable.
///
/// Deactivation ends the *product*, not the passport. Core's status doc says a
/// `Deactivated` record "is retained (the DPP outlives the product, EN 18221)",
/// and this node enforces that on the write side by refusing to archive before
/// `retention_until`. ESPR Art. 10(4)(i) is the basis: the passport is to
/// "remain available" for a period corresponding to "at least the expected
/// lifetime of a specific product".
///
/// It used to answer `404`, which made the retained record unreachable and
/// indistinguishable from one that never existed — and a recycler scanning the
/// carrier on a scrapped battery is exactly the reader the requirement is for.
///
/// The contrast with suspension above is the point of putting this here:
/// suspended is `410` (withdrawn, deliberately), deactivated is `200`
/// (retained). Two different facts, two different answers.
#[tokio::test(flavor = "multi_thread")]
async fn a_deactivated_passport_is_still_served_publicly() {
    let pg = start_postgres().await;
    let vault_url = start_vault(pg.dal.clone()).await;
    seed_complete_operator(&pg.dal).await;
    let token = make_jwt("00000000-0000-0000-0000-000000000003");
    let client = TestClient::new(&vault_url, &token);

    let body = serde_json::json!({
        "productName": "End Of Life Product",
        "manufacturer": {"name": "Recycle Inc", "address": "Test"},
        "materials": [{"name": "Nickel", "weightKg": 0.5}],
        "productGroupData": {
            "productGroup": "battery",
            "gtin": "09506000134352",
            "batteryChemistry": "NiMH",
            "batteryType": "portable",
            "nominalVoltageV": 12.0,
            "nominalCapacityAh": 40.0,
            "expectedLifetimeCycles": 1000,
            "co2ePerUnitKg": 20.0
        }
    });
    let resp = client.post_json("/api/v1/dpp", body).await;
    assert_eq!(resp.status(), 201);
    let created: serde_json::Value = resp.json().await.unwrap();
    let id = created["id"].as_str().unwrap().to_owned();

    let resp = client
        .post_json(&format!("/api/v1/dpp/{id}/publish"), serde_json::json!({}))
        .await;
    assert_eq!(resp.status(), 200);

    let resp = client
        .post_json(
            &format!("/api/v1/dpp/{id}/eol"),
            serde_json::json!({"reason": {"kind": "recycled"}}),
        )
        .await;
    assert_eq!(resp.status(), 200, "failed to declare end of life");
    let eol: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(eol["status"], "deactivated");

    let resp = client.get(&format!("/public/dpp/{id}")).await;
    assert_eq!(
        resp.status(),
        200,
        "a retained end-of-life passport must remain publicly readable"
    );

    // And only the public surface: the lens is unchanged by end of life, so a
    // restricted field must not appear just because the product is gone.
    let view: serde_json::Value = resp.json().await.unwrap();
    assert!(
        view.get("publicJwsSignature").is_some(),
        "the public view must still carry its own proof, got {view}"
    );
    assert!(
        view.get("jwsSignature").is_none(),
        "end of life must not widen the lens to the full-view signature, got {view}"
    );
}
