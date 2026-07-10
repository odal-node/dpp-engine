//! Integration test: the evidence-dossier HTTP API (generate, list, fetch,
//! verify) against a real PostgreSQL container.
//!
//! `MockIdentity` (see `helpers::start_vault`) produces a non-cryptographic
//! fake JWS, so these tests assert the API's *shape* and status codes, not
//! `report.all_verified()` — the Tier-1 `evidence_dossier.rs` suite covers
//! genuine cryptographic verification with real Ed25519 signing.

#![cfg(feature = "integration-tests")]

mod helpers;

use dpp_types::STANDALONE_OPERATOR_ID;
use helpers::{TestClient, make_jwt, seed_complete_operator, start_postgres, start_vault};

fn create_body() -> serde_json::Value {
    serde_json::json!({
        "productName": "Evidence API Widget",
        "productCategory": "BATTERY",
        "manufacturer": {"name": "Evidence API Inc", "address": "Berlin, DE"},
        "materials": [{"name": "Nickel", "weightKg": 0.5}],
        "schemaVersion": "1.0.0",
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

#[tokio::test(flavor = "multi_thread")]
async fn generate_evidence_for_a_draft_passport_is_conflict() {
    let pg = start_postgres().await;
    let vault_url = start_vault(pg.dal.clone()).await;
    seed_complete_operator(&pg.dal).await;
    let token = make_jwt(STANDALONE_OPERATOR_ID);
    let client = TestClient::new(&vault_url, &token);

    let resp = client.post_json("/api/v1/dpp", create_body()).await;
    assert_eq!(resp.status(), 201, "create should return 201");
    let passport: serde_json::Value = resp.json().await.unwrap();
    let id = passport["id"].as_str().unwrap().to_owned();

    let resp = client
        .post_json(&format!("/api/v1/dpp/{id}/evidence"), serde_json::json!({}))
        .await;
    assert_eq!(
        resp.status(),
        409,
        "generating evidence for a draft passport must be a conflict"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn generate_list_fetch_and_verify_round_trip() {
    let pg = start_postgres().await;
    let vault_url = start_vault(pg.dal.clone()).await;
    seed_complete_operator(&pg.dal).await;
    let token = make_jwt(STANDALONE_OPERATOR_ID);
    let client = TestClient::new(&vault_url, &token);

    let resp = client.post_json("/api/v1/dpp", create_body()).await;
    assert_eq!(resp.status(), 201);
    let passport: serde_json::Value = resp.json().await.unwrap();
    let id = passport["id"].as_str().unwrap().to_owned();

    let resp = client
        .post_json(&format!("/api/v1/dpp/{id}/publish"), serde_json::json!({}))
        .await;
    assert_eq!(resp.status(), 200, "publish should return 200");

    // POST generate — 201, envelope carries id/passportId/actor/docHash/dossier.
    let resp = client
        .post_json(&format!("/api/v1/dpp/{id}/evidence"), serde_json::json!({}))
        .await;
    assert_eq!(resp.status(), 201, "generate evidence should return 201");
    let record: serde_json::Value = resp.json().await.unwrap();
    let dossier_id = record["id"].as_str().unwrap().to_owned();
    assert_eq!(record["passportId"].as_str().unwrap(), id);
    assert!(record["docHash"].as_str().is_some());
    assert!(record["dossier"]["manifest"].is_object());

    // GET list — one summary, no document body.
    let resp = client.get(&format!("/api/v1/dpp/{id}/evidence")).await;
    assert_eq!(resp.status(), 200, "list evidence should return 200");
    let summaries: Vec<serde_json::Value> = resp.json().await.unwrap();
    assert_eq!(summaries.len(), 1);
    assert_eq!(summaries[0]["id"].as_str().unwrap(), dossier_id);
    assert!(
        summaries[0].get("dossier").is_none(),
        "summaries must not carry the full document"
    );

    // GET the stored document by dossier id.
    let resp = client.get(&format!("/api/v1/evidence/{dossier_id}")).await;
    assert_eq!(resp.status(), 200, "get evidence should return 200");
    let dossier: serde_json::Value = resp.json().await.unwrap();
    assert!(dossier["manifest"].is_object());
    assert_eq!(dossier["manifest"]["passportId"].as_str().unwrap(), id);

    // POST verify (stored) — 200 with a well-shaped report, regardless of
    // whether MockIdentity's fake JWS passes every check.
    let resp = client
        .post_json(
            &format!("/api/v1/evidence/{dossier_id}/verify"),
            serde_json::json!({}),
        )
        .await;
    assert_eq!(
        resp.status(),
        200,
        "verify stored dossier should return 200"
    );
    let report: serde_json::Value = resp.json().await.unwrap();
    assert!(report["trustAnchorNote"].as_str().is_some());
    let checks = report["checks"].as_array().expect("checks array");
    assert!(!checks.is_empty());
    assert!(
        checks
            .iter()
            .any(|c| c["name"].as_str() == Some("audit_chain")),
        "expected an audit_chain check in the report"
    );

    // POST verify (uploaded) with the same document — 200, same shape.
    let resp = client.post_json("/api/v1/evidence/verify", dossier).await;
    assert_eq!(
        resp.status(),
        200,
        "verify uploaded dossier should return 200"
    );
    let uploaded_report: serde_json::Value = resp.json().await.unwrap();
    assert!(uploaded_report["checks"].as_array().is_some());

    // POST verify (uploaded) with garbage — 422.
    let resp = client
        .post_json(
            "/api/v1/evidence/verify",
            serde_json::json!({"not": "a dossier"}),
        )
        .await;
    assert_eq!(
        resp.status(),
        422,
        "verifying a non-dossier document must be a hard error"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn evidence_endpoints_404_for_unknown_ids() {
    let pg = start_postgres().await;
    let vault_url = start_vault(pg.dal.clone()).await;
    let token = make_jwt(STANDALONE_OPERATOR_ID);
    let client = TestClient::new(&vault_url, &token);

    let resp = client
        .post_json(
            "/api/v1/dpp/00000000-0000-0000-0000-0000000000ff/evidence",
            serde_json::json!({}),
        )
        .await;
    assert_eq!(resp.status(), 404, "generate for unknown passport is 404");

    let resp = client
        .get("/api/v1/dpp/00000000-0000-0000-0000-0000000000ff/evidence")
        .await;
    assert_eq!(resp.status(), 404, "list for unknown passport is 404");

    let resp = client
        .get("/api/v1/evidence/00000000-0000-0000-0000-0000000000ff")
        .await;
    assert_eq!(resp.status(), 404, "get for unknown dossier is 404");

    let resp = client
        .post_json(
            "/api/v1/evidence/00000000-0000-0000-0000-0000000000ff/verify",
            serde_json::json!({}),
        )
        .await;
    assert_eq!(resp.status(), 404, "verify for unknown dossier is 404");
}
