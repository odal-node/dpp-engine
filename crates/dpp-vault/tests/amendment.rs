//! Integration test for amending a published passport.
//!
//! The merge gate for the version chain. A published passport is immutable, so
//! correcting one issues a successor and supersedes the predecessor; these
//! assertions are the difference between that and an in-place edit, which is the
//! thing the retention guard exists to refuse.

#![cfg(feature = "integration-tests")]

mod helpers;

use helpers::{TestClient, make_jwt, seed_complete_operator, start_postgres, start_vault};

/// A battery draft body, parameterised by the one field the amendment changes.
fn draft(product_name: &str) -> serde_json::Value {
    serde_json::json!({
        "productName": product_name,
        "manufacturer": {"name": "Amend Inc", "address": "Test"},
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
    })
}

#[tokio::test(flavor = "multi_thread")]
async fn amending_a_published_passport_issues_a_successor() {
    let pg = start_postgres().await;
    let vault_url = start_vault(pg.dal.clone()).await;
    seed_complete_operator(&pg.dal).await;
    let token = make_jwt("00000000-0000-0000-0000-000000000003");
    let client = TestClient::new(&vault_url, &token);

    // ── Publish the predecessor ──────────────────────────────────────────
    let resp = client
        .post_json("/api/v1/dpp", draft("Original Battery"))
        .await;
    assert_eq!(resp.status(), 201);
    let created: serde_json::Value = resp.json().await.unwrap();
    let original_id = created["id"].as_str().unwrap().to_owned();

    let resp = client
        .post_json(
            &format!("/api/v1/dpp/{original_id}/publish"),
            serde_json::json!({}),
        )
        .await;
    assert_eq!(resp.status(), 200);
    let published: serde_json::Value = resp.json().await.unwrap();
    let original_signature = published["jwsSignature"].as_str().unwrap().to_owned();
    assert_eq!(published["version"], 1, "a first publish is version 1");

    // ── Amend ────────────────────────────────────────────────────────────
    let resp = client
        .post_json(
            &format!("/api/v1/dpp/{original_id}/amend"),
            serde_json::json!({
                "patch": { "productName": "Corrected Battery" },
                "reason": "Product name restated after supplier re-declaration"
            }),
        )
        .await;
    let status = resp.status();
    let body = resp.text().await.unwrap();
    assert_eq!(status, 201, "amend should create a successor: {body}");
    let successor: serde_json::Value = serde_json::from_str(&body).unwrap();
    let successor_id = successor["id"].as_str().unwrap().to_owned();

    // The response is a *different* passport from the one in the path.
    assert_ne!(
        successor_id, original_id,
        "the successor takes a new id — `supersedes_id` is a self-FK onto `id`, \
         so it could not share one"
    );
    assert_eq!(successor["version"], 2, "the successor increments version");
    assert_eq!(
        successor["supersedesId"], original_id,
        "the successor points back at what it replaces"
    );
    assert_eq!(successor["status"], "active");
    assert_eq!(successor["productName"], "Corrected Battery");

    // The successor is separately signed. Sharing the predecessor's signature
    // would produce a passport that fails its own verification.
    let successor_signature = successor["jwsSignature"].as_str().unwrap();
    assert_ne!(
        successor_signature, original_signature,
        "the successor must carry its own signature over its own bytes"
    );

    // The schema version is inherited, not advanced — an amendment corrects
    // content, and the disclosure classes are read from the schema version.
    assert_eq!(
        successor["schemaVersion"], published["schemaVersion"],
        "an amendment must not silently migrate the passport's schema version"
    );

    // ── The predecessor ──────────────────────────────────────────────────
    let resp = client.get(&format!("/api/v1/dpp/{original_id}")).await;
    assert_eq!(
        resp.status(),
        200,
        "a superseded passport stays readable by its own id — superseding \
         withdraws it from being current, never from being readable"
    );
    let predecessor: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(predecessor["status"], "superseded");
    assert_eq!(
        predecessor["jwsSignature"], original_signature,
        "the predecessor keeps the signature it was published with — the \
         retention guard must not have been bypassed"
    );
    assert_eq!(
        predecessor["productName"], "Original Battery",
        "the predecessor's content is unchanged; the correction lives on the successor"
    );
    assert_eq!(predecessor["version"], 1);

    // ── The audit trail records why, and points at the successor ─────────
    let resp = client
        .get(&format!("/api/v1/dpp/{original_id}/history"))
        .await;
    assert_eq!(resp.status(), 200);
    let history: Vec<serde_json::Value> = resp.json().await.unwrap();
    let superseded_entry = history
        .iter()
        .find(|e| e["action"] == "superseded")
        .expect("supersession is recorded in the audit trail");
    assert_eq!(
        superseded_entry["metadata"]["successorId"], successor_id,
        "a reader arriving at the old record can find what replaced it"
    );
    assert_eq!(
        superseded_entry["metadata"]["reason"],
        "Product name restated after supplier re-declaration"
    );

    // ── A superseded passport is terminal ────────────────────────────────
    let resp = client
        .post_json(
            &format!("/api/v1/dpp/{original_id}/amend"),
            serde_json::json!({ "patch": { "productName": "Third Attempt" } }),
        )
        .await;
    assert_eq!(
        resp.status(),
        409,
        "a superseded passport cannot be superseded again — corrections chain \
         from the head, not from an arbitrary link"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_draft_cannot_be_amended() {
    let pg = start_postgres().await;
    let vault_url = start_vault(pg.dal.clone()).await;
    seed_complete_operator(&pg.dal).await;
    let token = make_jwt("00000000-0000-0000-0000-000000000003");
    let client = TestClient::new(&vault_url, &token);

    let resp = client
        .post_json("/api/v1/dpp", draft("Draft Battery"))
        .await;
    assert_eq!(resp.status(), 201);
    let created: serde_json::Value = resp.json().await.unwrap();
    let id = created["id"].as_str().unwrap();

    let resp = client
        .post_json(
            &format!("/api/v1/dpp/{id}/amend"),
            serde_json::json!({ "patch": { "productName": "Nope" } }),
        )
        .await;
    assert_eq!(
        resp.status(),
        409,
        "a draft is edited in place with PUT — issuing a successor to an \
         unpublished record would leave a version chain rooted in nothing"
    );

    // And the draft is untouched by the refusal.
    let resp = client.get(&format!("/api/v1/dpp/{id}")).await;
    let after: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(after["productName"], "Draft Battery");
    assert_eq!(after["status"], "draft");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refused_amendment_leaves_the_predecessor_live() {
    let pg = start_postgres().await;
    let vault_url = start_vault(pg.dal.clone()).await;
    seed_complete_operator(&pg.dal).await;
    let token = make_jwt("00000000-0000-0000-0000-000000000003");
    let client = TestClient::new(&vault_url, &token);

    let resp = client.post_json("/api/v1/dpp", draft("Live Battery")).await;
    assert_eq!(resp.status(), 201);
    let created: serde_json::Value = resp.json().await.unwrap();
    let id = created["id"].as_str().unwrap().to_owned();

    let resp = client
        .post_json(&format!("/api/v1/dpp/{id}/publish"), serde_json::json!({}))
        .await;
    assert_eq!(resp.status(), 200);

    // A correction the publish gates refuse: a chemistry the product-group
    // schema does not admit.
    let resp = client
        .post_json(
            &format!("/api/v1/dpp/{id}/amend"),
            serde_json::json!({
                "patch": {
                    "productGroupData": {
                        "productGroup": "battery",
                        "gtin": "09506000134352",
                        "batteryChemistry": "NiMH",
                        "batteryType": "not-a-battery-type",
                        "nominalVoltageV": 12.0,
                        "nominalCapacityAh": 40.0,
                        "expectedLifetimeCycles": 1000,
                        "co2ePerUnitKg": 20.0
                    }
                }
            }),
        )
        .await;
    assert!(
        resp.status() == 422 || resp.status() == 400,
        "an invalid correction is refused, got {}",
        resp.status()
    );

    // This is the reason the predecessor is superseded last: a refused
    // amendment must leave the product with a live passport, not none.
    let resp = client.get(&format!("/api/v1/dpp/{id}")).await;
    let after: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        after["status"], "active",
        "a refused amendment must not have superseded anything"
    );
    assert_eq!(after["productName"], "Live Battery");
}
