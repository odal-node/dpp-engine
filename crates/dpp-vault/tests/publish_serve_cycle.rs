//! The publish → serve cycle, end to end over the real HTTP surface.
//!
//! This exercises the path a consumer actually takes — create, publish, fetch
//! the public view, check the proof against the body it arrived with — which no
//! test covered before. Two defects reached `main` inside it: the public route
//! served the live database row with a publish-time signature attached, and the
//! carrier URL the publisher printed used AI segments the resolver did not
//! mount. Both were invisible to unit tests because neither ever ran the whole
//! sequence.
//!
//! **The invariant under test:** the body served at `/public/dpp/{id}`, minus
//! the proof itself, is byte-identical to the payload that proof was computed
//! over — and stays that way after a legitimate post-publish mutation.
//!
//! The resolver half of the cycle is covered where the routes live, in
//! `dpp-resolver`'s `gs1_digital_link_resolves_every_carrier_ai_shape`. Here we
//! assert the *shape* the publisher emits; that test asserts the same shapes
//! resolve. Together they close the loop without standing up two services.

#![cfg(feature = "integration-tests")]

mod helpers;

use base64::Engine as _;
use helpers::{TestClient, make_jwt, seed_complete_operator, start_postgres, start_vault};
use serde_json::Value;

/// Decode the payload segment of a compact JWS into JSON.
fn jws_payload(jws: &str) -> Value {
    let seg = jws
        .split('.')
        .nth(1)
        .expect("compact JWS has three segments");
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(seg)
        .expect("payload segment is base64url");
    serde_json::from_slice(&bytes).expect("payload segment is JSON")
}

/// The served body must equal the signed payload once the proof — which is
/// absent at signing time by construction — is set aside.
fn assert_body_matches_proof(served: &Value, context: &str) {
    let jws = served["publicJwsSignature"]
        .as_str()
        .unwrap_or_else(|| panic!("{context}: served body carries no publicJwsSignature"));

    let mut body = served.clone();
    body.as_object_mut()
        .expect("served body is an object")
        .remove("publicJwsSignature");

    assert_eq!(
        body,
        jws_payload(jws),
        "{context}: the served body is not what the attached proof was computed over — \
         anyone verifying this response would see a mismatch that is not tampering"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn published_passport_is_served_as_the_payload_its_proof_signed() {
    let pg = start_postgres().await;
    let vault_url = start_vault(pg.dal.clone()).await;
    seed_complete_operator(&pg.dal).await;
    let token = make_jwt("00000000-0000-0000-0000-000000000002");
    let client = TestClient::new(&vault_url, &token);

    // 1. Create — battery carries a GTIN, so publishing produces a GS1 carrier.
    let resp = client
        .post_json(
            "/api/v1/dpp",
            serde_json::json!({
                "productName": "E2E Cycle Pack",
                "productCategory": "BATTERY",
                "manufacturer": { "name": "GreenCell GmbH", "address": "Berlin, DE" },
                "materials": [{ "name": "Lithium", "weightKg": 1.2 }],
                "schemaVersion": "1.0.0",
                "batchId": "LOT-2026-07",
                "sectorData": {
                    "sector": "battery",
                    "gtin": "09506000134352",
                    "batteryChemistry": "LFP",
                    "nominalVoltageV": 48.0,
                    "nominalCapacityAh": 100.0,
                    "expectedLifetimeCycles": 3000,
                    "co2ePerUnitKg": 45.2,
                    "ratedCapacityKwh": 4.8
                }
            }),
        )
        .await;
    assert_eq!(resp.status(), 201, "create failed");
    let created: Value = resp.json().await.unwrap();
    let id = created["id"].as_str().expect("created passport has an id");

    // 2. Publish — signs the full payload and the public view separately.
    let resp = client
        .post_json(&format!("/api/v1/dpp/{id}/publish"), serde_json::json!({}))
        .await;
    assert_eq!(resp.status(), 200, "publish failed");

    // 3. Fetch the public view and check the proof against the body it came with.
    let resp = client.get(&format!("/public/dpp/{id}")).await;
    assert_eq!(resp.status(), 200, "public read failed");
    let served: Value = resp.json().await.unwrap();
    assert_body_matches_proof(&served, "immediately after publish");

    // 4. The carrier must be a GS1 Digital Link the resolver actually mounts.
    //    Publishing a URL nobody can resolve is the failure this pins.
    let carrier = served["qrCodeUrl"]
        .as_str()
        .expect("a published GTIN-bearing passport carries a qrCodeUrl");
    let path = carrier
        .split_once("://")
        .map(|(_, rest)| rest.split_once('/').map_or("", |(_, p)| p))
        .unwrap_or_default();
    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    assert_eq!(
        segments.first(),
        Some(&"01"),
        "carrier is not a GS1 Digital Link: {carrier}"
    );
    assert_eq!(
        segments.get(1).map(|g| g.len()),
        Some(14),
        "GTIN segment is not 14 digits: {carrier}"
    );
    assert!(
        segments.contains(&"21"),
        "carrier omits the AI 21 serial segment: {carrier}"
    );
    // AI 21 values are capped at 20 characters by the GS1 General Specifications.
    let serial = segments
        .iter()
        .position(|s| *s == "21")
        .and_then(|i| segments.get(i + 1))
        .expect("AI 21 is followed by a serial");
    assert!(
        serial.len() <= 20,
        "serial exceeds the GS1 20-character cap: {serial}"
    );

    // 5. A legitimate post-publish mutation must not move the served body away
    //    from its proof. `relint` rewrites `lintResult` and restamps
    //    `assessedAt` on a published passport — exactly the mutation that made
    //    the live-row rendering diverge from the signature it carried.
    let resp = client
        .post_json(&format!("/api/v1/dpp/{id}/lint"), serde_json::json!({}))
        .await;
    assert!(
        resp.status().is_success(),
        "relint on a published passport failed: {}",
        resp.status()
    );

    let resp = client.get(&format!("/public/dpp/{id}")).await;
    assert_eq!(resp.status(), 200, "public read after relint failed");
    let after: Value = resp.json().await.unwrap();
    assert_body_matches_proof(&after, "after a post-publish relint");

    // The published view is frozen: re-linting changes the stored row, never
    // what the public route serves.
    assert_eq!(
        served, after,
        "the public view changed after a post-publish relint — it must serve the \
         payload signed at publish time, not the live row"
    );
}
