//! Integration test for operator-identifier retirement (ESPR Art. 13 mirror of
//! the facility retire path): retiring an operator identifier is a soft-delete
//! that preserves the value a published passport stamped by value, records the
//! mutation in the append-only registry-identity audit trail, and frees the
//! scheme+value for re-registration.

#![cfg(feature = "integration-tests")]

mod helpers;

use dpp_dal::pg::sqlx;
use helpers::{TestClient, make_jwt, seed_operator_config, start_postgres, start_vault};
use serde_json::json;

#[tokio::test(flavor = "multi_thread")]
async fn retiring_an_operator_identifier_preserves_passport_provenance_and_audits() {
    let pg = start_postgres().await;
    seed_operator_config(&pg.dal).await;
    let vault_url = start_vault(pg.dal.clone()).await;
    let token = make_jwt("00000000-0000-0000-0000-000000000001");
    let client = TestClient::new(&vault_url, &token);

    // 1. Create a primary operator identifier.
    let resp = client
        .post_json(
            "/api/v1/operator-identifiers",
            json!({ "scheme": "vat", "value": "DE123456789", "isPrimary": true }),
        )
        .await;
    assert_eq!(
        resp.status(),
        201,
        "operator-identifier create should succeed"
    );
    let oid: serde_json::Value = resp.json().await.unwrap();
    let oid_id = oid["id"].as_str().unwrap().to_owned();

    // 2. Create a passport — the primary identifier value is stamped onto it.
    let resp = client
        .post_json(
            "/api/v1/dpp",
            json!({
                "productName": "EcoBattery LFP 3000",
                "manufacturer": { "name": "GreenCell GmbH", "address": "Berlin, DE" },
                "sectorData": {
                    "sector": "battery",
                    "gtin": "09506000134352",
                    "batteryChemistry": "LFP",
                    "nominalVoltageV": 48.0,
                    "nominalCapacityAh": 100.0,
                    "expectedLifetimeCycles": 3000,
                    "co2ePerUnitKg": 45.2
                }
            }),
        )
        .await;
    assert_eq!(resp.status(), 201, "passport create should succeed");
    let created: serde_json::Value = resp.json().await.unwrap();
    let passport_id = created["id"].as_str().unwrap().to_owned();

    // 3. Retire the identifier (DELETE is now a soft-delete).
    let resp = client
        .delete(&format!("/api/v1/operator-identifiers/{oid_id}"))
        .await;
    assert_eq!(resp.status(), 204, "retire should succeed");

    // 4. It disappears from the live listing…
    let resp = client.get("/api/v1/operator-identifiers").await;
    let ids: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        ids.as_array().map(|a| a.len()),
        Some(0),
        "retired identifier must be hidden from the listing"
    );

    // 5. …but the passport that stamped it keeps its provenance.
    let resp = client.get(&format!("/api/v1/dpp/{passport_id}")).await;
    let dpp: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        dpp["operatorIdentifier"], "DE123456789",
        "stamped operator identifier must survive retirement (ESPR Art. 13)"
    );

    // 6. The row is preserved (soft-delete) with retired_at set.
    let is_retired: bool = sqlx::query_scalar(
        "SELECT retired_at IS NOT NULL FROM odal.operator_identifier WHERE id::text = $1",
    )
    .bind(oid_id.as_str())
    .fetch_one(pg.dal.pool())
    .await
    .expect("identifier row must still exist after retirement");
    assert!(is_retired, "identifier row kept with retired_at set");

    // 7. Retiring again is a no-op → 404.
    let resp = client
        .delete(&format!("/api/v1/operator-identifiers/{oid_id}"))
        .await;
    assert_eq!(resp.status(), 404, "second retire must return not-found");

    // 8. The mutation history is recorded append-only: added, then retired.
    let actions: Vec<String> = sqlx::query_scalar(
        "SELECT action FROM odal.registry_identity_audit \
         WHERE entity_type = 'operator_identifier' AND entity_id::text = $1 ORDER BY ts",
    )
    .bind(oid_id.as_str())
    .fetch_all(pg.dal.pool())
    .await
    .unwrap();
    assert_eq!(
        actions,
        vec!["added".to_string(), "retired".to_string()],
        "add + retire must be audited"
    );

    // 9. The same scheme+value can be re-registered after retirement.
    let resp = client
        .post_json(
            "/api/v1/operator-identifiers",
            json!({ "scheme": "vat", "value": "DE123456789" }),
        )
        .await;
    assert_eq!(
        resp.status(),
        201,
        "a retired identifier must be re-registrable"
    );
}
