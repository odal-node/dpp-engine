//! Integration test for facility retirement (solution A): retiring a facility is
//! a soft-delete that preserves the ESPR Annex III provenance a published
//! passport stamped by value, records the mutation in the append-only
//! registry-identity audit trail, and frees the identifier for re-registration.

#![cfg(feature = "integration-tests")]

mod helpers;

use dpp_dal::pg::sqlx;
use helpers::{TestClient, make_jwt, seed_operator_config, start_postgres, start_vault};
use serde_json::json;

#[tokio::test(flavor = "multi_thread")]
async fn retiring_a_facility_preserves_passport_provenance_and_audits() {
    let pg = start_postgres().await;
    seed_operator_config(&pg.dal).await;
    let vault_url = start_vault(pg.dal.clone()).await;
    let token = make_jwt("00000000-0000-0000-0000-000000000001");
    let client = TestClient::new(&vault_url, &token);

    // 1. Create a default facility.
    let resp = client
        .post_json(
            "/api/v1/facilities",
            json!({
                "name": "Default Plant",
                "identifierScheme": "gln",
                "identifierValue": "4012345000009",
                "country": "DE",
                "isDefault": true
            }),
        )
        .await;
    assert_eq!(resp.status(), 201, "facility create should succeed");
    let facility: serde_json::Value = resp.json().await.unwrap();
    let facility_id = facility["id"].as_str().unwrap().to_owned();

    // 2. Create a passport — the default facility identifier is stamped onto it.
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

    // 3. Retire the facility (DELETE is now a soft-delete).
    let resp = client
        .delete(&format!("/api/v1/facilities/{facility_id}"))
        .await;
    assert_eq!(resp.status(), 204, "retire should succeed");

    // 4. It disappears from the live listing…
    let resp = client.get("/api/v1/facilities").await;
    let facilities: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        facilities.as_array().map(|a| a.len()),
        Some(0),
        "retired facility must be hidden from the listing"
    );

    // 5. …but the passport that stamped it keeps its provenance — no dangling loss.
    let resp = client.get(&format!("/api/v1/dpp/{passport_id}")).await;
    let dpp: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        dpp["facility"]["value"], "4012345000009",
        "stamped facility identifier must survive retirement (ESPR Annex III)"
    );
    assert_eq!(
        dpp["facility"]["name"], "Default Plant",
        "the full facility snapshot (name/country/…) survives retirement, not just the id"
    );

    // 6. The row is preserved (soft-delete, not destroyed) with retired_at set.
    // fetch_one succeeds only if the row still exists; the bool proves it's retired.
    let is_retired: bool =
        sqlx::query_scalar("SELECT retired_at IS NOT NULL FROM odal.facility WHERE id::text = $1")
            .bind(facility_id.as_str())
            .fetch_one(pg.dal.pool())
            .await
            .expect("facility row must still exist after retirement");
    assert!(is_retired, "facility row kept with retired_at set");

    // 7. Retiring again is a no-op → 404 (no live facility with that id).
    let resp = client
        .delete(&format!("/api/v1/facilities/{facility_id}"))
        .await;
    assert_eq!(resp.status(), 404, "second retire must return not-found");

    // 8. The mutation history is recorded append-only: added, then retired.
    let actions: Vec<String> = sqlx::query_scalar(
        "SELECT action FROM odal.registry_identity_audit \
         WHERE entity_type = 'facility' AND entity_id::text = $1 ORDER BY ts",
    )
    .bind(facility_id.as_str())
    .fetch_all(pg.dal.pool())
    .await
    .unwrap();
    assert_eq!(
        actions,
        vec!["added".to_string(), "retired".to_string()],
        "add + retire must be audited"
    );

    // 9. The same GLN can be re-registered after retirement (partial unique index
    //    scoped to live rows).
    let resp = client
        .post_json(
            "/api/v1/facilities",
            json!({
                "name": "Replacement Plant",
                "identifierScheme": "gln",
                "identifierValue": "4012345000009",
                "country": "DE"
            }),
        )
        .await;
    assert_eq!(
        resp.status(),
        201,
        "a retired identifier must be re-registrable"
    );
}
