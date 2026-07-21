//! Integration test for `GET /api/v1/dpp/by-identity` — the exact compound
//! identity lookup (sector, GTIN, batch) the import delta-matcher relies on.
//!
//! Regression coverage for a real bug: the handler existed but was never
//! mounted in `dpp-vault`'s router. `dpp-dal`'s `pg_integration` suite tests
//! `PgPassportRepo::find_by_identity` at the repository layer only, bypassing
//! the HTTP/router/auth-middleware stack entirely — exactly why the
//! route-mounting bug went unnoticed. This drives the real router over HTTP.

#![cfg(feature = "integration-tests")]

mod helpers;
use helpers::{TestClient, make_jwt, start_postgres, start_vault};

fn op() -> String {
    "00000000-0000-0000-0000-000000000001".to_owned()
}

fn battery_passport(gtin: &str) -> serde_json::Value {
    serde_json::json!({
        "productName": "EcoBattery LFP 3000",
        "productCategory": "BATTERY",
        "manufacturer": {
            "name": "GreenCell GmbH",
            "address": "Prenzlauer Berg, Berlin, DE"
        },
        "materials": [
            {"name": "Lithium Iron Phosphate", "weightKg": 1.2}
        ],
        "schemaVersion": "1.0.0",
        "sectorData": {
            "sector": "battery",
            "gtin": gtin,
            "batteryChemistry": "LFP",
            "nominalVoltageV": 48.0,
            "nominalCapacityAh": 100.0,
            "expectedLifetimeCycles": 3000,
            "co2ePerUnitKg": 45.2
        }
    })
}

#[tokio::test(flavor = "multi_thread")]
async fn by_identity_finds_the_matching_draft() {
    let pg = start_postgres().await;
    let base = start_vault(pg.dal.clone()).await;
    let client = TestClient::new(&base, make_jwt(&op()));

    let resp = client
        .post_json("/api/v1/dpp", battery_passport("09506000134352"))
        .await;
    assert_eq!(resp.status(), 201, "failed to create battery passport");
    let created: serde_json::Value = resp.json().await.expect("parse create response");
    let id = created["id"].as_str().expect("id missing").to_owned();

    let resp = client
        .get("/api/v1/dpp/by-identity?sector=battery&gtin=09506000134352")
        .await;
    assert_eq!(resp.status(), 200, "the route must be reachable, not 404");
    let found: serde_json::Value = resp.json().await.expect("parse by-identity response");
    assert_eq!(
        found["id"], id,
        "must return the exact passport that matches"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn by_identity_returns_404_when_nothing_matches() {
    let pg = start_postgres().await;
    let base = start_vault(pg.dal.clone()).await;
    let client = TestClient::new(&base, make_jwt(&op()));

    client
        .post_json("/api/v1/dpp", battery_passport("09506000134352"))
        .await;

    // Same sector, a GTIN that was never created.
    let resp = client
        .get("/api/v1/dpp/by-identity?sector=battery&gtin=00000000000000")
        .await;
    assert_eq!(resp.status(), 404, "no passport matches this identity");
}
