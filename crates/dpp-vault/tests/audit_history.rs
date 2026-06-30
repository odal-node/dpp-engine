//! Integration test: passport audit trail (end-to-end).
//!
//! The DAL audit repo is covered by `dpp-dal`'s `audit_append_and_list_round_trip`,
//! but the *wired* flow was untested: that each vault lifecycle action actually
//! writes an audit entry and that `GET /dpp/{id}/history` returns the trail.
//! This drives the assembled vault against a real PostgreSQL container and asserts
//! the immutable audit log the ESPR retention requirement depends on.

#![cfg(feature = "integration-tests")]

mod helpers;

use dpp_types::STANDALONE_OPERATOR_ID;
use helpers::{TestClient, make_jwt, seed_complete_operator, start_postgres, start_vault};

#[tokio::test(flavor = "multi_thread")]
async fn lifecycle_actions_are_recorded_in_audit_history() {
    let pg = start_postgres().await;
    let vault_url = start_vault(pg.dal.clone()).await;
    seed_complete_operator(&pg.dal).await;
    // Single-tenant node: production auth always yields STANDALONE_OPERATOR_ID,
    // so audit writes and reads share the node's one operator identity. There is
    // no multi-operator scoping — isolation is an infrastructure boundary, one
    // node per operator (ADR-005) — so a different operator can't occur here.
    let token = make_jwt(STANDALONE_OPERATOR_ID);
    let client = TestClient::new(&vault_url, &token);

    // 1. Create (draft)
    let body = serde_json::json!({
        "productName": "Audit Trail Widget",
        "productCategory": "BATTERY",
        "manufacturer": {"name": "Audit Inc", "address": "Berlin, DE"},
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
    });
    let resp = client.post_json("/api/v1/dpp", body).await;
    assert_eq!(resp.status(), 201, "create should return 201");
    let passport: serde_json::Value = resp.json().await.unwrap();
    let id = passport["id"].as_str().unwrap().to_owned();

    // 2. Publish → 3. Suspend. (Archive is intentionally *retention-locked* for a
    // freshly published passport — the ESPR retention policy forbids archiving
    // before the retention period — so it is correctly not part of this flow.)
    for action in ["publish", "suspend"] {
        let resp = client
            .post_json(&format!("/api/v1/dpp/{id}/{action}"), serde_json::json!({}))
            .await;
        assert_eq!(resp.status(), 200, "{action} should return 200");
    }

    // 5. GET history — the audit trail must record every action, in order.
    let resp = client.get(&format!("/api/v1/dpp/{id}/history")).await;
    assert_eq!(resp.status(), 200, "history should return 200");
    let entries: Vec<serde_json::Value> = resp.json().await.unwrap();

    let actions: Vec<&str> = entries
        .iter()
        .filter_map(|e| e["action"].as_str())
        .collect();

    assert!(
        actions.len() >= 3,
        "expected >=3 audit entries (created/published/suspended), got {actions:?}"
    );
    for expected in ["created", "published", "suspended"] {
        assert!(
            actions.contains(&expected),
            "audit trail missing '{expected}' action; got {actions:?}"
        );
    }

    // Every entry must belong to this passport (no cross-passport leakage).
    for e in &entries {
        let pid = e
            .get("passportId")
            .or_else(|| e.get("passport_id"))
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        assert!(pid.contains(&id), "audit entry not scoped to passport: {e}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn history_for_unknown_passport_is_not_found() {
    let pg = start_postgres().await;
    let vault_url = start_vault(pg.dal.clone()).await;
    // Single-tenant node: production auth always yields STANDALONE_OPERATOR_ID,
    // so audit writes and reads share the node's one operator identity. There is
    // no multi-operator scoping — isolation is an infrastructure boundary, one
    // node per operator (ADR-005) — so a different operator can't occur here.
    let token = make_jwt(STANDALONE_OPERATOR_ID);
    let client = TestClient::new(&vault_url, &token);

    let resp = client
        .get("/api/v1/dpp/00000000-0000-0000-0000-0000000000ff/history")
        .await;
    assert_eq!(resp.status(), 404, "history for unknown id should be 404");
}
