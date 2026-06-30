//! N-2 live PoC: API-key scope enforcement against a real Postgres-backed vault.
//!
//! Proves end-to-end that a least-privilege (`write`) credential cannot escalate
//! to administrative actions — it can neither mint API keys (persistence) nor
//! revoke them (lockout) nor mutate operator config — while an `admin`
//! credential can. The final round-trip also proves the `scopes` column persists
//! and reads back correctly through Postgres (the path that was previously only
//! "verified by construction").

#![cfg(feature = "integration-tests")]

mod helpers;

use helpers::{TestClient, make_jwt, make_jwt_scoped, start_postgres, start_vault};
use serde_json::json;

#[tokio::test(flavor = "multi_thread")]
async fn write_scoped_credential_cannot_escalate() {
    let pg = start_postgres().await;
    let vault_url = start_vault(pg.dal.clone()).await;

    // The attacker holds a leaked least-privilege (write) key.
    let attacker = TestClient::new(&vault_url, &make_jwt_scoped("op", "write"));

    // 1) Persistence: cannot mint a new key.
    let mint = attacker
        .post_json("/api/v1/api-keys", json!({ "name": "persistence" }))
        .await;
    assert_eq!(
        mint.status(),
        403,
        "write-scoped credential must NOT be able to mint API keys"
    );

    // 2) Reconnaissance: cannot list keys.
    let list = attacker.get("/api/v1/api-keys").await;
    assert_eq!(
        list.status(),
        403,
        "write-scoped credential must NOT list keys"
    );

    // 3) Lockout: cannot revoke a key.
    let revoke = attacker
        .delete("/api/v1/api-keys/00000000-0000-4000-8000-000000000000")
        .await;
    assert_eq!(
        revoke.status(),
        403,
        "write-scoped credential must NOT revoke keys"
    );

    // 4) Tamper: cannot mutate operator config. (Empty merge-patch body so the
    // request reaches the handler's scope check rather than failing JSON
    // extraction first.)
    let patch = attacker.patch_json("/api/v1/operator", json!({})).await;
    assert_eq!(
        patch.status(),
        403,
        "write-scoped credential must NOT mutate operator config"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn admin_can_mint_least_privilege_key_and_scope_round_trips() {
    let pg = start_postgres().await;
    let vault_url = start_vault(pg.dal.clone()).await;
    let admin = TestClient::new(&vault_url, &make_jwt("op"));

    // Admin mints a least-privilege integration key (the recommended posture).
    let create = admin
        .post_json(
            "/api/v1/api-keys",
            json!({ "name": "partner-integration", "scope": "write" }),
        )
        .await;
    assert_eq!(create.status(), 201, "admin must be able to mint keys");

    // The scope must survive a Postgres round-trip: list and confirm it reads
    // back as "write" (validates the `scopes TEXT[]` read/write path live).
    let list = admin.get("/api/v1/api-keys").await;
    assert_eq!(list.status(), 200);
    let keys: serde_json::Value = list.json().await.unwrap();
    let found = keys
        .as_array()
        .expect("array of keys")
        .iter()
        .find(|k| k["name"] == "partner-integration")
        .expect("created key present in listing");
    assert_eq!(
        found["scope"], "write",
        "scope must persist and read back through Postgres"
    );
}
