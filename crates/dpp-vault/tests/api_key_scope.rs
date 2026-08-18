//! Live PoC: API-key scope enforcement against a real Postgres-backed vault.
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
    let attacker = TestClient::new(&vault_url, make_jwt_scoped("op", "write"));

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
async fn read_scoped_credential_cannot_mutate_passports() {
    let pg = start_postgres().await;
    let vault_url = start_vault(pg.dal.clone()).await;

    // A least-privilege read-only key (documented for GET-only integrations).
    let reader = TestClient::new(&vault_url, make_jwt_scoped("op", "read"));
    let id = "00000000-0000-4000-8000-000000000000";

    // Every passport-lifecycle mutation must reject a Read-scoped credential with
    // 403 — the `can_write()` gate runs first, before any state change. Bodies are
    // valid so each request reaches the handler rather than failing extraction.
    let create = reader
        .post_json(
            "/api/v1/dpp",
            json!({ "productName": "x", "manufacturer": { "name": "n", "address": "a" } }),
        )
        .await;
    assert_eq!(create.status(), 403, "create must require write scope");

    let update = reader
        .put_json(&format!("/api/v1/dpp/{id}"), json!({}))
        .await;
    assert_eq!(update.status(), 403, "update must require write scope");

    // publish / suspend / archive / transfer-accept take no request body of their
    // own; eol and transfer-initiate share the identical first-line gate.
    for path in [
        format!("/api/v1/dpp/{id}/publish"),
        format!("/api/v1/dpp/{id}/suspend"),
        format!("/api/v1/dpp/{id}/archive"),
        format!("/api/v1/dpp/{id}/transfer/accept"),
        // `lint` persists a recomputed `lintResult` via `patch_fields` — a
        // database write on any passport the caller can name, and one that
        // appends no audit entry, so a read key mutating through it left no
        // trace at all. `evidence` inserts into an append-only table the app
        // role cannot DELETE from, and drives the transfer-chain DID fetches.
        // Both read like queries and are not.
        format!("/api/v1/dpp/{id}/lint"),
        format!("/api/v1/dpp/{id}/evidence"),
    ] {
        let r = reader.post_json(&path, json!({})).await;
        assert_eq!(r.status(), 403, "{path} must require write scope");
    }
}

/// The read endpoints must stay reachable on a read credential — a scope guard
/// added to the wrong handler is as much a defect as one missing from the right
/// handler, and "tighten everything" is the easy overcorrection here.
///
/// `404` (or `400` for the deliberately malformed dossier id) proves the request
/// reached the handler rather than being refused at the scope gate; the ids do
/// not exist, which is the point — this asserts *not 403*.
#[tokio::test(flavor = "multi_thread")]
async fn read_scoped_credential_can_still_read() {
    let pg = start_postgres().await;
    let vault_url = start_vault(pg.dal.clone()).await;

    let reader = TestClient::new(&vault_url, make_jwt_scoped("op", "read"));
    let id = "00000000-0000-4000-8000-000000000000";

    for path in [
        format!("/api/v1/dpp/{id}"),
        format!("/api/v1/dpp/{id}/evidence"),
        format!("/api/v1/dpp/{id}/history"),
        "/api/v1/dpps".to_owned(),
    ] {
        let r = reader.get(&path).await;
        assert_ne!(
            r.status(),
            403,
            "{path} is a read and must not require write scope"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn admin_can_mint_least_privilege_key_and_scope_round_trips() {
    let pg = start_postgres().await;
    let vault_url = start_vault(pg.dal.clone()).await;
    let admin = TestClient::new(&vault_url, make_jwt("op"));

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
