//! A transfer chain dpp-core refuses to read, met by every route that reads one.
//!
//! dpp-core checks a chain as it reads it, and refuses one that breaks the
//! chain's invariants. The chains here are written straight into the tables with
//! SQL, since no route can produce one: a completed record that carries no
//! signature.
//!
//! A verify route reports such a chain as a failed transfer-chain check, and
//! every other route refuses with `409`. Neither is a `500`.

#![cfg(feature = "integration-tests")]

mod helpers;

use dpp_dal::pg::sqlx;
use helpers::{
    PgContainer, TestClient, make_jwt, seed_complete_operator, start_postgres, start_vault,
};
use uuid::Uuid;

/// The record the refused chain breaks at, which core names in its refusal.
const REFUSED_RECORD: &str = "01990000-0000-7000-8000-0000000000aa";

fn client_for(vault_url: &str) -> TestClient {
    TestClient::new(vault_url, make_jwt("00000000-0000-0000-0000-000000000003"))
}

fn draft() -> serde_json::Value {
    serde_json::json!({
        "productName": "Refused Chain Battery",
        "manufacturer": {"name": "Refused Inc", "address": "Test"},
        "materials": [{"name": "Nickel", "weightKg": 0.5}],
        "productGroupData": {
            "productGroup": "battery",
            "productIdentifier": {"scheme": "gs1", "gtin": "09506000134352"},
            "batteryChemistry": "NiMH",
            "batteryType": "portable",
            "nominalVoltageV": 12.0,
            "nominalCapacityAh": 40.0,
            "expectedLifetimeCycles": 1000,
            "co2ePerUnitKg": 20.0
        }
    })
}

/// A published passport, on a node with its operator set up.
async fn published(pg: &PgContainer, client: &TestClient) -> String {
    seed_complete_operator(&pg.dal).await;
    let created: serde_json::Value = client
        .post_json("/api/v1/dpp", draft())
        .await
        .json()
        .await
        .unwrap();
    let id = created["id"].as_str().expect("created id").to_owned();
    let resp = client
        .post_json(&format!("/api/v1/dpp/{id}/publish"), serde_json::json!({}))
        .await;
    assert_eq!(resp.status(), 200, "the passport must be published");
    id
}

fn operator(did: &str) -> serde_json::Value {
    serde_json::json!({ "did": did, "name": "Acme", "role": "distributor", "country": "DE" })
}

/// A chain holding one record that says it completed and carries no signature.
/// dpp-core refuses it, as it refuses a record for another passport, a broken
/// operator sequence, a record after a pending one and a record with two
/// outcomes.
fn refused_chain(passport_id: &str) -> serde_json::Value {
    serde_json::json!({
        "passportId": passport_id,
        "originalOperator": operator("did:web:acme.example"),
        "transfers": [{
            "transferId": REFUSED_RECORD,
            "passportId": passport_id,
            "fromOperator": operator("did:web:acme.example"),
            "toOperator": operator("did:web:reco.example"),
            "reason": "sale",
            "fromSignature": null,
            "nodeAcceptanceAttestation": null,
            "initiatedAt": "2026-11-01T00:00:00Z",
            "completedAt": "2026-11-02T00:00:00Z",
            "notes": null
        }]
    })
}

/// Store the refused chain as the passport's transfer chain.
async fn store_refused_chain(pg: &PgContainer, passport_id: &str) {
    sqlx::query(
        "INSERT INTO odal.passport_transfer (passport_id, chain, updated_at) \
         VALUES ($1, $2, now())",
    )
    .bind(Uuid::parse_str(passport_id).unwrap())
    .bind(refused_chain(passport_id))
    .execute(pg.dal.pool())
    .await
    .expect("store the refused chain");
}

/// A body that names the passport and the record core cited.
fn assert_names_passport_and_record(detail: &str, passport_id: &str) {
    assert!(detail.contains(passport_id), "names the passport: {detail}");
    assert!(
        detail.contains(REFUSED_RECORD),
        "names the record core cited: {detail}"
    );
}

async fn problem_detail(resp: reqwest::Response) -> String {
    let body: serde_json::Value = resp.json().await.unwrap();
    body["detail"]
        .as_str()
        .expect("a problem detail")
        .to_owned()
}

/// A dossier generated for the passport, with the refused chain set as its
/// `transferChain` member.
async fn dossier_with_refused_chain(client: &TestClient, passport_id: &str) -> serde_json::Value {
    let record: serde_json::Value = client
        .post_json(
            &format!("/api/v1/dpp/{passport_id}/evidence"),
            serde_json::json!({}),
        )
        .await
        .json()
        .await
        .unwrap();
    let mut dossier = record["dossier"].clone();
    dossier["transferChain"] = refused_chain(passport_id);
    dossier
}

/// The check named `name` in a verification report.
fn check<'a>(report: &'a serde_json::Value, name: &str) -> &'a serde_json::Value {
    report["checks"]
        .as_array()
        .expect("checks array")
        .iter()
        .find(|c| c["name"].as_str() == Some(name))
        .unwrap_or_else(|| panic!("the report has no {name} check: {report}"))
}

fn assert_transfer_chain_check_failed_naming_the_record(report: &serde_json::Value) {
    let transfer = check(report, "transfer_chain");
    assert_eq!(transfer["status"], "fail", "{report}");
    let detail = transfer["detail"].as_str().expect("a failure detail");
    assert!(
        detail.contains(REFUSED_RECORD),
        "the failed check names the record: {detail}"
    );
    // The rest of the dossier is read and checked as usual. The checks named here
    // are the ones both verify routes report. A stored dossier is read the way an
    // uploaded one is, so it also carries `input_fidelity`, which the report of a
    // dossier that reads normally does not; nothing here asserts its verdict.
    for name in [
        "audit_chain",
        "checkpoint",
        "qualified_seal",
        "input_fidelity",
    ] {
        check(report, name);
    }
    assert_eq!(check(report, "audit_chain")["status"], "pass", "{report}");
}

#[tokio::test(flavor = "multi_thread")]
async fn an_uploaded_dossier_whose_chain_core_refuses_fails_the_transfer_chain_check() {
    let pg = start_postgres().await;
    let vault_url = start_vault(pg.dal.clone()).await;
    let client = client_for(&vault_url);
    let id = published(&pg, &client).await;
    let dossier = dossier_with_refused_chain(&client, &id).await;

    let resp = client.post_json("/api/v1/evidence/verify", dossier).await;
    assert_eq!(
        resp.status(),
        200,
        "a refused chain is a failed check, not a refused upload"
    );
    let report: serde_json::Value = resp.json().await.unwrap();
    assert_transfer_chain_check_failed_naming_the_record(&report);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_uploaded_dossier_with_a_malformed_chain_is_still_refused_with_422() {
    let pg = start_postgres().await;
    let vault_url = start_vault(pg.dal.clone()).await;
    let client = client_for(&vault_url);
    let id = published(&pg, &client).await;
    let mut dossier = dossier_with_refused_chain(&client, &id).await;
    dossier["transferChain"]
        .as_object_mut()
        .unwrap()
        .remove("transfers");

    let resp = client.post_json("/api/v1/evidence/verify", dossier).await;
    assert_eq!(
        resp.status(),
        422,
        "a chain that is malformed, not refused by core, is not a dossier"
    );
}

/// Insert `dossier` as a stored dossier of the passport, which no route can do
/// for a dossier whose chain core refuses.
async fn store_dossier(pg: &PgContainer, passport_id: &str, dossier: &serde_json::Value) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO odal.evidence_dossier (id, passport_id, actor, doc_hash, doc) \
         VALUES ($1, $2, 'test', 'not-checked', $3)",
    )
    .bind(id)
    .bind(Uuid::parse_str(passport_id).unwrap())
    .bind(dossier)
    .execute(pg.dal.pool())
    .await
    .expect("store the dossier");
    id
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stored_dossier_whose_chain_core_refuses_fails_the_transfer_chain_check() {
    let pg = start_postgres().await;
    let vault_url = start_vault(pg.dal.clone()).await;
    let client = client_for(&vault_url);
    let id = published(&pg, &client).await;
    let dossier = dossier_with_refused_chain(&client, &id).await;
    let dossier_id = store_dossier(&pg, &id, &dossier).await;

    let resp = client
        .post_json(
            &format!("/api/v1/evidence/{dossier_id}/verify"),
            serde_json::json!({}),
        )
        .await;
    assert_eq!(resp.status(), 200, "a refused chain is a failed check");
    let report: serde_json::Value = resp.json().await.unwrap();
    assert_transfer_chain_check_failed_naming_the_record(&report);
}

/// A stored dossier whose chain core refuses and whose remainder cannot be read
/// either has nothing to report on, and the answer is the refusal, not an
/// internal error.
#[tokio::test(flavor = "multi_thread")]
async fn verifying_a_stored_dossier_unreadable_beyond_its_refused_chain_is_409() {
    let pg = start_postgres().await;
    let vault_url = start_vault(pg.dal.clone()).await;
    let client = client_for(&vault_url);
    let id = published(&pg, &client).await;
    let mut dossier = dossier_with_refused_chain(&client, &id).await;
    dossier["notARealField"] = serde_json::json!("unreadable");
    let dossier_id = store_dossier(&pg, &id, &dossier).await;

    let resp = client
        .post_json(
            &format!("/api/v1/evidence/{dossier_id}/verify"),
            serde_json::json!({}),
        )
        .await;
    assert_eq!(resp.status(), 409);
    assert_names_passport_and_record(&problem_detail(resp).await, &id);
}

/// `GET /evidence/{id}` serves the dossier as a `DossierV1`, which re-writes its
/// members in the order they were signed in. The stored document cannot be
/// served as it is stored without giving that up, so a dossier that cannot be
/// read as one is refused with `409`.
#[tokio::test(flavor = "multi_thread")]
async fn fetching_a_stored_dossier_whose_chain_core_refuses_is_409() {
    let pg = start_postgres().await;
    let vault_url = start_vault(pg.dal.clone()).await;
    let client = client_for(&vault_url);
    let id = published(&pg, &client).await;
    let dossier = dossier_with_refused_chain(&client, &id).await;
    let dossier_id = store_dossier(&pg, &id, &dossier).await;

    let resp = client.get(&format!("/api/v1/evidence/{dossier_id}")).await;
    assert_eq!(resp.status(), 409);
    assert_names_passport_and_record(&problem_detail(resp).await, &id);
}

#[tokio::test(flavor = "multi_thread")]
async fn generating_evidence_over_a_chain_core_refuses_is_409() {
    let pg = start_postgres().await;
    let vault_url = start_vault(pg.dal.clone()).await;
    let client = client_for(&vault_url);
    let id = published(&pg, &client).await;
    store_refused_chain(&pg, &id).await;

    let resp = client
        .post_json(&format!("/api/v1/dpp/{id}/evidence"), serde_json::json!({}))
        .await;
    assert_eq!(resp.status(), 409);
    assert_names_passport_and_record(&problem_detail(resp).await, &id);
}

#[tokio::test(flavor = "multi_thread")]
async fn every_transfer_action_over_a_chain_core_refuses_is_409() {
    let pg = start_postgres().await;
    let vault_url = start_vault(pg.dal.clone()).await;
    let client = client_for(&vault_url);
    let id = published(&pg, &client).await;
    store_refused_chain(&pg, &id).await;

    let initiate = serde_json::json!({
        "fromOperator": {"did":"did:web:acme.example","name":"Acme GmbH","role":"manufacturer","euOperatorId":null,"country":"DE"},
        "toOperator": {"did":"did:web:reco.example","name":"ReCo","role":"recycler","euOperatorId":null,"country":"DE"},
        "reason": "preparationForReuse"
    });
    for (action, body) in [
        ("initiate", initiate),
        ("accept", serde_json::json!({})),
        ("reject", serde_json::json!({})),
        ("cancel", serde_json::json!({})),
    ] {
        let resp = client
            .post_json(&format!("/api/v1/dpp/{id}/transfer/{action}"), body)
            .await;
        assert_eq!(resp.status(), 409, "transfer/{action}");
        assert_names_passport_and_record(&problem_detail(resp).await, &id);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_registry_status_over_a_chain_core_refuses_is_409() {
    let pg = start_postgres().await;
    let vault_url = start_vault(pg.dal.clone()).await;
    let client = client_for(&vault_url);
    let id = published(&pg, &client).await;
    store_refused_chain(&pg, &id).await;

    let resp = client.get(&format!("/api/v1/dpp/{id}/registry")).await;
    assert_eq!(resp.status(), 409);
    assert_names_passport_and_record(&problem_detail(resp).await, &id);
}
