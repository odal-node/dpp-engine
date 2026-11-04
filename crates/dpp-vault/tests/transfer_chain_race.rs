//! Transfer steps that overlap on one passport.
//!
//! A transfer step reads the passport's chain, signs, and writes the chain back
//! whole. Two initiations that overlap each read a chain with nothing pending,
//! each signed a handover, and the second write replaced the first: both callers
//! got a record, both left an audit entry and an event, and the chain held one.
//! The same held for an accept, a reject or a cancel racing another step, and
//! each of those routes documents the `422` a step gets when it loses.

#![cfg(feature = "integration-tests")]

mod helpers;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use dpp_dal::pg::{PgTransferRepo, sqlx};
use dpp_domain::DppError;
use dpp_domain::credential::SignedCredential;
use dpp_domain::passport::PassportId;
use dpp_domain::ports::identity::IdentityPort;
use dpp_domain::transfer::TransferStatus;
use dpp_types::TransferStore;
use helpers::{
    MockIdentity, PgContainer, TestClient, make_jwt, seed_complete_operator, start_postgres,
    start_vault, start_vault_with_signer,
};
use tokio::sync::Barrier;
use uuid::Uuid;

fn initiate_body(to_did: &str) -> serde_json::Value {
    serde_json::json!({
        "fromOperator": {"did":"did:web:acme.example","name":"Acme GmbH","role":"manufacturer","euOperatorId":null,"country":"DE"},
        "toOperator": {"did":to_did,"name":"ReCo","role":"recycler","euOperatorId":null,"country":"DE"},
        "reason": "preparationForReuse"
    })
}

/// A battery draft with the fewest fields a publish accepts.
fn draft() -> serde_json::Value {
    serde_json::json!({
        "productName": "Transfer Race Battery",
        "manufacturer": {"name": "Race Inc", "address": "Test"},
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

/// A signer that, once armed, returns no signature until two are waiting.
///
/// A transfer step reads the chain and then signs, so holding two steps here
/// means both have read before either writes, whatever the scheduler does.
struct RendezvousSigner {
    armed: AtomicBool,
    barrier: Barrier,
}

#[async_trait]
impl IdentityPort for RendezvousSigner {
    async fn sign_passport(
        &self,
        passport_id: PassportId,
        payload: &serde_json::Value,
    ) -> Result<SignedCredential, DppError> {
        if self.armed.load(Ordering::SeqCst) {
            self.barrier.wait().await;
        }
        MockIdentity.sign_passport(passport_id, payload).await
    }

    async fn verify_signature(
        &self,
        jws: &str,
        payload: &serde_json::Value,
    ) -> Result<bool, DppError> {
        MockIdentity.verify_signature(jws, payload).await
    }

    async fn own_did_document(&self) -> Result<serde_json::Value, DppError> {
        MockIdentity.own_did_document().await
    }
}

fn client_for(vault_url: &str) -> TestClient {
    TestClient::new(vault_url, make_jwt("00000000-0000-0000-0000-000000000003"))
}

/// Create a battery draft and publish it, returning its id.
async fn published(client: &TestClient) -> String {
    let created: serde_json::Value = client
        .post_json("/api/v1/dpp", draft())
        .await
        .json()
        .await
        .unwrap();
    let id = created["id"].as_str().expect("created id").to_owned();
    let published = client
        .post_json(&format!("/api/v1/dpp/{id}/publish"), serde_json::json!({}))
        .await;
    assert_eq!(published.status(), 200, "the passport must be published");
    id
}

/// How many `transferred` entries the passport's audit trail holds.
async fn transfer_entries(client: &TestClient, id: &str) -> usize {
    let history: Vec<serde_json::Value> = client
        .get(&format!("/api/v1/dpp/{id}/history"))
        .await
        .json()
        .await
        .unwrap();
    history
        .iter()
        .filter(|e| e["action"].as_str() == Some("transferred"))
        .count()
}

/// Two initiations on one published passport, started at the same moment.
///
/// The signer holds both after their chain reads and releases them together, so
/// both are certain to have read a chain with nothing pending before either
/// writes. Exactly one is recorded: the other is refused, and neither the chain
/// nor the audit trail has a trace of it.
#[tokio::test(flavor = "multi_thread")]
async fn of_two_transfers_started_together_exactly_one_is_recorded() {
    let pg = start_postgres().await;
    let signer = Arc::new(RendezvousSigner {
        armed: AtomicBool::new(false),
        barrier: Barrier::new(2),
    });
    let vault_url = start_vault_with_signer(pg.dal.clone(), signer.clone()).await;
    seed_complete_operator(&pg.dal).await;
    let client = client_for(&vault_url);
    let id = published(&client).await;

    signer.armed.store(true, Ordering::SeqCst);
    let path = format!("/api/v1/dpp/{id}/transfer/initiate");
    let (a, b) = tokio::time::timeout(Duration::from_secs(30), async {
        tokio::join!(
            client.post_json(&path, initiate_body("did:web:recycler-a.example")),
            client.post_json(&path, initiate_body("did:web:recycler-b.example")),
        )
    })
    .await
    .expect("both initiations reach the signer");
    let (a_status, b_status) = (a.status().as_u16(), b.status().as_u16());
    let (a_body, b_body): (serde_json::Value, serde_json::Value) =
        (a.json().await.unwrap(), b.json().await.unwrap());

    let mut statuses = [a_status, b_status];
    statuses.sort_unstable();
    assert_eq!(
        statuses,
        [200, 422],
        "one initiation is recorded and one is refused: {a_body} / {b_body}"
    );
    let (winner, loser) = if a_status == 200 {
        (&a_body, &b_body)
    } else {
        (&b_body, &a_body)
    };
    assert!(
        loser["detail"]
            .as_str()
            .is_some_and(|d| d.contains("another request")),
        "the refusal says the chain moved under it: {loser}"
    );

    let stored = PgTransferRepo::new(pg.dal.clone())
        .get_chain(PassportId(id.parse().unwrap()))
        .await
        .expect("read the chain")
        .expect("a chain was stored")
        .chain;
    assert_eq!(
        stored.transfers.len(),
        1,
        "the chain holds the one initiation that succeeded"
    );
    assert_eq!(
        stored.transfers[0].transfer_id.to_string(),
        winner["transferId"].as_str().expect("winner's transfer id"),
        "and it is the one whose caller was told it succeeded"
    );
    assert_eq!(
        transfer_entries(&client, &id).await,
        1,
        "the refused initiation left no audit entry"
    );
}

/// Sessions on this test's database waiting for a lock.
async fn sessions_waiting_for_a_lock(pg: &PgContainer) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM pg_stat_activity
         WHERE datname = current_database() AND wait_event_type = 'Lock'",
    )
    .fetch_one(pg.dal.pool())
    .await
    .expect("read pg_stat_activity")
}

/// `step` (`accept`, `reject` or `cancel`) sent to a passport whose chain
/// another request changes after the step has read it and before it writes.
///
/// The test holds the chain's row, so the step reads the chain and then waits
/// at its write; once it is waiting, the test writes the row, which moves the
/// revision the step read, and lets go. Nothing here depends on timing: the
/// write is made only once the step is blocked behind it.
async fn a_step_over_a_chain_changed_under_it_is_refused(step: &str) {
    let pg = start_postgres().await;
    let vault_url = start_vault(pg.dal.clone()).await;
    seed_complete_operator(&pg.dal).await;
    let client = client_for(&vault_url);
    let id = published(&client).await;
    let initiated = client
        .post_json(
            &format!("/api/v1/dpp/{id}/transfer/initiate"),
            initiate_body("did:web:recycler.example"),
        )
        .await;
    assert_eq!(initiated.status(), 200, "the handover must be pending");
    let passport_id: Uuid = id.parse().unwrap();

    let mut hold = pg.dal.pool().begin().await.expect("begin");
    sqlx::query("SELECT 1 FROM odal.passport_transfer WHERE passport_id = $1 FOR UPDATE")
        .bind(passport_id)
        .execute(&mut *hold)
        .await
        .expect("hold the chain");

    let path = format!("/api/v1/dpp/{id}/transfer/{step}");
    let request = client.post_json(&path, serde_json::json!({}));
    let pg_ref = &pg;
    let change_the_chain = async move {
        let started = Instant::now();
        while sessions_waiting_for_a_lock(pg_ref).await < 1 {
            assert!(
                started.elapsed() < Duration::from_secs(10),
                "the {step} never reached its write"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        sqlx::query("UPDATE odal.passport_transfer SET chain = chain WHERE passport_id = $1")
            .bind(passport_id)
            .execute(&mut *hold)
            .await
            .expect("change the chain");
        hold.commit().await.expect("release the chain");
    };
    let (response, ()) = tokio::join!(request, change_the_chain);

    assert_eq!(response.status(), 422, "the {step} read a chain that moved");
    let problem: serde_json::Value = response.json().await.unwrap();
    assert!(
        problem["detail"]
            .as_str()
            .is_some_and(|d| d.contains("another request")),
        "the refusal says the chain moved under it: {problem}"
    );

    let stored = PgTransferRepo::new(pg.dal.clone())
        .get_chain(PassportId(passport_id))
        .await
        .expect("read the chain")
        .expect("a chain was stored")
        .chain;
    assert_eq!(
        stored.transfers[0].status(),
        TransferStatus::Initiated,
        "the refused {step} changed nothing"
    );
    assert_eq!(
        transfer_entries(&client, &id).await,
        1,
        "the refused {step} left no audit entry"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_accept_over_a_changed_chain_is_refused() {
    a_step_over_a_chain_changed_under_it_is_refused("accept").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_reject_over_a_changed_chain_is_refused() {
    a_step_over_a_chain_changed_under_it_is_refused("reject").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_cancel_over_a_changed_chain_is_refused() {
    a_step_over_a_chain_changed_under_it_is_refused("cancel").await;
}
