//! A publish refused for its signature is recorded in the database, where a restart
//! cannot clear it. It is read through a fresh repo over the same database,
//! as a node that has restarted would read it.

#![cfg(feature = "integration-tests")]

mod helpers;

use dpp_dal::pg::PgNodeSignalRepo;
use dpp_types::node_signal::{NodeSignals, Signal, SignalState};
use helpers::{
    TestClient, make_jwt, seed_complete_operator, start_postgres, start_vault_failing_signer,
};

fn op() -> String {
    "00000000-0000-0000-0000-000000000001".to_owned()
}

fn sample() -> serde_json::Value {
    serde_json::json!({
        "productName": "Test Widget",
        "manufacturer": {"name": "ACME Corp", "address": "Berlin, DE"},
        "materials": [],
    })
}

#[tokio::test(flavor = "multi_thread")]
async fn a_publish_refused_for_its_signature_is_recorded_durably() {
    let pg = start_postgres().await;
    let base = start_vault_failing_signer(pg.dal.clone()).await;
    seed_complete_operator(&pg.dal).await;
    let client = TestClient::new(&base, make_jwt(&op()));

    // Creation does not involve the signer, so the draft is made first.
    let resp = client.post_json("/api/v1/dpp", sample()).await;
    assert_eq!(
        resp.status(),
        201,
        "create must succeed regardless of signer"
    );
    let id = resp.json::<serde_json::Value>().await.unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();

    let publish = client
        .post_json(&format!("/api/v1/dpp/{id}/publish"), serde_json::json!({}))
        .await;
    assert!(
        publish.status().is_server_error(),
        "publish with a broken signer must fail, got {}",
        publish.status()
    );

    let states = PgNodeSignalRepo::new(pg.dal.clone())
        .states()
        .await
        .unwrap();
    let [
        (Signal::Signing, signing),
        (Signal::RulesetLoad, ruleset_load),
    ] = states[..]
    else {
        panic!("every signal, in order: {states:?}");
    };
    assert_eq!(signing.failures, 1, "one refused signature, counted once");
    assert!(signing.is_failing(), "and the latest outcome: {signing:?}");
    assert_eq!(signing.last_succeeded_at, None, "nothing has signed");
    assert_eq!(
        ruleset_load,
        SignalState::default(),
        "no ruleset load recorded"
    );
}
