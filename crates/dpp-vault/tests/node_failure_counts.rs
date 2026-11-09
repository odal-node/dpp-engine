//! A publish refused for its signature is counted in the database, where a restart
//! cannot clear it. The count is read through a fresh repo over the same database,
//! as a node that has restarted would read it.

#![cfg(feature = "integration-tests")]

mod helpers;

use dpp_dal::pg::PgNodeFailureRepo;
use dpp_types::node_failure::{NodeFailureCounter, Refusals};
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
async fn a_publish_refused_for_its_signature_is_counted_durably() {
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

    let counts = PgNodeFailureRepo::new(pg.dal.clone())
        .counts()
        .await
        .unwrap();
    assert_eq!(
        counts.signing.total, 1,
        "one refused signature, counted once"
    );
    assert!(counts.signing.last_at.is_some(), "and marked the latest");
    assert_eq!(
        counts.ruleset_load,
        Refusals::default(),
        "no ruleset refused"
    );
}
