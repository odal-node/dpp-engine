//! Transfers started together on one passport.
//!
//! A transfer step reads the passport's chain, signs, and writes the chain back
//! whole. Two initiations that overlap each read a chain with nothing pending,
//! each signed a handover, and the second write replaced the first: both callers
//! got a record, both left an audit entry and an event, and the chain held one.

#![cfg(feature = "integration-tests")]

mod helpers;

use dpp_dal::pg::PgTransferRepo;
use dpp_domain::passport::PassportId;
use dpp_types::TransferStore;
use helpers::{
    TestClient, make_jwt, seed_complete_operator, start_postgres, start_vault_slow_signer,
};

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

/// Two initiations on one published passport, started at the same moment.
///
/// The slow signer holds the gap between the chain read and the chain write
/// open, so the second request is certain to read before the first writes.
/// Exactly one is recorded: the other is refused, and neither the chain nor the
/// audit trail has a trace of it.
#[tokio::test(flavor = "multi_thread")]
async fn of_two_transfers_started_together_exactly_one_is_recorded() {
    let pg = start_postgres().await;
    let vault_url =
        start_vault_slow_signer(pg.dal.clone(), std::time::Duration::from_millis(300)).await;
    seed_complete_operator(&pg.dal).await;
    let client = TestClient::new(&vault_url, make_jwt("00000000-0000-0000-0000-000000000003"));

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

    let path = format!("/api/v1/dpp/{id}/transfer/initiate");
    let (a, b) = tokio::join!(
        client.post_json(&path, initiate_body("did:web:recycler-a.example")),
        client.post_json(&path, initiate_body("did:web:recycler-b.example")),
    );
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

    let history: Vec<serde_json::Value> = client
        .get(&format!("/api/v1/dpp/{id}/history"))
        .await
        .json()
        .await
        .unwrap();
    let transfers = history
        .iter()
        .filter(|e| e["action"].as_str() == Some("transferred"))
        .count();
    assert_eq!(
        transfers, 1,
        "the refused initiation left no audit entry: {history:?}"
    );
}
