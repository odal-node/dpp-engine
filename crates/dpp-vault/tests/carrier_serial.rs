//! Integration test for the serial an operator attributes to a passport's GS1
//! carrier.
//!
//! A carrier prints the passport's *carrier serial*: by default one derived from
//! its id, and when the operator states one at create, that. These pin the whole
//! path through the real routes: the serial is accepted, printed, resolved by,
//! refused where it would make one label name two passports, and never refused
//! where one label is meant to name a whole amendment chain.

#![cfg(feature = "integration-tests")]

mod helpers;

use helpers::{TestClient, make_jwt, seed_complete_operator, start_postgres, start_vault};

const GTIN: &str = "09506000134352";
const OTHER_GTIN: &str = "01234567890128";

/// A battery draft under `identifier`, optionally attributing a carrier serial.
fn draft(name: &str, identifier: serde_json::Value, serial: Option<&str>) -> serde_json::Value {
    let mut body = serde_json::json!({
        "productName": name,
        "manufacturer": {"name": "Serial Inc", "address": "Test"},
        "materials": [{"name": "Nickel", "weightKg": 0.5}],
        "productGroupData": {
            "productGroup": "battery",
            "productIdentifier": identifier,
            "batteryChemistry": "NiMH",
            "batteryType": "portable",
            "nominalVoltageV": 12.0,
            "nominalCapacityAh": 40.0,
            "expectedLifetimeCycles": 1000,
            "co2ePerUnitKg": 20.0
        }
    });
    if let Some(serial) = serial {
        body["carrierSerial"] = serde_json::json!(serial);
    }
    body
}

fn gs1(gtin: &str) -> serde_json::Value {
    serde_json::json!({ "scheme": "gs1", "gtin": gtin })
}

async fn client() -> (TestClient, helpers::PgContainer) {
    let pg = start_postgres().await;
    let vault_url = start_vault(pg.dal.clone()).await;
    seed_complete_operator(&pg.dal).await;
    let token = make_jwt("00000000-0000-0000-0000-000000000003");
    (TestClient::new(&vault_url, &token), pg)
}

/// Create, expecting `201`, and return the response body.
async fn create(client: &TestClient, body: serde_json::Value) -> serde_json::Value {
    let resp = client.post_json("/api/v1/dpp", body).await;
    let status = resp.status();
    let text = resp.text().await.unwrap();
    assert_eq!(status, 201, "create should succeed: {text}");
    serde_json::from_str(&text).unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn an_attributed_serial_is_stored_printed_and_resolved_by() {
    let (client, _pg) = client().await;

    let created = create(
        &client,
        draft("Serialised", gs1(GTIN), Some("SN-2026-0001")),
    )
    .await;
    assert_eq!(created["carrierSerial"], "SN-2026-0001");
    let id = created["id"].as_str().unwrap().to_owned();

    let resp = client
        .post_json(&format!("/api/v1/dpp/{id}/publish"), serde_json::json!({}))
        .await;
    assert_eq!(resp.status(), 200);
    let published: serde_json::Value = resp.json().await.unwrap();
    let carrier = published["qrCodeUrl"].as_str().unwrap();
    assert!(
        carrier.ends_with(&format!("/01/{GTIN}/21/SN-2026-0001")),
        "the carrier prints the serial the operator attributed, not one derived from the id: {carrier}"
    );

    // And the label on the object reaches this passport through that serial.
    let resp = client
        .get(&format!("/public/dpp/by-gtin/{GTIN}?serial=SN-2026-0001"))
        .await;
    assert_eq!(resp.status(), 200);
    let served: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(served["id"], id.as_str());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_serial_another_passport_holds_is_refused_by_create_and_by_the_dry_run() {
    let (client, _pg) = client().await;
    create(&client, draft("First", gs1(GTIN), Some("SN-1"))).await;

    let second = draft("Second", gs1(GTIN), Some("SN-1"));

    let resp = client.post_json("/api/v1/dpp", second.clone()).await;
    assert_eq!(resp.status(), 409, "two unrelated passports, one label");
    let problem: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        problem["errors"][0]["field"], "/carrierSerial",
        "the refusal names the field: {problem}"
    );

    // The dry run says the same, so a preview cannot pass what create refuses.
    let resp = client.post_json("/api/v1/dpp/validate", second).await;
    assert_eq!(resp.status(), 409, "the dry run must agree with create");

    // What is refused is the serial: the same body without it is fine, and so is
    // the same serial under another GTIN, which is another product.
    create(&client, draft("Second, defaulted", gs1(GTIN), None)).await;
    create(&client, draft("Elsewhere", gs1(OTHER_GTIN), Some("SN-1"))).await;
}

/// One label is meant to name a whole amendment chain, so the serial a successor
/// shares with its predecessor is never a collision: not for an amendment, which
/// carries it forward, and not for a successor declared at create.
#[tokio::test(flavor = "multi_thread")]
async fn an_amendment_chain_shares_one_serial_without_being_refused() {
    let (client, _pg) = client().await;
    let first = create(&client, draft("Chained", gs1(GTIN), Some("SN-1"))).await;
    let first_id = first["id"].as_str().unwrap().to_owned();

    let resp = client
        .post_json(
            &format!("/api/v1/dpp/{first_id}/publish"),
            serde_json::json!({}),
        )
        .await;
    assert_eq!(resp.status(), 200);

    // An amendment carries the serial forward and is not refused for it.
    let resp = client
        .post_json(
            &format!("/api/v1/dpp/{first_id}/amend"),
            serde_json::json!({ "patch": { "productName": "Chained, corrected" } }),
        )
        .await;
    assert_eq!(resp.status(), 201);
    let head: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(head["carrierSerial"], "SN-1");
    let head_id = head["id"].as_str().unwrap().to_owned();

    // A successor declared at create, replacing the head, may state it too.
    let mut declared = draft("Chained, declared", gs1(GTIN), Some("SN-1"));
    declared["supersedesId"] = serde_json::json!(head_id);
    create(&client, declared).await;

    // Without naming what it replaces, the same body collides with the head.
    let resp = client
        .post_json(
            "/api/v1/dpp",
            draft("Chained, unrelated", gs1(GTIN), Some("SN-1")),
        )
        .await;
    assert_eq!(resp.status(), 409);
}

/// Publish `id`, expecting `200`.
async fn publish(client: &TestClient, id: &str) {
    let resp = client
        .post_json(&format!("/api/v1/dpp/{id}/publish"), serde_json::json!({}))
        .await;
    let status = resp.status();
    assert_eq!(
        status,
        200,
        "publish should succeed: {}",
        resp.text().await.unwrap()
    );
}

/// The id of the passport the label `/01/{GTIN}/21/{serial}` reaches.
async fn label_reaches(client: &TestClient, serial: &str) -> String {
    let resp = client
        .get(&format!("/public/dpp/by-gtin/{GTIN}?serial={serial}"))
        .await;
    let status = resp.status();
    let text = resp.text().await.unwrap();
    assert_eq!(status, 200, "the label must resolve: {text}");
    let served: serde_json::Value = serde_json::from_str(&text).unwrap();
    served["id"].as_str().unwrap().to_owned()
}

/// A successor declared at create is published and then named by a separate
/// `supersede` call, so for a while both it and the passport it replaces are
/// live under one label. The label answers the predecessor until the supersede,
/// and the successor after it. Never an error.
#[tokio::test(flavor = "multi_thread")]
async fn a_declared_successor_takes_the_label_when_its_predecessor_is_superseded() {
    let (client, _pg) = client().await;
    let first = create(&client, draft("Original", gs1(GTIN), Some("SN-1"))).await;
    let first_id = first["id"].as_str().unwrap().to_owned();
    publish(&client, &first_id).await;

    let mut declared = draft("Replacement", gs1(GTIN), Some("SN-1"));
    declared["supersedesId"] = serde_json::json!(first_id);
    let second = create(&client, declared).await;
    let second_id = second["id"].as_str().unwrap().to_owned();
    publish(&client, &second_id).await;

    assert_eq!(
        label_reaches(&client, "SN-1").await,
        first_id,
        "until it is superseded, the predecessor is the live record"
    );

    let resp = client
        .post_json(
            &format!("/api/v1/dpp/{first_id}/supersede"),
            serde_json::json!({ "supersededBy": second_id }),
        )
        .await;
    assert_eq!(resp.status(), 200);

    assert_eq!(label_reaches(&client, "SN-1").await, second_id);
}

/// Two creates that arrive together can both pass create's check, simulated by
/// writing the second draft straight to the store. Publish checks again as the
/// label goes live: the first to publish keeps the serial, and the other is a
/// `422` naming the field and stays a draft, so the label never names both.
#[tokio::test(flavor = "multi_thread")]
async fn of_two_drafts_that_raced_past_create_only_the_first_published_goes_live() {
    use dpp_dal::pg::PgPassportRepo;
    use dpp_domain::{passport::PassportId, ports::passport_repo::PassportRepository};

    let (client, pg) = client().await;
    let first = create(&client, draft("First", gs1(GTIN), Some("SN-1"))).await;
    let first_id = first["id"].as_str().unwrap().to_owned();

    let repo = PgPassportRepo::new(pg.dal.clone());
    let mut raced = repo
        .find_by_id(PassportId(first_id.parse().unwrap()))
        .await
        .unwrap()
        .expect("the first draft is stored");
    raced.id = PassportId::new();
    let raced_id = raced.id.to_string();
    repo.create(raced).await.expect("seed the raced draft");

    publish(&client, &first_id).await;

    let resp = client
        .post_json(
            &format!("/api/v1/dpp/{raced_id}/publish"),
            serde_json::json!({}),
        )
        .await;
    assert_eq!(resp.status(), 422);
    let problem: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(problem["errors"][0]["field"], "/carrierSerial", "{problem}");

    assert_eq!(label_reaches(&client, "SN-1").await, first_id);
}

/// A draft's update ignores the create-time fields it is sent, but not this
/// one: a different serial is a `422` naming it, because ignoring it would answer
/// a caller whose label will not say what they sent. The serial it already
/// prints is accepted, so a body read back and sent again still applies.
#[tokio::test(flavor = "multi_thread")]
async fn an_update_naming_a_different_serial_is_refused_not_ignored() {
    let (client, _pg) = client().await;
    let created = create(&client, draft("Fixed", gs1(GTIN), Some("SN-1"))).await;
    let id = created["id"].as_str().unwrap().to_owned();

    let resp = client
        .put_json(
            &format!("/api/v1/dpp/{id}"),
            serde_json::json!({ "productName": "Renamed", "carrierSerial": "SN-2" }),
        )
        .await;
    assert_eq!(resp.status(), 422);
    let problem: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(problem["errors"][0]["field"], "/carrierSerial", "{problem}");

    let resp = client
        .put_json(
            &format!("/api/v1/dpp/{id}"),
            serde_json::json!({ "productName": "Renamed", "carrierSerial": "SN-1" }),
        )
        .await;
    assert_eq!(resp.status(), 200);
    let updated: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(updated["productName"], "Renamed");
    assert_eq!(updated["carrierSerial"], "SN-1");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_serial_gs1_would_reject_or_that_cannot_be_printed_is_a_422_naming_the_field() {
    let (client, _pg) = client().await;

    // A value outside CSET 82.
    let resp = client
        .post_json("/api/v1/dpp", draft("Spaced", gs1(GTIN), Some("SN 1")))
        .await;
    assert_eq!(resp.status(), 422);
    let problem: serde_json::Value = resp.json().await.unwrap();
    assert!(
        problem["detail"]
            .as_str()
            .is_some_and(|d| d.contains("carrierSerial")),
        "{problem}"
    );

    // On a passport with no GTIN there is no GS1 carrier to print it on.
    let link = serde_json::json!({
        "scheme": "identificationLink",
        "url": "https://example.com/p/abc"
    });
    let resp = client
        .post_json("/api/v1/dpp", draft("Linked", link, Some("SN-1")))
        .await;
    assert_eq!(resp.status(), 422);
}
