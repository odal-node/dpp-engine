//! The personal-data erasure route and the dry run's personal-data findings,
//! against a real PostgreSQL.
//!
//! What is here, and why each one has to be an HTTP test:
//!
//! 1. **The receipt, and the retry.** `DELETE /api/v1/personal-data/{record}`
//!    answers the receipt the first time and the same one after.
//! 2. **Erasing touches nothing else.** The passport read back after an erasure
//!    is the one read back before it, statement and all.
//! 3. **The scope gate runs before the erasure.** A refused caller leaves the
//!    record present — not merely a `403`.
//! 4. **`404` and `200` are told apart.** The pair CLAUDE.md names as worth a
//!    test: a record this node never held, against one it held and erased.
//! 5. **The dry run says what create says.** A preview that passed a body create
//!    refuses would send an operator into a draft that cannot be stored.
//! 6. **Storing and listing.** `POST` and `GET /api/v1/dpp/{dppId}/personal-data`:
//!    the path an operator takes through the API alone, a retry that stores a
//!    second record, the refusals (`409` against `422`, a body that cannot be
//!    read judged after the passport, `404` against an empty listing, `413`, the
//!    scope gate), that a refusal stores nothing, and that the node's log of a
//!    store names the record and never the data.

#![cfg(feature = "integration-tests")]

mod helpers;

use dpp_dal::pg::PgPersonalDataRepo;
use dpp_domain::passport::PassportId;
use dpp_domain::ports::personal_data::{HeldRecord, PersonalDataPort};
use helpers::{TestClient, make_jwt, make_jwt_scoped, start_postgres, start_vault};
use serde_json::{Value, json};

const FIELD: &str = "repairHistoryUrl";

/// A textile draft whose `repairHistoryUrl` — a log of repairs to one specific
/// item, marked as able to hold personal data — has a value.
fn textile_with_a_repair_history(personal_data: Option<Value>) -> Value {
    let mut body = json!({
        "productName": "Organic Cotton Tee",
        "productGroup": "textile",
        "manufacturer": {"name": "RouteTestCorp", "address": "Berlin, DE"},
        "materials": [],
        "productGroupData": {
            "carbonFootprintKgCo2e": 4.2,
            "careInstructions": "Machine wash cold, line dry",
            "chemicalComplianceStandard": "OEKO-TEX 100",
            "countryOfOrigin": "IT",
            "countryOfRawMaterialOrigin": "IN",
            "disassemblyInstructions": "Remove label and neck tape before recycling",
            "endOfLifeInstructions": "Return to a textile collection point",
            "expectedWashCycles": 50,
            "fibreComposition": [{"fibre": "cotton", "pct": 95}, {"fibre": "elastane", "pct": 5}],
            "microplasticSheddingMgPerWash": 12,
            "productGroup": "textile",
            "productIdentifier": {"gtin": "09506000134369", "scheme": "gs1"},
            "productWeightGrams": 220,
            "recyclabilityClass": "B",
            "recycledContentPct": 30,
            "sparePartsAvailable": false,
            "waterUseLitres": 1800,
            "repairHistoryUrl": "https://repairs.example.com/item/42",
        },
    });
    if let Some(statements) = personal_data {
        body["personalData"] = statements;
    }
    body
}

fn admin(url: &str) -> TestClient {
    TestClient::new(url, make_jwt("00000000-0000-0000-0000-0000000000a1"))
}

/// A draft whose marked field is stated as held in `record`, with the record
/// held for it.
async fn a_draft_naming_a_record(
    client: &TestClient,
    store: &PgPersonalDataRepo,
) -> (String, String, Value) {
    let created: Value = client
        .post_json(
            "/api/v1/dpp",
            textile_with_a_repair_history(Some(json!({ FIELD: { "held": "nothing" } }))),
        )
        .await
        .json()
        .await
        .expect("created");
    let id = created["id"].as_str().expect("an id").to_owned();

    let record = store
        .store(
            PassportId(id.parse().expect("uuid")),
            FIELD,
            &json!({ "owner": "named in the repair log" }),
        )
        .await
        .expect("held");

    let statement = json!({
        FIELD: { "held": "outside", "lawfulBasis": "consent", "record": record.as_str() }
    });
    let updated = client
        .put_json(
            &format!("/api/v1/dpp/{id}"),
            json!({ "personalData": statement }),
        )
        .await;
    assert_eq!(updated.status(), 200, "a draft may name its record");
    (id, record.to_string(), statement)
}

/// 🚨 The route that honours a withdrawn consent. The first call erases and
/// answers the receipt; the second — a caller that lost the first answer —
/// is handed the same one, with the same instant.
#[tokio::test(flavor = "multi_thread")]
async fn erasing_answers_the_receipt_and_a_retry_answers_the_same_one() {
    let pg = start_postgres().await;
    let url = start_vault(pg.dal.clone()).await;
    let client = admin(&url);
    let store = PgPersonalDataRepo::new(pg.dal.clone());
    let (id, record, _) = a_draft_naming_a_record(&client, &store).await;

    let first = client
        .delete(&format!("/api/v1/personal-data/{record}"))
        .await;
    assert_eq!(first.status(), 200);
    let first: Value = first.json().await.expect("receipt");
    assert_eq!(first["record"], record);
    assert_eq!(first["passportId"], id);
    assert_eq!(first["field"], FIELD);
    assert!(first["erasedAt"].is_string(), "{first}");
    assert!(
        !first.to_string().contains("named in the repair log"),
        "nothing of the content is in the receipt: {first}"
    );

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let again = client
        .delete(&format!("/api/v1/personal-data/{record}"))
        .await;
    assert_eq!(again.status(), 200, "a retry is not an error");
    assert_eq!(again.json::<Value>().await.expect("receipt"), first);

    let held = store
        .fetch(&dpp_domain::PersonalDataRecordId::new(record))
        .await
        .expect("fetch");
    assert!(matches!(held, Some(HeldRecord::Erased(_))), "{held:?}");
}

/// Erasing must not touch the passport or its statement: the statement keeps
/// naming a record that is gone, which is how a reader learns it was erased
/// rather than never there.
#[tokio::test(flavor = "multi_thread")]
async fn erasing_leaves_the_passport_and_the_statement_naming_the_record() {
    let pg = start_postgres().await;
    let url = start_vault(pg.dal.clone()).await;
    let client = admin(&url);
    let store = PgPersonalDataRepo::new(pg.dal.clone());
    let (id, record, statement) = a_draft_naming_a_record(&client, &store).await;

    let before: Value = client
        .get(&format!("/api/v1/dpp/{id}"))
        .await
        .json()
        .await
        .expect("passport");
    assert_eq!(before["personalData"], statement);

    let erased = client
        .delete(&format!("/api/v1/personal-data/{record}"))
        .await;
    assert_eq!(erased.status(), 200);

    let after: Value = client
        .get(&format!("/api/v1/dpp/{id}"))
        .await
        .json()
        .await
        .expect("passport");
    assert_eq!(before, after, "the passport is as it was, byte for byte");
    assert_eq!(after["personalData"], statement);
}

/// A caller that cannot administer is refused before anything is erased: the
/// record is still present afterwards, so the refusal is not merely a status.
#[tokio::test(flavor = "multi_thread")]
async fn a_caller_without_the_admin_scope_erases_nothing() {
    let pg = start_postgres().await;
    let url = start_vault(pg.dal.clone()).await;
    let store = PgPersonalDataRepo::new(pg.dal.clone());
    let (_id, record, _) = a_draft_naming_a_record(&admin(&url), &store).await;
    let path = format!("/api/v1/personal-data/{record}");

    for scope in ["write", "read"] {
        let refused = TestClient::new(&url, make_jwt_scoped("op", scope))
            .delete(&path)
            .await;
        assert_eq!(refused.status(), 403, "a {scope}-scoped key must not erase");
    }

    let unauthenticated =
        helpers::send_checked(reqwest::Client::new().delete(format!("{url}{path}"))).await;
    assert_eq!(unauthenticated.status(), 401);

    let held = store
        .fetch(&dpp_domain::PersonalDataRecordId::new(record))
        .await
        .expect("fetch");
    assert!(
        matches!(held, Some(HeldRecord::Present(_))),
        "three refusals, and the record is still held: {held:?}"
    );
}

/// `404` means this node never held the record. A record it held and erased is
/// not that, and a retry of it is `200`.
#[tokio::test(flavor = "multi_thread")]
async fn a_record_never_held_and_one_already_erased_are_told_apart() {
    let pg = start_postgres().await;
    let url = start_vault(pg.dal.clone()).await;
    let client = admin(&url);
    let store = PgPersonalDataRepo::new(pg.dal.clone());
    let (_id, record, _) = a_draft_naming_a_record(&client, &store).await;

    // One that could have been minted here, and one that never could.
    for stranger in [uuid::Uuid::now_v7().to_string(), "never-minted".to_owned()] {
        let resp = client
            .delete(&format!("/api/v1/personal-data/{stranger}"))
            .await;
        assert_eq!(resp.status(), 404, "{stranger}");
        assert_eq!(
            resp.headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok()),
            Some("application/problem+json")
        );
    }

    assert_eq!(
        client
            .delete(&format!("/api/v1/personal-data/{record}"))
            .await
            .status(),
        200
    );
    assert_eq!(
        client
            .delete(&format!("/api/v1/personal-data/{record}"))
            .await
            .status(),
        200,
        "erased is not unknown"
    );
}

/// What a `422` from create names, so the dry run can be held to the same words.
async fn refusal(resp: reqwest::Response) -> (u16, Value) {
    let status = resp.status().as_u16();
    let mut problem: Value = resp.json().await.expect("a problem document");
    // Per request, so two refusals of one body differ in it and in nothing else.
    problem
        .as_object_mut()
        .expect("an object")
        .remove("requestId");
    (status, problem)
}

/// 🚨 A preview that passes a body create refuses sends an operator into a draft
/// that cannot be stored. Each finding the personal-data check makes is refused
/// by the dry run in the same words create uses, and the same body that clears
/// the check is accepted by both.
#[tokio::test(flavor = "multi_thread")]
async fn the_dry_run_refuses_what_the_personal_data_check_refuses_on_create() {
    let pg = start_postgres().await;
    let url = start_vault(pg.dal.clone()).await;
    let client = admin(&url);

    let unstated = textile_with_a_repair_history(None);
    let about_an_unmarked_field = textile_with_a_repair_history(Some(json!({
        FIELD: { "held": "nothing" },
        "productName": { "held": "nothing" },
    })));
    let on_a_basis_the_act_does_not_admit = textile_with_a_repair_history(Some(json!({
        FIELD: { "held": "outside", "lawfulBasis": "contract", "record": "r-1" },
    })));
    let naming_no_record = textile_with_a_repair_history(Some(json!({
        FIELD: { "held": "outside", "lawfulBasis": "consent", "record": "" },
    })));

    for (what, body, field) in [
        (
            "no statement",
            unstated,
            "/productGroupData/repairHistoryUrl",
        ),
        (
            "a statement about a field that is not marked",
            about_an_unmarked_field,
            "/personalData/productName",
        ),
        (
            "a basis the governing act does not admit",
            on_a_basis_the_act_does_not_admit,
            "/personalData/repairHistoryUrl/lawfulBasis",
        ),
        (
            "an outside statement naming no record",
            naming_no_record,
            "/personalData/repairHistoryUrl/record",
        ),
    ] {
        let created = refusal(client.post_json("/api/v1/dpp", body.clone()).await).await;
        let previewed = refusal(client.post_json("/api/v1/dpp/validate", body).await).await;

        assert_eq!(created.0, 422, "create refuses {what}");
        assert_eq!(
            previewed, created,
            "the dry run says what create says for {what}"
        );
        assert!(
            created.1["errors"]
                .as_array()
                .expect("the findings are addressable")
                .iter()
                .any(|e| e["field"] == field),
            "{what}: names {field}: {}",
            created.1
        );
    }

    let stated = textile_with_a_repair_history(Some(json!({ FIELD: { "held": "nothing" } })));
    let preview = client
        .post_json("/api/v1/dpp/validate", stated.clone())
        .await;
    assert_eq!(preview.status(), 200, "a stated field clears the preview");
    assert_eq!(
        client.post_json("/api/v1/dpp", stated).await.status(),
        201,
        "and create"
    );
}

/// The preview now builds the draft create builds, so it refuses a tariff code
/// create refuses. It passed one before, because that refusal lived in the
/// handler's own assembly of the passport.
#[tokio::test(flavor = "multi_thread")]
async fn the_dry_run_refuses_a_tariff_code_create_refuses() {
    let pg = start_postgres().await;
    let url = start_vault(pg.dal.clone()).await;
    let client = admin(&url);

    let mut body = textile_with_a_repair_history(Some(json!({ FIELD: { "held": "nothing" } })));
    body["commodityCode"] = json!("not a tariff code");

    let created = refusal(client.post_json("/api/v1/dpp", body.clone()).await).await;
    let previewed = refusal(client.post_json("/api/v1/dpp/validate", body).await).await;

    assert_eq!(created.0, 422, "{}", created.1);
    assert_eq!(previewed, created);
}

/// The preview runs core's own invariants on the draft, as create does, rather
/// than only the copy of some of them that the request check keeps.
///
/// A battery's two placing-on-market dates (the envelope's and the battery
/// data's own) must agree, and only `Passport::validate` compares them. It
/// reads the assembled record, so the request check never sees the pair. The
/// preview passed this body (`200`, `createValid: true`) while create refused
/// it.
#[tokio::test(flavor = "multi_thread")]
async fn the_dry_run_refuses_a_draft_core_refuses() {
    let pg = start_postgres().await;
    let url = start_vault(pg.dal.clone()).await;
    let client = admin(&url);

    let body = json!({
        "productName": "EcoBattery LFP 3000",
        "manufacturer": { "name": "Example Batteries GmbH", "address": "Berlin, DE" },
        "placedOnMarketDate": "2026-07-15",
        "productGroupData": {
            "productGroup": "battery",
            "productIdentifier": { "scheme": "gs1", "gtin": "09506000134352" },
            "batteryChemistry": "LFP",
            "batteryType": "portable",
            "nominalVoltageV": 48.0,
            "nominalCapacityAh": 100.0,
            "expectedLifetimeCycles": 3000,
            "co2ePerUnitKg": 45.2,
            "placedOnMarketDate": "2027-02-18"
        }
    });

    let created = refusal(client.post_json("/api/v1/dpp", body.clone()).await).await;
    let previewed = refusal(client.post_json("/api/v1/dpp/validate", body).await).await;

    assert_eq!(created.0, 422, "{}", created.1);
    assert!(
        created.1["errors"]
            .as_array()
            .expect("the findings are addressable")
            .iter()
            .any(|e| e["field"] == "/productGroupData/placedOnMarketDate"),
        "create refuses it for the dates: {}",
        created.1
    );
    assert_eq!(previewed, created, "the dry run says what create says");
}

// ---------------------------------------------------------------------------
// Storing and listing: `POST` and `GET /api/v1/dpp/{dppId}/personal-data`
// ---------------------------------------------------------------------------

/// A draft that says nothing is held about its marked field yet, which is the
/// state a client is in when it stores the record the statement will name.
async fn a_draft(client: &TestClient) -> String {
    let created: Value = client
        .post_json(
            "/api/v1/dpp",
            textile_with_a_repair_history(Some(json!({ FIELD: { "held": "nothing" } }))),
        )
        .await
        .json()
        .await
        .expect("created");
    created["id"].as_str().expect("an id").to_owned()
}

fn records_path(id: &str) -> String {
    format!("/api/v1/dpp/{id}/personal-data")
}

/// A store request for the marked field.
fn a_record_of(content: Value) -> Value {
    json!({ "field": FIELD, "content": content })
}

/// The records the route lists for a passport.
async fn listed(client: &TestClient, id: &str) -> Vec<Value> {
    let resp = client.get(&records_path(id)).await;
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.expect("a listing");
    body["records"].as_array().expect("records").clone()
}

/// 🚨 The whole path an operator takes, through the API and nothing else: store
/// the record, name it in the statement, list it, erase it. The content goes in
/// once and comes out of no route: the store answers without it, the listing
/// carries none in either state, and the passport never held it.
#[tokio::test(flavor = "multi_thread")]
async fn a_record_is_stored_named_listed_and_erased_by_the_routes_alone() {
    let pg = start_postgres().await;
    let url = start_vault(pg.dal.clone()).await;
    let client = admin(&url);
    let id = a_draft(&client).await;
    let content = json!({ "owner": "Ada Lovelace", "note": "named in the repair log" });

    let stored = client
        .post_json(&records_path(&id), a_record_of(content.clone()))
        .await;
    assert_eq!(stored.status(), 201);
    let stored: Value = stored.json().await.expect("a summary");
    let record = stored["record"].as_str().expect("an id").to_owned();
    assert_eq!(stored["field"], FIELD);
    assert_eq!(stored["state"], "present");
    assert!(stored["storedAt"].is_string(), "{stored}");
    assert!(stored.get("erasedAt").is_none(), "{stored}");
    assert!(
        !stored.to_string().contains("Ada Lovelace"),
        "the answer to a store carries no content: {stored}"
    );

    // The content was kept, as sent, for this passport.
    let port = PgPersonalDataRepo::new(pg.dal.clone());
    let held = port
        .fetch(&dpp_domain::PersonalDataRecordId::new(record.clone()))
        .await
        .expect("fetch");
    let Some(HeldRecord::Present(held)) = held else {
        panic!("the record is held: {held:?}");
    };
    assert_eq!(held.content, content);
    assert_eq!(held.passport_id.0.to_string(), id);

    // The statement is written after the store, naming the id the store answered.
    let statement = json!({
        FIELD: { "held": "outside", "lawfulBasis": "consent", "record": record }
    });
    let patched = client
        .put_json(
            &format!("/api/v1/dpp/{id}"),
            json!({ "personalData": statement }),
        )
        .await;
    assert_eq!(
        patched.status(),
        200,
        "the draft may name the stored record"
    );
    let passport = client.get(&format!("/api/v1/dpp/{id}")).await.text().await;
    assert!(
        !passport.expect("a body").contains("Ada Lovelace"),
        "the passport never holds the content"
    );

    let records = listed(&client, &id).await;
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["record"], record);
    assert_eq!(records[0]["field"], FIELD);
    assert_eq!(records[0]["state"], "present");
    assert!(records[0]["storedAt"].is_string());
    assert!(records[0].get("erasedAt").is_none());

    let erased = client
        .delete(&format!("/api/v1/personal-data/{record}"))
        .await;
    assert_eq!(erased.status(), 200);

    let records = listed(&client, &id).await;
    assert_eq!(records.len(), 1, "an erased record is still listed");
    assert_eq!(records[0]["record"], record);
    assert_eq!(records[0]["state"], "erased");
    assert!(records[0]["erasedAt"].is_string());
    assert!(
        records[0].get("storedAt").is_none(),
        "a tombstone keeps when it was erased and nothing else: {}",
        records[0]
    );
    assert!(
        !serde_json::to_string(&records)
            .unwrap()
            .contains("Ada Lovelace"),
        "no listing carries the content, in either state"
    );
}

/// The route takes no `Idempotency-Key`, so a retry is a second record. The
/// listing is how a caller that lost the first answer finds it, and the order is
/// the order they were stored.
#[tokio::test(flavor = "multi_thread")]
async fn a_retried_store_holds_a_second_record_and_the_listing_finds_both() {
    let pg = start_postgres().await;
    let url = start_vault(pg.dal.clone()).await;
    let client = admin(&url);
    let id = a_draft(&client).await;
    let body = a_record_of(json!({ "note": "the same request twice" }));

    let first: Value = client
        .post_json(&records_path(&id), body.clone())
        .await
        .json()
        .await
        .expect("a summary");
    let second: Value = client
        .post_json(&records_path(&id), body)
        .await
        .json()
        .await
        .expect("a summary");
    assert_ne!(first["record"], second["record"], "every store mints an id");

    let records = listed(&client, &id).await;
    let ids: Vec<&Value> = records.iter().map(|r| &r["record"]).collect();
    assert_eq!(ids, [&first["record"], &second["record"]], "oldest first");
}

/// Every refusal of a store holds nothing: the listing is empty afterwards, so a
/// refusal is not merely a status. The `422` names what the caller can do.
#[tokio::test(flavor = "multi_thread")]
async fn a_refused_store_holds_nothing() {
    let pg = start_postgres().await;
    let url = start_vault(pg.dal.clone()).await;
    let client = admin(&url);
    let id = a_draft(&client).await;
    let path = records_path(&id);

    // A field the schema does not mark: no statement could name a record for it.
    let (status, problem) = refusal(
        client
            .post_json(
                &path,
                json!({ "field": "careInstructions", "content": "x" }),
            )
            .await,
    )
    .await;
    assert_eq!(status, 422);
    let detail = problem["detail"].as_str().expect("a detail");
    assert!(
        detail.contains("'careInstructions' is not a field"),
        "{detail}"
    );
    assert!(
        detail.contains(FIELD),
        "the detail lists the fields that are marked: {detail}"
    );

    // A blank field is not a marked one either.
    let (status, _) = refusal(
        client
            .post_json(&path, json!({ "field": "", "content": "x" }))
            .await,
    )
    .await;
    assert_eq!(status, 422);

    // `null` is no content: a record holds something or is erased.
    let (status, problem) = refusal(
        client
            .post_json(&path, json!({ "field": FIELD, "content": null }))
            .await,
    )
    .await;
    assert_eq!(status, 422);
    assert!(
        problem["detail"].as_str().unwrap().contains("null"),
        "{problem}"
    );

    // A body that is not the documented one: no content, or a member it does not
    // define.
    for body in [
        json!({ "field": FIELD }),
        json!({ "field": FIELD, "content": "x", "passportId": id }),
    ] {
        let (status, _) = refusal(client.post_json(&path, body.clone()).await).await;
        assert_eq!(status, 422, "{body}");
    }

    assert!(
        listed(&client, &id).await.is_empty(),
        "five refusals, and nothing was stored"
    );
}

/// `409` and `422` are told apart: a passport that is no longer a draft is
/// refused for that, whatever the body says, and it can still be listed — a
/// record outlives the draft it was stored for.
#[tokio::test(flavor = "multi_thread")]
async fn only_a_draft_takes_a_record_and_a_passport_of_any_status_can_be_listed() {
    let pg = start_postgres().await;
    let url = start_vault(pg.dal.clone()).await;
    let client = admin(&url);
    let id = a_draft(&client).await;

    let stored = client
        .post_json(&records_path(&id), a_record_of(json!("held while a draft")))
        .await;
    assert_eq!(stored.status(), 201);

    let retired = client
        .post_json(&format!("/api/v1/dpp/{id}/retire"), json!({}))
        .await;
    assert_eq!(retired.status(), 200, "a draft may be retired");

    let (status, problem) = refusal(
        client
            .post_json(&records_path(&id), a_record_of(json!("too late")))
            .await,
    )
    .await;
    assert_eq!(status, 409, "{problem}");

    // A body that would be a `422` on a draft is still a `409` here.
    let (status, _) = refusal(
        client
            .post_json(
                &records_path(&id),
                json!({ "field": "careInstructions", "content": null }),
            )
            .await,
    )
    .await;
    assert_eq!(
        status, 409,
        "the passport's state is judged before the body"
    );

    let records = listed(&client, &id).await;
    assert_eq!(records.len(), 1, "the refused store held nothing");
    assert_eq!(records[0]["state"], "present");
}

/// 🚨 The passport is judged before the body is read, and not only before it is
/// checked. A body the JSON extractor refuses on its own (a member missing, a
/// member the request does not have, text that is not JSON) used to be refused
/// before the handler ran, so a retired passport answered `422` where it answers
/// `409` to every other body, and an unknown one lost its `404`.
///
/// A draft reads the body and refuses it, each in its own way. A retired passport
/// and an unknown one do not read it, so the same three bodies get `409` and
/// `404`.
#[tokio::test(flavor = "multi_thread")]
async fn a_body_that_cannot_be_read_is_judged_after_the_passport() {
    let pg = start_postgres().await;
    let url = start_vault(pg.dal.clone()).await;
    let client = admin(&url);
    let token = make_jwt("00000000-0000-0000-0000-0000000000a1");
    let id = a_draft(&client).await;
    let unknown = uuid::Uuid::now_v7().to_string();

    // Sent as text, because what is under test is what the node does with bytes
    // it cannot read.
    let send = |passport: String, body: &'static str| {
        let request = reqwest::Client::new()
            .post(format!("{url}{}", records_path(&passport)))
            .bearer_auth(&token)
            .header("content-type", "application/json")
            .body(body);
        async move { helpers::send_checked(request).await.status().as_u16() }
    };
    // What is wrong with the body, the body, and what a draft says to it.
    let unreadable: [(&str, &str, u16); 3] = [
        ("no `content`", r#"{"field":"repairHistoryUrl"}"#, 422),
        (
            "a member the request does not have",
            r#"{"field":"repairHistoryUrl","content":"x","owner":"someone"}"#,
            422,
        ),
        ("not JSON", "{not json", 400),
    ];

    for (what, body, on_a_draft) in unreadable {
        assert_eq!(
            send(id.clone(), body).await,
            on_a_draft,
            "a draft refuses a body with {what}"
        );
    }

    let retired = client
        .post_json(&format!("/api/v1/dpp/{id}/retire"), json!({}))
        .await;
    assert_eq!(retired.status(), 200, "a draft may be retired");

    for (what, body, _) in unreadable {
        assert_eq!(
            send(id.clone(), body).await,
            409,
            "a retired passport is a `409` whatever the body, even one with {what}"
        );
        assert_eq!(
            send(unknown.clone(), body).await,
            404,
            "an unknown passport is a `404` whatever the body, even one with {what}"
        );
    }

    assert!(
        listed(&client, &id).await.is_empty(),
        "no refusal stored anything"
    );
}

/// `404` means this node holds no such passport; a passport with nothing stored
/// is a `200` with an empty list. The pair an operator needs told apart, to know a
/// mistyped identifier from a passport that has no records.
#[tokio::test(flavor = "multi_thread")]
async fn an_unknown_passport_and_one_with_no_records_are_told_apart() {
    let pg = start_postgres().await;
    let url = start_vault(pg.dal.clone()).await;
    let client = admin(&url);
    let id = a_draft(&client).await;
    let unknown = uuid::Uuid::now_v7().to_string();

    assert!(
        listed(&client, &id).await.is_empty(),
        "nothing stored is a listing with nothing in it"
    );

    let resp = client.get(&records_path(&unknown)).await;
    assert_eq!(resp.status(), 404);
    assert_eq!(
        resp.headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok()),
        Some("application/problem+json")
    );

    let resp = client
        .post_json(&records_path(&unknown), a_record_of(json!("x")))
        .await;
    assert_eq!(
        resp.status(),
        404,
        "nothing is stored for a passport not held"
    );
}

/// The cap is 64 KiB of body, as the description says: a body over it is refused
/// with a problem document and stores nothing, one under it is held.
#[tokio::test(flavor = "multi_thread")]
async fn a_body_over_64_kib_is_refused_and_one_under_it_is_held() {
    let pg = start_postgres().await;
    let url = start_vault(pg.dal.clone()).await;
    let client = admin(&url);
    let id = a_draft(&client).await;
    let path = records_path(&id);

    let over = client
        .post_json(&path, a_record_of(json!("x".repeat(64 * 1024))))
        .await;
    assert_eq!(over.status(), 413);
    assert_eq!(
        over.headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok()),
        Some("application/problem+json")
    );
    assert!(listed(&client, &id).await.is_empty(), "nothing was stored");

    let under = client
        .post_json(&path, a_record_of(json!("x".repeat(64 * 1024 - 1024))))
        .await;
    assert_eq!(under.status(), 201, "a body under the cap is held");
}

/// A caller that cannot administer neither stores nor lists: the listing is as
/// sensitive as the records, and the refusal comes before anything is read or
/// written.
#[tokio::test(flavor = "multi_thread")]
async fn a_caller_without_the_admin_scope_stores_and_lists_nothing() {
    let pg = start_postgres().await;
    let url = start_vault(pg.dal.clone()).await;
    let client = admin(&url);
    let id = a_draft(&client).await;
    let path = records_path(&id);

    for scope in ["write", "read"] {
        let other = TestClient::new(&url, make_jwt_scoped("op", scope));
        let stored = other.post_json(&path, a_record_of(json!("refused"))).await;
        assert_eq!(stored.status(), 403, "a {scope}-scoped key must not store");
        assert_eq!(
            other.get(&path).await.status(),
            403,
            "a {scope}-scoped key must not list"
        );
    }

    let unauthenticated =
        helpers::send_checked(reqwest::Client::new().get(format!("{url}{path}"))).await;
    assert_eq!(unauthenticated.status(), 401);

    assert!(
        listed(&client, &id).await.is_empty(),
        "five refusals, and nothing was stored"
    );
}

/// What the node logs when it stores a record: who, and which record. Not the
/// data, and not the passport — the line is where the actor is kept, and a log is
/// read by people who are not entitled to the record.
///
/// The subscriber is global, because the vault serves from tasks on other
/// threads; this is the only test in the file that installs one.
#[tokio::test(flavor = "multi_thread")]
async fn a_store_logs_who_and_which_record_and_never_the_data_or_the_passport() {
    #[derive(Clone, Default)]
    struct Captured(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for Captured {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Captured {
        type Writer = Captured;
        fn make_writer(&'a self) -> Captured {
            self.clone()
        }
    }

    let captured = Captured::default();
    tracing_subscriber::fmt()
        .with_writer(captured.clone())
        .with_ansi(false)
        .with_max_level(tracing_subscriber::filter::LevelFilter::INFO)
        .try_init()
        .expect("no other test in this file installs a subscriber");

    let pg = start_postgres().await;
    let url = start_vault(pg.dal.clone()).await;
    let client = admin(&url);
    let id = a_draft(&client).await;

    let stored: Value = client
        .post_json(
            &records_path(&id),
            a_record_of(json!("marker-for-the-log-test")),
        )
        .await
        .json()
        .await
        .expect("a summary");
    let record = stored["record"].as_str().expect("an id");

    let log = String::from_utf8_lossy(&captured.0.lock().unwrap()).into_owned();
    let line = log
        .lines()
        .find(|l| l.contains("stored a personal data record"))
        .unwrap_or_else(|| panic!("a store is logged: {log}"));
    assert!(line.contains(record), "the line names the record: {line}");
    assert!(
        line.contains("00000000-0000-0000-0000-0000000000a1"),
        "and who stored it: {line}"
    );
    assert!(!line.contains(&id), "never the passport: {line}");
    assert!(
        !log.contains("marker-for-the-log-test"),
        "the data is in no log line at all"
    );
}
