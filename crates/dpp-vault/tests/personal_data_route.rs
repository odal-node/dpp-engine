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

    let unauthenticated = reqwest::Client::new()
        .delete(format!("{url}{path}"))
        .send()
        .await
        .expect("request");
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
