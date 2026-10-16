//! The personal-data store, against a real PostgreSQL (`ops/pg/0043`).
//!
//! Core states the contract in `dpp_domain::ports::personal_data` and tests it
//! against an in-memory holder. What these cover that a holder in memory cannot:
//!
//! 1. **The contract holds on the real table** — the same cases, through the
//!    SQL: a tombstone with no content, a retried erasure handing back the first
//!    receipt, a listing per passport that includes what was erased.
//! 2. **A lost answer does not lose the record.** A `store` whose answer never
//!    arrived still committed a row; it is found through `records_for`.
//! 3. **Two erasures racing are handed one receipt.** The retry rule is a
//!    property of the `UPDATE ... WHERE erased_at IS NULL` and the row lock, and
//!    only concurrent connections can show it.
//! 4. **The database refuses what the Rust never asks for.** The app role cannot
//!    `DELETE` a tombstone, rewrite a record, or bring an erased one back, and
//!    neither can the trigger's other callers: a superuser's `UPDATE` hits it
//!    too.
//! 5. **Erasing touches nothing else** — not the passport row, not another
//!    record.

#![cfg(feature = "integration-tests")]

use dpp_dal::pg::{PgPersonalDataRepo, sqlx};
use dpp_dal::test_harness::{TestPg, start_pg};
use dpp_domain::DppError;
use dpp_domain::passport::PassportId;
use dpp_domain::personal_data::PersonalDataRecordId;
use dpp_domain::ports::personal_data::{HeldRecord, PersonalDataPort};
use serde_json::json;
use sqlx::Row as _;
use uuid::Uuid;

const FIELD: &str = "usageHistory.negativeEvents";

/// A row in `odal.passport`, which is all a record's foreign key asks of a
/// passport. Written as the superuser with a minimal `doc`: this suite is about
/// the record store, and the typed `Passport` builders the other suites carry
/// would add a sixth copy to say nothing more.
async fn a_passport(pg: &TestPg) -> PassportId {
    let id = Uuid::now_v7();
    let admin = sqlx::PgPool::connect(&pg.admin_url).await.expect("admin");
    sqlx::query(
        "INSERT INTO odal.passport (id, product_group, schema_version, doc)
           VALUES ($1, 'battery', '2.0.0', $2)",
    )
    .bind(id)
    .bind(json!({ "id": id, "productName": "Personal Data Test Battery" }))
    .execute(&admin)
    .await
    .expect("insert passport");
    admin.close().await;
    PassportId(id)
}

async fn admin(pg: &TestPg) -> sqlx::PgPool {
    sqlx::PgPool::connect(&pg.admin_url).await.expect("admin")
}

fn present(held: Option<HeldRecord>) -> dpp_domain::ports::personal_data::PersonalDataRecord {
    match held {
        Some(HeldRecord::Present(record)) => record,
        other => panic!("expected a present record, got {other:?}"),
    }
}

#[tokio::test]
async fn a_stored_record_is_held_under_the_identifier_it_was_given() {
    let pg = start_pg().await;
    let store = PgPersonalDataRepo::new(pg.dal.clone());
    let passport = a_passport(&pg).await;
    let content =
        json!({ "driver": "named in the accident report", "events": [1, 2, { "n": null }] });

    let id = store.store(passport, FIELD, &content).await.expect("store");

    let record = present(store.fetch(&id).await.expect("fetch"));
    assert_eq!(record.id, id);
    assert_eq!(record.passport_id, passport);
    assert_eq!(record.field, FIELD);
    assert_eq!(record.content, content);
}

/// JSON `null` is a value, and the controller keeps data "in whatever shape" it
/// likes. A column that read it back as SQL `NULL` would call a held record
/// erased.
#[tokio::test]
async fn a_record_whose_content_is_json_null_is_still_present() {
    let pg = start_pg().await;
    let store = PgPersonalDataRepo::new(pg.dal.clone());
    let passport = a_passport(&pg).await;

    let id = store
        .store(passport, FIELD, &serde_json::Value::Null)
        .await
        .expect("store");

    let record = present(store.fetch(&id).await.expect("fetch"));
    assert_eq!(record.content, serde_json::Value::Null);
}

/// The identifier goes into a signed passport that outlives the record.
#[tokio::test]
async fn every_store_mints_a_new_identifier_that_carries_nothing_of_the_content() {
    let pg = start_pg().await;
    let store = PgPersonalDataRepo::new(pg.dal.clone());
    let passport = a_passport(&pg).await;
    let content = json!("Jane Example");

    let first = store.store(passport, FIELD, &content).await.expect("store");
    let second = store.store(passport, FIELD, &content).await.expect("store");

    assert_ne!(first, second);
    assert!(!first.as_str().contains("Jane"));
    Uuid::parse_str(first.as_str()).expect("a UUID, not anything derived from the data");
}

/// Storing does not check that the field is marked: that is the passport's check,
/// made when the statement naming the record is written.
#[tokio::test]
async fn storing_does_not_ask_whether_the_field_is_marked() {
    let pg = start_pg().await;
    let store = PgPersonalDataRepo::new(pg.dal.clone());
    let passport = a_passport(&pg).await;

    store
        .store(passport, "productName", &json!("anything"))
        .await
        .expect("held");
}

#[tokio::test]
async fn erasure_keeps_a_tombstone_without_the_data() {
    let pg = start_pg().await;
    let store = PgPersonalDataRepo::new(pg.dal.clone());
    let passport = a_passport(&pg).await;
    let id = store
        .store(passport, FIELD, &json!("Jane Example"))
        .await
        .expect("store");

    let receipt = store.erase(&id).await.expect("erase");
    assert_eq!(receipt.record, id);
    assert_eq!(receipt.passport_id, passport);
    assert_eq!(receipt.field, FIELD);

    let held = store.fetch(&id).await.expect("fetch");
    assert_eq!(held, Some(HeldRecord::Erased(receipt)));

    // Not only absent from the Rust type: absent from the row.
    let admin = admin(&pg).await;
    let row = sqlx::query("SELECT content IS NULL AS no_content, to_jsonb(r)::text AS whole FROM odal.personal_data_record r")
        .fetch_one(&admin)
        .await
        .expect("the tombstone is a row");
    assert!(row.get::<bool, _>("no_content"));
    assert!(
        !row.get::<String, _>("whole").contains("Jane"),
        "nothing of the content survives anywhere in the row"
    );
}

/// 🚨 The retry rule. A caller that lost the answer asks again and is handed the
/// receipt it was always going to be given — not a second one with a later
/// instant, which would misstate when the data was erased.
#[tokio::test]
async fn a_retried_erasure_returns_the_first_receipt() {
    let pg = start_pg().await;
    let store = PgPersonalDataRepo::new(pg.dal.clone());
    let passport = a_passport(&pg).await;
    let id = store
        .store(passport, FIELD, &json!("x"))
        .await
        .expect("store");

    let first = store.erase(&id).await.expect("erase");
    // Long enough that a receipt stamped again would show a later instant.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let again = store.erase(&id).await.expect("a retry is safe");

    assert_eq!(first, again);
    assert_eq!(first.erased_at, again.erased_at);
}

/// Two callers racing to erase one record are both answered with the same
/// receipt: the second waits on the row, finds it erased, and reads the first's.
#[tokio::test(flavor = "multi_thread")]
async fn concurrent_erasures_are_handed_one_receipt() {
    let pg = start_pg().await;
    let store = std::sync::Arc::new(PgPersonalDataRepo::new(pg.dal.clone()));
    let passport = a_passport(&pg).await;
    let id = store
        .store(passport, FIELD, &json!("x"))
        .await
        .expect("store");

    let mut racers = Vec::new();
    for _ in 0..8 {
        let store = store.clone();
        let id = id.clone();
        racers.push(tokio::spawn(async move { store.erase(&id).await }));
    }
    let mut receipts = Vec::new();
    for racer in racers {
        receipts.push(
            racer
                .await
                .expect("joined")
                .expect("every caller is answered"),
        );
    }

    assert!(
        receipts.windows(2).all(|pair| pair[0] == pair[1]),
        "one receipt, handed to all eight: {receipts:?}"
    );
}

#[tokio::test]
async fn erasing_one_record_leaves_the_others_and_the_passport() {
    let pg = start_pg().await;
    let store = PgPersonalDataRepo::new(pg.dal.clone());
    let passport = a_passport(&pg).await;
    let erased = store
        .store(passport, FIELD, &json!("a"))
        .await
        .expect("store");
    let kept = store
        .store(passport, FIELD, &json!("b"))
        .await
        .expect("store");

    let admin = admin(&pg).await;
    let doc_before: serde_json::Value =
        sqlx::query_scalar("SELECT doc FROM odal.passport WHERE id = $1")
            .bind(passport.0)
            .fetch_one(&admin)
            .await
            .expect("doc");

    store.erase(&erased).await.expect("erase");

    present(store.fetch(&kept).await.expect("fetch"));
    let doc_after: serde_json::Value =
        sqlx::query_scalar("SELECT doc FROM odal.passport WHERE id = $1")
            .bind(passport.0)
            .fetch_one(&admin)
            .await
            .expect("doc");
    assert_eq!(
        doc_before, doc_after,
        "erasing a record does not touch the passport"
    );
}

#[tokio::test]
async fn an_identifier_never_minted_is_unknown() {
    let pg = start_pg().await;
    let store = PgPersonalDataRepo::new(pg.dal.clone());

    // One that could have been minted here and was not, and ones that never
    // could be: neither names a record, and both are answered alike.
    for stranger in [
        Uuid::now_v7().to_string(),
        "never-minted".to_owned(),
        String::new(),
    ] {
        let stranger = PersonalDataRecordId::new(stranger);
        assert_eq!(
            store.fetch(&stranger).await.expect("fetch"),
            None,
            "{stranger}"
        );
        assert!(
            matches!(store.erase(&stranger).await, Err(DppError::NotFound(_))),
            "{stranger}"
        );
    }
}

/// A `store` whose answer never arrived still left a row, and the caller must
/// be able to find it to erase it.
#[tokio::test]
async fn a_record_whose_identifier_was_lost_is_found_by_its_passport_and_erased() {
    let pg = start_pg().await;
    let store = PgPersonalDataRepo::new(pg.dal.clone());
    let passport = a_passport(&pg).await;
    let elsewhere = a_passport(&pg).await;

    // The caller's `store` committed and its answer was lost: the id is dropped
    // on the floor, which is exactly what losing it means.
    let _ = store
        .store(passport, FIELD, &json!("a"))
        .await
        .expect("store");
    let erased = store
        .store(passport, FIELD, &json!("b"))
        .await
        .expect("store");
    store
        .store(elsewhere, FIELD, &json!("c"))
        .await
        .expect("store");
    let receipt = store.erase(&erased).await.expect("erase");

    let held = store.records_for(passport).await.expect("records_for");
    assert_eq!(
        held.len(),
        2,
        "this passport's records only, erased ones too"
    );
    let HeldRecord::Present(lost) = &held[0] else {
        panic!("the first record stored is listed first, with its data: {held:?}");
    };
    assert_eq!(lost.content, json!("a"));
    assert_eq!(held[1], HeldRecord::Erased(receipt));

    store
        .erase(&lost.id)
        .await
        .expect("the lost record is erased by the id the listing gave");
    assert!(
        store
            .records_for(passport)
            .await
            .expect("records_for")
            .iter()
            .all(|h| matches!(h, HeldRecord::Erased(_))),
        "nothing is held for the passport any more"
    );
    assert!(
        matches!(
            store.records_for(elsewhere).await.expect("records_for")[0],
            HeldRecord::Present(_)
        ),
        "the other passport's record is untouched"
    );
}

/// Listed in the order stored, not the order the keys happen to sort.
#[tokio::test]
async fn records_for_lists_in_the_order_they_were_stored() {
    let pg = start_pg().await;
    let store = PgPersonalDataRepo::new(pg.dal.clone());
    let passport = a_passport(&pg).await;

    let mut stored = Vec::new();
    for n in 0..5 {
        stored.push(
            store
                .store(passport, FIELD, &json!(n))
                .await
                .expect("store"),
        );
    }
    // Erased out of order: a tombstone keeps its place.
    store.erase(&stored[3]).await.expect("erase");
    store.erase(&stored[0]).await.expect("erase");

    let listed: Vec<String> = store
        .records_for(passport)
        .await
        .expect("records_for")
        .into_iter()
        .map(|h| match h {
            HeldRecord::Present(r) => r.id.to_string(),
            HeldRecord::Erased(r) => r.record.to_string(),
        })
        .collect();
    let expected: Vec<String> = stored.iter().map(ToString::to_string).collect();
    assert_eq!(listed, expected);
}

#[tokio::test]
async fn a_passport_with_nothing_held_lists_nothing() {
    let pg = start_pg().await;
    let store = PgPersonalDataRepo::new(pg.dal.clone());
    let passport = a_passport(&pg).await;

    assert!(
        store
            .records_for(passport)
            .await
            .expect("records_for")
            .is_empty()
    );
}

/// The record hangs off a passport this node holds. Refused as the passport
/// being unknown, and nothing is written.
#[tokio::test]
async fn a_record_for_a_passport_this_node_does_not_hold_is_refused() {
    let pg = start_pg().await;
    let store = PgPersonalDataRepo::new(pg.dal.clone());

    let refused = store.store(PassportId::new(), FIELD, &json!("x")).await;
    assert!(matches!(refused, Err(DppError::NotFound(_))), "{refused:?}");

    let admin = admin(&pg).await;
    let held: i64 = sqlx::query_scalar("SELECT count(*) FROM odal.personal_data_record")
        .fetch_one(&admin)
        .await
        .expect("count");
    assert_eq!(held, 0);
}

/// What the app role is not allowed to do, tried as the app role: the grants are
/// the first line, and a tombstone is the controller's proof that it erased.
#[tokio::test]
async fn the_app_role_can_neither_delete_a_record_nor_rewrite_it() {
    let pg = start_pg().await;
    let store = PgPersonalDataRepo::new(pg.dal.clone());
    let passport = a_passport(&pg).await;
    let id = store
        .store(passport, FIELD, &json!("x"))
        .await
        .expect("store");
    let other = a_passport(&pg).await;
    store.erase(&id).await.expect("erase");
    let id = Uuid::parse_str(id.as_str()).expect("uuid");

    let app = sqlx::PgPool::connect(&pg.app_url).await.expect("app");

    let delete = sqlx::query("DELETE FROM odal.personal_data_record WHERE id = $1")
        .bind(id)
        .execute(&app)
        .await;
    assert!(
        delete.is_err(),
        "a tombstone is not the app role's to delete"
    );

    // Moving a record to another passport would hand its data to someone else.
    let repoint =
        sqlx::query("UPDATE odal.personal_data_record SET passport_id = $2 WHERE id = $1")
            .bind(id)
            .bind(other.0)
            .execute(&app)
            .await;
    assert!(
        repoint.is_err(),
        "UPDATE is granted on the two erasure columns only"
    );

    let still: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM odal.personal_data_record WHERE id = $1 AND passport_id <> $2",
    )
    .bind(id)
    .bind(other.0)
    .fetch_one(&app)
    .await
    .expect("count");
    assert_eq!(still, 1);
}

/// The trigger is the second line, and holds for the superuser too: an erased
/// record does not come back, and a present one is erased or left alone.
#[tokio::test]
async fn an_erased_record_cannot_be_brought_back_and_a_present_one_cannot_be_rewritten() {
    let pg = start_pg().await;
    let store = PgPersonalDataRepo::new(pg.dal.clone());
    let passport = a_passport(&pg).await;
    let erased = store
        .store(passport, FIELD, &json!("gone"))
        .await
        .expect("store");
    let present = store
        .store(passport, FIELD, &json!("held"))
        .await
        .expect("store");
    let receipt = store.erase(&erased).await.expect("erase");
    let erased = Uuid::parse_str(erased.as_str()).expect("uuid");
    let present = Uuid::parse_str(present.as_str()).expect("uuid");

    let admin = admin(&pg).await;

    let resurrect = sqlx::query(
        "UPDATE odal.personal_data_record SET content = '\"back\"', erased_at = NULL WHERE id = $1",
    )
    .bind(erased)
    .execute(&admin)
    .await
    .expect_err("an erased record stays erased");
    assert!(
        resurrect.to_string().contains("ODAL_PERSONAL_DATA"),
        "{resurrect}"
    );

    let restamp =
        sqlx::query("UPDATE odal.personal_data_record SET erased_at = now() WHERE id = $1")
            .bind(erased)
            .execute(&admin)
            .await
            .expect_err("the receipt is the first one");
    assert!(
        restamp.to_string().contains("ODAL_PERSONAL_DATA"),
        "{restamp}"
    );

    let rewrite =
        sqlx::query("UPDATE odal.personal_data_record SET content = '\"other\"' WHERE id = $1")
            .bind(present)
            .execute(&admin)
            .await
            .expect_err("a record is erased, not edited");
    assert!(
        rewrite.to_string().contains("ODAL_PERSONAL_DATA"),
        "{rewrite}"
    );

    assert_eq!(
        store
            .fetch(&PersonalDataRecordId::new(erased.to_string()))
            .await
            .expect("fetch"),
        Some(HeldRecord::Erased(receipt)),
        "the tombstone is as it was"
    );
}

/// Neither state can be half-written: the migration's CHECK.
#[tokio::test]
async fn a_row_is_present_or_erased_and_never_both_or_neither() {
    let pg = start_pg().await;
    let passport = a_passport(&pg).await;
    let admin = admin(&pg).await;

    for (content, erased_at) in [("'\"x\"'::jsonb", "now()"), ("NULL", "NULL")] {
        let sql = format!(
            "INSERT INTO odal.personal_data_record (id, passport_id, field, content, erased_at)
               VALUES ($1, $2, 'f', {content}, {erased_at})"
        );
        let refused = sqlx::query(sqlx::AssertSqlSafe(sql))
            .bind(Uuid::now_v7())
            .bind(passport.0)
            .execute(&admin)
            .await
            .expect_err("a row in neither state is refused");
        assert!(
            refused
                .to_string()
                .contains("personal_data_record_one_state"),
            "{refused}"
        );
    }
}
