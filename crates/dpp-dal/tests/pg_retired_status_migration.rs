//! `ops/pg/0041` must rewrite `doc`, not just the `status` column.
//!
//! # Why this test exists
//!
//! `passport.status` is a **projection**; `passport.doc` is the record. Reads go
//! `SELECT doc` → `Passport::from_stored`, and core 0.21.0 refuses `"archived"`
//! on deserialisation. So a migration that rewrote only the column would leave
//! every pre-rename row *unreadable* — a 500 per request, on exactly the
//! passports that already existed, with the column reading `retired` the whole
//! time so the migration looked like it had worked.
//!
//! That is the same failure as the `product_group` envelope rename, which cost
//! 244 of 276 passports. It was caught here by review rather than by a test,
//! which is why the test is now the thing that holds it.
//!
//! # It asserts both sides of the migration, on purpose
//!
//! A test that only checked the row reads afterwards would still pass if
//! `from_stored` had quietly started accepting `"archived"` — it would be
//! asserting nothing about the migration at all. So this first proves the row
//! is **unreadable before** 0041 runs, which is the hazard, and only then that
//! 0041 makes it readable. Delete the `doc` rewrite from the migration and the
//! second half fails; make core accept the old value and the first half fails.

#![cfg(feature = "integration-tests")]

use chrono::Utc;

use dpp_dal::pg::{PgDal, PgPassportRepo};
use dpp_dal::test_harness::start_pg_before;
use dpp_domain::passport::{ManufacturerInfo, Passport, PassportId};
use dpp_domain::ports::passport_repo::PassportRepository;
use dpp_domain::product_group::ProductGroup;
use dpp_domain::status::PassportStatus;

/// A passport as a pre-rename node would have stored it: everything current
/// except the one word.
///
/// Built by serialising a `Retired` passport and putting the old spelling back,
/// because core can no longer produce `"archived"` — which is the point of the
/// change and also why the fixture has to be made this way rather than by
/// constructing the old variant.
fn doc_with_the_old_spelling(id: PassportId) -> serde_json::Value {
    let passport = Passport {
        id,
        batch_id: None,
        serial_number: None,
        product_name: "Pre-rename Battery".into(),
        product_group: ProductGroup::Battery,
        applicable_instruments: Vec::new(),
        granularity: None,
        manufacturer: ManufacturerInfo {
            name: "TestCorp GmbH".into(),
            address: "Berlin, DE".into(),
            registered_trade_name: None,
            electronic_address: None,
            country: None,
            did_web_url: None,
        },
        materials: vec![],
        co2e_per_unit: None,
        repairability_score: None,
        compliance_result: None,
        lint_result: None,
        product_group_data: None,
        status: PassportStatus::Retired,
        qr_code_url: None,
        jws_signature: None,
        public_jws_signature: None,
        disclosure_signatures: Default::default(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        published_at: None,
        placed_on_market_date: None,
        schema_version: "2.0.0".into(),
        retention_locked: false,
        version: 1,
        supersedes_id: None,
        derived_from: Vec::new(),
        component_refs: Vec::new(),
        life_status: None,
        retention_until: None,
        product_id: None,
        commodity_code: None,
        operator_identifier: None,
        responsible_operator: None,
        facility: None,
        seal: None,
    };

    let mut doc = serde_json::to_value(&passport).expect("serialise passport");
    doc["status"] = serde_json::Value::String("archived".into());
    doc
}

#[tokio::test(flavor = "multi_thread")]
async fn migration_0041_rewrites_the_document_not_only_the_column() {
    let pg = start_pg_before("0041_").await;

    let admin = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&pg.admin_url)
        .await
        .expect("admin connect");

    let id = PassportId::new();
    let doc = doc_with_the_old_spelling(id);

    // Same column-from-`doc` derivation the repository's own INSERT uses, so
    // the row is shaped exactly as a pre-rename node would have written it —
    // including `status` taking the old spelling from the document.
    sqlx::query(
        r#"INSERT INTO odal.passport
             (id, product_group, status, retention_locked, schema_version,
              version, created_at, updated_at, doc)
           VALUES ($1,
                   $2->>'productGroup',
                   COALESCE($2->>'status','draft'),
                   COALESCE(($2->>'retentionLocked')::boolean, false),
                   COALESCE($2->>'schemaVersion','1.0.0'),
                   COALESCE(($2->>'version')::integer, 1),
                   now(), now(), $2)"#,
    )
    .bind(id.0)
    .bind(&doc)
    .execute(&admin)
    .await
    .expect("insert a pre-rename row");

    // ── Before: the hazard is real ──────────────────────────────────────────
    let dal = PgDal::connect(&pg.app_url).await.expect("dal connect");
    let repo = PgPassportRepo::new(dal);
    let before = repo.find_by_id(id).await;
    assert!(
        before.is_err(),
        "a row whose doc still says \"archived\" must fail to read — if this \
         passes, core accepts the old value again and the migration below is \
         no longer what keeps these rows readable"
    );

    // ── Apply 0041 ──────────────────────────────────────────────────────────
    // Straight from the file: the manual 0001–0040 run leaves `_sqlx_migrations`
    // empty, so `PgDal::migrate` would try to replay them.
    let sql = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../ops/pg/0041_retired_status.sql"
    ))
    .expect("read 0041");
    // Repo-controlled migration text from ops/pg, not caller input.
    sqlx::raw_sql(sqlx::AssertSqlSafe(sql))
        .execute(&admin)
        .await
        .expect("apply 0041");

    // ── After: the record reads, and reads as Retired ───────────────────────
    let after = repo
        .find_by_id(id)
        .await
        .expect("0041 must leave the document readable")
        .expect("the row is still there");
    assert_eq!(
        after.status,
        PassportStatus::Retired,
        "the document's status must carry the new spelling, not just the column"
    );

    // And the projection agrees with it.
    let column: String = sqlx::query_scalar("SELECT status FROM odal.passport WHERE id = $1")
        .bind(id.0)
        .fetch_one(&admin)
        .await
        .expect("read the status column");
    assert_eq!(column, "retired", "the projection must follow the document");
}
