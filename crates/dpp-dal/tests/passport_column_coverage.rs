//! Every column on `odal.passport` is written, or documented as not being.
//!
//! Run with:
//! ```sh
//! cargo test -p dpp-dal --features integration-tests --test passport_column_coverage
//! ```
//!
//! # Why this exists
//!
//! `0004` reserved ten scalar columns for values that would live in the `doc`
//! JSONB, and no write path populated any of them. The data was never lost —
//! the document had it all along — but the projection was never connected, and
//! that is a quieter problem than a missing column.
//!
//! A column reads as authoritative whether or not anything writes it. `WHERE
//! supersedes_id IS NULL` returned every row; ordering by `version` ordered by
//! nothing; `retention_until` was exposed on the API response *and* sat NULL in
//! its own column, so the two disagreed and only one of them was right. Each of
//! those queries returns a result that looks like a fact about the data and is
//! an artefact of the column never having been written.
//!
//! # Why it asserts the value, not the statement text
//!
//! Grepping the repository source for a column name proves the name appears. It
//! does not prove the statement runs, that the JSON path it reads is the right
//! one, or that the cast succeeds — and a wrong path fails silently, because
//! `->>` on a missing key is SQL NULL rather than an error. So this inserts a
//! passport with every projected field populated, updates it, and reads the row
//! back as JSON: a column that is still NULL was not written, whatever the
//! source says.
//!
//! `to_jsonb(p)` rather than a column list, deliberately. The point is to fail
//! when a column is *added* and forgotten, and a hand-written list here would be
//! one more thing to forget.
//!
//! Scoped to `odal.passport` because that is the table the problem happened on.
//! The same shape would generalise, at the cost of an exception list per table.

#![cfg(feature = "integration-tests")]

use dpp_dal::pg::{PgPassportRepo, sqlx};
use dpp_dal::test_harness::start_pg;
use dpp_domain::{
    catalog::Granularity,
    compliance::{ComplianceResult, ComplianceStatus},
    passport::{ManufacturerInfo, Passport, PassportId},
    ports::passport_repo::PassportRepository,
    product_group::ProductGroup,
    status::PassportStatus,
};
use sqlx::Row;

/// Columns deliberately left unwritten, and why.
///
/// A drift log, not a place to silence the gate: an entry here is a claim that
/// the column should exist while nothing fills it, and that claim needs to be
/// true. Adding one is the last resort — writing the column, or dropping it,
/// are both better answers.
const UNWRITTEN: &[(&str, &str)] = &[(
    "serial_number",
    "reserved for an item-level unit serial the core library does not model — \
     `Passport` carries `granularity`, which has an `item` level, but no serial \
     to go with it. The AI 21 value in the GS1 carrier is derived from the \
     passport id and identifies the record rather than the product, so it is \
     not the value this column wants. Tracked upstream; the column is kept \
     rather than dropped because the field is expected, and this entry is the \
     thing that should disappear when it lands.",
)];

/// A passport with every projected field populated.
fn fully_populated(supersedes: Option<PassportId>) -> Passport {
    let now = chrono::Utc::now();
    Passport {
        id: PassportId::new(),
        batch_id: Some("LOT-COVERAGE-1".into()),
        product_name: "Column Coverage Battery".into(),
        product_group: ProductGroup::Battery,
        applicable_instruments: Vec::new(),
        granularity: Some(Granularity::Item),
        manufacturer: ManufacturerInfo {
            name: "TestCorp GmbH".into(),
            address: "Berlin, DE".into(),
            did_web_url: None,
        },
        materials: vec![],
        co2e_per_unit: None,
        repairability_score: None,
        compliance_result: Some(ComplianceResult {
            compliance_status: ComplianceStatus::PassthroughNoValidation,
            ruleset_version: Some("test-ruleset@0.0.0".into()),
            assessed_at: Some(now),
            ..ComplianceResult::default()
        }),
        lint_result: None,
        product_group_data: None,
        status: PassportStatus::Published,
        qr_code_url: None,
        jws_signature: None,
        public_jws_signature: None,
        disclosure_signatures: Default::default(),
        created_at: now,
        updated_at: now,
        published_at: Some(now),
        placed_on_market_date: None,
        schema_version: "2.0.0".into(),
        retention_locked: false,
        version: if supersedes.is_some() { 2 } else { 1 },
        supersedes_id: supersedes,
        parent_passport_ref: None,
        component_refs: Vec::new(),
        retention_until: Some(now + chrono::Duration::days(3650)),
        product_id: Some(uuid::Uuid::now_v7()),
        commodity_code: None,
        operator_identifier: None,
        facility: None,
        seal: None,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn every_passport_column_is_written_or_documented() {
    let pg = start_pg().await;
    let repo = PgPassportRepo::new(pg.dal.clone());

    // A predecessor first: `supersedes_id` is a self-referencing foreign key,
    // so it can only be exercised by pointing at a row that exists.
    let predecessor = fully_populated(None);
    let predecessor_id = predecessor.id;
    repo.create(predecessor).await.expect("create predecessor");

    let subject = fully_populated(Some(predecessor_id));
    let subject_id = subject.id;
    repo.create(subject.clone()).await.expect("create subject");

    // Through the update path too: `retention_until` is sealed at publish and is
    // never present at create, so an insert-only projection would leave it NULL
    // on every passport that has one.
    let mut updated = subject;
    updated.product_name = "Column Coverage Battery, corrected".into();
    repo.update(updated).await.expect("update subject");

    let row = sqlx::query("SELECT to_jsonb(p) AS row FROM odal.passport p WHERE id = $1")
        .bind(subject_id.0)
        .fetch_one(pg.dal.pool())
        .await
        .expect("read the row back");
    let columns: serde_json::Value = row.get("row");
    let columns = columns.as_object().expect("a row is a JSON object");

    let mut unwritten: Vec<&str> = Vec::new();
    for (name, value) in columns {
        if value.is_null() && !UNWRITTEN.iter().any(|(c, _)| c == name) {
            unwritten.push(name);
        }
    }
    unwritten.sort_unstable();
    assert!(
        unwritten.is_empty(),
        "these columns on odal.passport were NULL after a fully-populated insert \
         and update, so nothing writes them: {unwritten:?}\n\n\
         Write the column, drop it in a migration, or add it to UNWRITTEN with \
         the reason it should exist while nothing fills it."
    );

    // The exception list must describe reality. An entry that names a column the
    // table no longer has is a stale claim, and stale claims are how the list
    // stops being read.
    for (name, _why) in UNWRITTEN {
        assert!(
            columns.contains_key(*name),
            "UNWRITTEN names `{name}`, which is not a column on odal.passport — \
             drop the entry"
        );
    }
}

/// The two columns `0035` removed modelled nothing, and their absence is the
/// assertion: re-adding either without a field to fill it would put the table
/// back in the state this gate exists to prevent.
#[tokio::test(flavor = "multi_thread")]
async fn the_unmodelled_columns_are_gone() {
    let pg = start_pg().await;

    let row = sqlx::query(
        "SELECT count(*) AS n FROM information_schema.columns \
         WHERE table_schema = 'odal' AND table_name = 'passport' \
           AND column_name IN ('template_version', 'presentation_profile_id')",
    )
    .fetch_one(pg.dal.pool())
    .await
    .expect("query information_schema");

    assert_eq!(
        row.get::<i64, _>("n"),
        0,
        "template_version and presentation_profile_id reference a product-template \
         and presentation-profile model that does not exist; 0035 dropped them"
    );
}
