//! Postgres-backed tests for the version archive (`ops/pg/0040`).
//!
//! ✅ COMPLIANCE-PIN: EN 18221:2026 clause 4.2 (archiving).
//!
//! 🚨 Not `PassportStatus::Archived`, the terminal lifecycle state. The two wear
//! the same word and mean unrelated things — see the migration's header.
//!
//! What is here rather than in a unit test, and why each one has to be:
//!
//! 1. **The append-only trigger actually fires.** "All archived versions shall be
//!    maintained during the digital product passport lifetime" is enforced by a
//!    trigger, and a trigger that was never exercised is a comment. Both arms —
//!    `UPDATE` and `DELETE` — because the trigger names both and a `BEFORE
//!    UPDATE OR DELETE` clause is one edit away from naming one.
//! 2. **A version can outlive what it is a version of.** `passport_id` carries
//!    no foreign key deliberately; the test that proves it is an insert for a
//!    passport that does not exist, which an FK would refuse.
//! 3. **`version_at`'s boundary.** `superseded_at` is the instant the *next*
//!    version took over, so asking as-of exactly that instant must answer with
//!    the successor. That is a `>` versus `>=` in one query and it is invisible
//!    in every test that does not land on the boundary exactly.
//! 4. **The decorator, the repository and the migration compose.** Each is
//!    tested alone; this is the only place the three run together against a real
//!    database, which is where the `doc` column's shape and the archive's shape
//!    have to agree.

#![cfg(feature = "integration-tests")]

use chrono::{TimeZone, Utc};

use dpp_dal::pg::{ArchivingPassportRepo, PgPassportRepo, PgPassportVersionRepo};
use dpp_dal::test_harness::start_pg;
use dpp_domain::passport::{ManufacturerInfo, Passport, PassportId};
use dpp_domain::ports::passport_repo::PassportRepository;
use dpp_domain::product_group::ProductGroup;
use dpp_domain::status::PassportStatus;
use dpp_types::audit::PassportVersionStore;

fn a_passport() -> Passport {
    Passport {
        id: PassportId::new(),
        batch_id: None,
        serial_number: None,
        product_name: "Version Test Battery".into(),
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
        status: PassportStatus::Draft,
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
    }
}

/// A change to a live passport leaves a readable version of what it replaced.
///
/// The whole design in one pass: the decorator wraps the real repository, the
/// real repository writes to the real table, and the version that comes back is
/// the passport *before* the change — the one the clause calls the initial
/// digital product passport.
#[tokio::test]
async fn a_change_to_a_passport_leaves_the_version_it_replaced() {
    let pg = start_pg().await;
    let versions = std::sync::Arc::new(PgPassportVersionRepo::new(pg.dal.clone()));
    let repo = ArchivingPassportRepo::new(PgPassportRepo::new(pg.dal.clone()), versions.clone());

    let created = repo.create(a_passport()).await.expect("create");
    let id = created.id;

    assert!(
        versions
            .versions(&id.to_string())
            .await
            .expect("versions")
            .is_empty(),
        "create is not a change, so nothing is archived yet"
    );

    let mut changed = created.clone();
    changed.product_name = "Version Test Battery Mk II".into();
    repo.update(changed).await.expect("update");

    let archived = versions.versions(&id.to_string()).await.expect("versions");
    assert_eq!(archived.len(), 1, "one change, one version");
    assert_eq!(archived[0].passport_id, id.to_string());
    assert_eq!(
        archived[0].doc.get("productName").and_then(|v| v.as_str()),
        Some("Version Test Battery"),
        "the archived version is the passport as it was, not as it became"
    );
    assert_eq!(
        repo.find_by_id(id)
            .await
            .expect("read")
            .expect("present")
            .product_name,
        "Version Test Battery Mk II",
        "and the live record is the present"
    );
}

/// An archived version cannot be rewritten or removed.
///
/// 🚨 The grant withholds `UPDATE` and `DELETE` as well, so this asserts through
/// the **privileged** connection: a test that only proved the app role lacks the
/// grant would pass identically if the trigger were dropped, and the trigger is
/// the statement that survives someone re-granting.
#[tokio::test]
async fn an_archived_version_can_be_neither_rewritten_nor_removed() {
    let pg = start_pg().await;
    let versions = PgPassportVersionRepo::new(pg.dal.clone());
    let id = PassportId::new();

    versions
        .archive(
            &id.to_string(),
            &serde_json::json!({ "productName": "as it was" }),
            Utc::now(),
        )
        .await
        .expect("archive");

    let admin = sqlx::PgPool::connect(&pg.admin_url)
        .await
        .expect("privileged connection");

    let update = sqlx::query("UPDATE odal.passport_version SET doc = '{}'::jsonb")
        .execute(&admin)
        .await
        .expect_err("an archived version must not be rewritable");
    assert!(
        update.to_string().contains("ODAL_VERSION"),
        "the append-only trigger should be what refuses it: {update}"
    );

    let delete = sqlx::query("DELETE FROM odal.passport_version")
        .execute(&admin)
        .await
        .expect_err("an archived version must not be removable");
    assert!(
        delete.to_string().contains("ODAL_VERSION"),
        "the append-only trigger should be what refuses it: {delete}"
    );

    assert_eq!(
        versions
            .versions(&id.to_string())
            .await
            .expect("versions")
            .len(),
        1,
        "and the row is still there after both attempts"
    );
}

/// A version outlives the passport it is a version of.
///
/// `passport_id` carries no foreign key, and this is what that costs and buys: a
/// version may be written for a passport row that does not exist, which is the
/// same permission that stops a deleted passport taking its history with it.
/// With an FK and a cascade, the archive would be deletable by deleting the
/// thing it exists to remember.
#[tokio::test]
async fn a_version_may_exist_without_the_passport_it_belongs_to() {
    let pg = start_pg().await;
    let versions = PgPassportVersionRepo::new(pg.dal.clone());
    let orphan = PassportId::new();

    versions
        .archive(
            &orphan.to_string(),
            &serde_json::json!({ "productName": "gone" }),
            Utc::now(),
        )
        .await
        .expect("a version needs no passport row to exist");

    assert_eq!(
        versions
            .versions(&orphan.to_string())
            .await
            .expect("versions")
            .len(),
        1
    );
}

/// As of the exact instant of a change, the answer is what the change produced.
///
/// `superseded_at` is the moment a version *stopped* being current, so at that
/// instant its successor is already the one in force. The query says `>` rather
/// than `>=` for this reason, and nothing but a probe landing exactly on the
/// boundary can tell the two apart.
#[tokio::test]
async fn as_of_the_moment_of_a_change_the_successor_is_current() {
    let pg = start_pg().await;
    let versions = PgPassportVersionRepo::new(pg.dal.clone());
    let id = PassportId::new();

    let noon = Utc.with_ymd_and_hms(2026, 1, 1, 12, 0, 0).unwrap();
    let one = Utc.with_ymd_and_hms(2026, 1, 1, 13, 0, 0).unwrap();

    // "first" was current until noon; "second" was current from noon until one.
    versions
        .archive(
            &id.to_string(),
            &serde_json::json!({ "productName": "first" }),
            noon,
        )
        .await
        .expect("archive");
    versions
        .archive(
            &id.to_string(),
            &serde_json::json!({ "productName": "second" }),
            one,
        )
        .await
        .expect("archive");

    let before = versions
        .version_at(&id.to_string(), noon - chrono::Duration::seconds(1))
        .await
        .expect("as of")
        .expect("a version covers the time before the first change");
    assert_eq!(
        before.doc.get("productName").and_then(|v| v.as_str()),
        Some("first")
    );

    let at = versions
        .version_at(&id.to_string(), noon)
        .await
        .expect("as of")
        .expect("a version covers the instant of the first change");
    assert_eq!(
        at.doc.get("productName").and_then(|v| v.as_str()),
        Some("second"),
        "at the instant of a change, the answer is what the change produced"
    );

    assert!(
        versions
            .version_at(&id.to_string(), one)
            .await
            .expect("as of")
            .is_none(),
        "past the most recent change nothing is archived — the live record is the answer, \
         and this route deliberately does not serve it"
    );
}
