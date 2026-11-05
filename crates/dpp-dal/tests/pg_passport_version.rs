//! Postgres-backed tests for the version archive (`ops/pg/0040`).
//!
//! ✅ COMPLIANCE-PIN: EN 18221:2026 clause 4.2 (archiving).
//!
//! 🚨 Not `PassportStatus::Retired`, the terminal lifecycle state. The two wear
//! the same word and mean unrelated things — see the migration's header.
//!
//! What is here rather than in a unit test, and why each one has to be:
//!
//! 1. **The append-only trigger actually fires.** Keeping every archived version
//!    for the passport's whole lifetime is enforced by a trigger, and a trigger
//!    that was never exercised is a comment. Both arms —
//!    `UPDATE` and `DELETE` — because the trigger names both and a `BEFORE
//!    UPDATE OR DELETE` clause is one edit away from naming one.
//! 2. **A version can outlive what it is a version of.** `passport_id` carries
//!    no foreign key deliberately; the test that proves it is an insert for a
//!    passport that does not exist, which an FK would refuse.
//! 3. **`state_at`'s boundary.** `superseded_at` is the instant the *next*
//!    version took over, so asking as-of exactly that instant must answer with
//!    the successor. That is a `>` versus `>=` in one query and it is invisible
//!    in every test that does not land on the boundary exactly.
//! 4. **Every change archives what it replaced.** The repository archives in the
//!    transaction that makes each change, so this is where its writes and the
//!    migration run together: create archives nothing, and an update, a patch, a
//!    status change and each item of a batch archive the record before them.
//! 5. **A moment is answered once, whenever it is asked.** `state_at` waits for
//!    a change in progress on the passport, so a moment the change has stamped
//!    but not committed is not answered with the record from before it.

#![cfg(feature = "integration-tests")]

use chrono::{DateTime, TimeZone, Utc};

use dpp_dal::pg::{PgPassportRepo, PgPassportVersionRepo};
use dpp_dal::test_harness::{TestPg, sessions_waiting_for_a_lock, start_pg};
use dpp_domain::passport::{ManufacturerInfo, Passport, PassportId};
use dpp_domain::ports::passport_repo::PassportRepository;
use dpp_domain::product_group::ProductGroup;
use dpp_domain::status::PassportStatus;
use dpp_types::audit::PassportVersionStore;

/// Write `doc` as a version of `id`, superseded at `superseded_at`, as the app
/// role. The store archives only the record a change replaces, so a test that
/// needs a version at a chosen instant, or of no passport at all, writes the row.
async fn archive(
    pg: &TestPg,
    id: PassportId,
    doc: serde_json::Value,
    superseded_at: DateTime<Utc>,
) {
    sqlx::query(
        "INSERT INTO odal.passport_version (id, passport_id, doc, superseded_at)
         VALUES ($1, $2, $3, $4)",
    )
    .bind(uuid::Uuid::now_v7())
    .bind(id.0)
    .bind(doc)
    .bind(superseded_at)
    .execute(pg.dal.pool())
    .await
    .expect("the app role archives a version");
}

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
        personal_data: Default::default(),
        retention_until: None,
        product_id: None,
        commodity_code: None,
        operator_identifier: None,
        responsible_operator: None,
        facility: None,
        seal: None,
        carrier_serial: None,
    }
}

/// A change to a live passport leaves a readable version of what it replaced.
///
/// The whole design in one pass: the repository writes the change and the
/// version in one transaction, and the version that comes back is the passport
/// *before* the change — the one the clause calls the initial digital product
/// passport.
#[tokio::test]
async fn a_change_to_a_passport_leaves_the_version_it_replaced() {
    let pg = start_pg().await;
    let versions = PgPassportVersionRepo::new(pg.dal.clone());
    let repo = PgPassportRepo::new(pg.dal.clone());

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

/// Every kind of change archives the state it replaced.
///
/// The **pre**-change state, which is what makes the first change record the
/// initial passport — the version the clause names. Archiving the result
/// instead would leave the initial version unrecorded, and no later change
/// could recover it.
#[tokio::test]
async fn every_change_archives_what_it_replaced() {
    let pg = start_pg().await;
    let versions = PgPassportVersionRepo::new(pg.dal.clone());
    let repo = PgPassportRepo::new(pg.dal.clone());

    let created = repo.create(a_passport()).await.expect("create");
    let id = created.id;

    let mut changed = created.clone();
    changed.product_name = "Version Test Battery Mk II".into();
    repo.update(changed).await.expect("update");
    repo.patch_fields(
        id,
        serde_json::json!({ "productName": "Version Test Battery Mk III" }),
    )
    .await
    .expect("patch");
    repo.update_status(id, PassportStatus::Published)
        .await
        .expect("status");

    let names: Vec<_> = versions
        .versions(&id.to_string())
        .await
        .expect("versions")
        .into_iter()
        .map(|v| v.doc["productName"].clone())
        .collect();
    assert_eq!(
        names,
        [
            "Version Test Battery",
            "Version Test Battery Mk II",
            "Version Test Battery Mk III"
        ],
        "one version per change, each the state that change replaced — including the one a \
         status transition replaced, which it did not itself write"
    );
}

/// A bulk update archives every item.
///
/// `update_batch`'s trait default loops over `update`, which archives. A store
/// that grew its own bulk statement would have to archive in it as well, and
/// this is the test that would say so.
#[tokio::test]
async fn a_batch_update_archives_every_item() {
    let pg = start_pg().await;
    let versions = PgPassportVersionRepo::new(pg.dal.clone());
    let repo = PgPassportRepo::new(pg.dal.clone());

    let first = repo.create(a_passport()).await.expect("create");
    let second = repo.create(a_passport()).await.expect("create");
    repo.update_batch(vec![first.clone(), second.clone()]).await;

    for p in [first, second] {
        assert_eq!(
            versions
                .versions(&p.id.to_string())
                .await
                .expect("versions")
                .len(),
            1,
            "a bulk update is a change per item, and each one is archived"
        );
    }
}

/// Two changes made at once each archive the record the other left.
///
/// The archive is read under the lock the change takes, so the second change
/// waits for the first to commit and archives what the first wrote. Read without
/// that lock, both would archive the record they started from: the history would
/// hold the initial record twice and never the first change's result.
///
/// The row is held while both changes start, so both are at their archive before
/// either can take it.
#[tokio::test]
async fn two_changes_at_once_each_archive_what_the_other_left() {
    use std::time::{Duration, Instant};

    let pg = start_pg().await;
    let versions = PgPassportVersionRepo::new(pg.dal.clone());
    let repo = std::sync::Arc::new(PgPassportRepo::new(pg.dal.clone()));
    let created = repo.create(a_passport()).await.expect("create");
    let id = created.id;
    let patience = Duration::from_secs(10);

    let mut hold = pg.dal.pool().begin().await.expect("begin");
    sqlx::query("SELECT 1 FROM odal.passport WHERE id = $1 FOR UPDATE")
        .bind(id.0)
        .execute(&mut *hold)
        .await
        .expect("hold the passport row");

    let mut changes = Vec::new();
    for (waiting, name) in [(1, "Change A"), (2, "Change B")] {
        let repo = repo.clone();
        changes.push(tokio::spawn(async move {
            repo.patch_fields(id, serde_json::json!({ "productName": name }))
                .await
        }));
        let started = Instant::now();
        while sessions_waiting_for_a_lock(&pg).await < waiting {
            assert!(
                started.elapsed() < patience,
                "{name} never waited for the held row"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    hold.commit().await.expect("release the row");
    for change in changes {
        change.await.expect("join").expect("change");
    }

    let names: Vec<_> = versions
        .versions(&id.to_string())
        .await
        .expect("versions")
        .into_iter()
        .map(|v| v.doc["productName"].clone())
        .collect();
    let live = repo
        .find_by_id(id)
        .await
        .expect("read")
        .expect("exists")
        .product_name;
    let first = if live == "Change A" {
        "Change B"
    } else {
        "Change A"
    };
    assert_eq!(
        names,
        ["Version Test Battery", first],
        "the initial record, then what the first change to commit wrote; never the \
         initial record twice"
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

    archive(
        &pg,
        id,
        serde_json::json!({ "productName": "as it was" }),
        Utc::now(),
    )
    .await;

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

    // A version needs no passport row to exist.
    archive(
        &pg,
        orphan,
        serde_json::json!({ "productName": "gone" }),
        Utc::now(),
    )
    .await;

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
    // A live row to read beside the versions, which are written by hand below
    // so they can be stamped at chosen instants.
    let id = PgPassportRepo::new(pg.dal.clone())
        .create(a_passport())
        .await
        .expect("create")
        .id;

    let noon = Utc.with_ymd_and_hms(2026, 1, 1, 12, 0, 0).unwrap();
    let one = Utc.with_ymd_and_hms(2026, 1, 1, 13, 0, 0).unwrap();

    // "first" was current until noon; "second" was current from noon until one.
    archive(&pg, id, serde_json::json!({ "productName": "first" }), noon).await;
    archive(&pg, id, serde_json::json!({ "productName": "second" }), one).await;

    let before = versions
        .state_at(&id.to_string(), noon - chrono::Duration::seconds(1))
        .await
        .expect("as of")
        .version
        .expect("a version covers the time before the first change");
    assert_eq!(
        before.doc.get("productName").and_then(|v| v.as_str()),
        Some("first")
    );

    let at = versions
        .state_at(&id.to_string(), noon)
        .await
        .expect("as of")
        .version
        .expect("a version covers the instant of the first change");
    assert_eq!(
        at.doc.get("productName").and_then(|v| v.as_str()),
        Some("second"),
        "at the instant of a change, the answer is what the change produced"
    );

    assert!(
        versions
            .state_at(&id.to_string(), one)
            .await
            .expect("as of")
            .version
            .is_none(),
        "past the most recent change nothing is archived — the live record is the answer, \
         and this route deliberately does not serve it"
    );
}

/// A moment inside a change that has stamped its version but not committed is
/// answered once that change commits, and as it will be answered afterwards.
///
/// A change archives the record it replaces under the passport's lock, stamped
/// when it takes it, and its version is invisible until it commits. Read without
/// waiting for that lock, a moment after the stamp found no version past it and
/// the live record from before the change, then, asked again after the commit,
/// the live record from after it: two answers for one moment. The change is held
/// open here between its stamp and its commit, and the moment is asked inside it.
#[tokio::test]
async fn a_moment_inside_a_change_is_answered_as_it_is_after_the_commit() {
    use std::time::{Duration, Instant};

    let pg = start_pg().await;
    let versions = std::sync::Arc::new(PgPassportVersionRepo::new(pg.dal.clone()));
    let id = PgPassportRepo::new(pg.dal.clone())
        .create(a_passport())
        .await
        .expect("create")
        .id;

    // The change, as `PgPassportRepo` makes one: lock, archive, write. Held open.
    let mut change = pg.dal.pool().begin().await.expect("begin");
    sqlx::query("SELECT 1 FROM odal.passport WHERE id = $1 FOR UPDATE")
        .bind(id.0)
        .execute(&mut *change)
        .await
        .expect("lock the passport");
    sqlx::query(
        "INSERT INTO odal.passport_version (id, passport_id, doc, superseded_at)
         SELECT $1, id, doc, clock_timestamp() FROM odal.passport WHERE id = $2",
    )
    .bind(uuid::Uuid::now_v7())
    .bind(id.0)
    .execute(&mut *change)
    .await
    .expect("archive");
    sqlx::query(
        "UPDATE odal.passport SET doc = jsonb_set(doc, '{productName}', '\"Changed\"') \
         WHERE id = $1",
    )
    .bind(id.0)
    .execute(&mut *change)
    .await
    .expect("write");

    // A moment after the change's stamp, by the clock that stamped it.
    let at: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(pg.dal.pool())
        .await
        .expect("the database's clock");

    let during = tokio::spawn({
        let versions = versions.clone();
        async move { versions.state_at(&id.to_string(), at).await }
    });
    // The read waits for the change, or has nothing to wait on and finishes.
    let patience = Duration::from_secs(10);
    let started = Instant::now();
    while !during.is_finished() && sessions_waiting_for_a_lock(&pg).await < 1 {
        assert!(
            started.elapsed() < patience,
            "the read neither waited nor finished"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    change.commit().await.expect("commit the change");

    let during = during.await.expect("join").expect("read during the change");
    let after = versions
        .state_at(&id.to_string(), at)
        .await
        .expect("read after the change");
    let name = |live: &Option<serde_json::Value>| {
        live.as_ref()
            .map(|doc| doc["productName"].clone())
            .expect("the passport exists")
    };
    assert_eq!(
        (name(&during.live), during.version.map(|v| v.id)),
        (name(&after.live), after.version.map(|v| v.id)),
        "one moment, two answers: the read did not wait for the change in progress"
    );
    assert_eq!(name(&after.live), "Changed");
    assert!(
        during.read_at >= at,
        "the store's clock is read once it holds the row"
    );
}
