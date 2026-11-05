//! A passport published against an older schema version can still change status.
//!
//! # Why this test exists
//!
//! Every read upcasts `productGroupData` through the lens chain, so a passport
//! stored in an older shape comes back in the current one. A status change is a
//! read-modify-write: it loads that upcast passport, sets the status and hands
//! the whole document back to the update. On a draft that is harmless. On a
//! published passport it rewrites content its signatures commit to, and
//! `passport_retention_guard` refuses it.
//!
//! That shipped. Core 0.22.0 rewrites every product group's `gtin` as a scheme 1
//! `productIdentifier`, and a node upgraded over passports published under core
//! 0.20.0 could no longer suspend, retire or supersede any of them: each write
//! came back `RetentionLocked`, a 500 at the route. `amend` was worse than a
//! refusal, because it publishes the successor before it supersedes the
//! predecessor, so it left both live.
//!
//! The fixture is the frozen battery 2.6.0 document, a real published passport
//! that differs from its own reading in both ways that matter: it still carries
//! the bare `gtin` the lens converts, and its `manufacturer` predates `country`,
//! which the current struct writes as `null`. Neither is a change anyone made.
//!
//! # Both directions, on purpose
//!
//! A fix that simply stopped writing content keys to a locked row would pass the
//! first two tests and turn the guard's refusal of a real edit into a silent
//! no-op. The third test holds that line: an edit to the content is still
//! refused.
//!
//! # What a change archives
//!
//! EN 18221 clause 4.2 archives the version a change replaces, and the version
//! is the record as it was stored. A reading of it is this build's upcast,
//! carrying a `productIdentifier` the operator never published, so a version
//! archived from a reading would not hold what was signed. Every writer is
//! checked here against the same old shape.

#![cfg(feature = "integration-tests")]

use std::path::Path;

use dpp_dal::pg::{PgPassportRepo, PgPassportVersionRepo, PgRegistrySyncRepo, PgStateChangeLog};
use dpp_dal::test_harness::{TestPg, start_pg};
use dpp_domain::DppError;
use dpp_domain::passport::{Passport, PassportId};
use dpp_domain::ports::passport_repo::PassportRepository;
use dpp_domain::status::PassportStatus;
use dpp_types::audit::{PassportAuditEntry, PassportVersionStore};
use dpp_types::registry_sync::RegistrySyncOutbox;
use dpp_types::state_change::{PassportWrite, StateChange, StateChangeLog};
use serde_json::Value;

/// The frozen battery 2.6.0 document: published, retention-locked, signed, and
/// in the shape the `gtin` → `productIdentifier` lens upcasts.
fn published_before_the_lens_hop() -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/passport_docs/battery/v2.6.0.json");
    let doc: Value =
        serde_json::from_str(&std::fs::read_to_string(path).expect("read the fixture"))
            .expect("the fixture is JSON");
    assert!(
        doc["retentionLocked"] == true && doc["productGroupData"]["gtin"].is_string(),
        "the fixture must be a locked passport still carrying the pre-lens `gtin`, \
         or this test no longer exercises the upcast"
    );
    doc
}

/// Store `doc` under a fresh id, as the node that published it wrote it.
///
/// Written as the superuser with the repository's own column derivation, so the
/// row is the old node's bytes rather than anything this build serialised.
async fn seed(pg: &TestPg, mut doc: Value) -> PassportId {
    let id = PassportId::new();
    doc["id"] = Value::String(id.to_string());
    sqlx::query(
        r#"INSERT INTO odal.passport
             (id, product_group, status, retention_locked, schema_version,
              version, created_at, updated_at, published_at, doc)
           VALUES ($1,
                   $2->>'productGroup',
                   COALESCE($2->>'status','draft'),
                   COALESCE(($2->>'retentionLocked')::boolean, false),
                   COALESCE($2->>'schemaVersion','1.0.0'),
                   COALESCE(($2->>'version')::integer, 1),
                   now(), now(),
                   NULLIF($2->>'publishedAt','')::timestamptz,
                   $2)"#,
    )
    .bind(id.0)
    .bind(&doc)
    .execute(&admin(pg).await)
    .await
    .expect("insert the published row");
    id
}

async fn admin(pg: &TestPg) -> sqlx::PgPool {
    sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&pg.admin_url)
        .await
        .expect("admin connect")
}

/// The row's stored `doc`, read raw: no lens, no deserialisation.
async fn stored(pg: &TestPg, id: PassportId) -> Value {
    sqlx::query_scalar("SELECT doc FROM odal.passport WHERE id = $1")
        .bind(id.0)
        .fetch_one(&admin(pg).await)
        .await
        .expect("read the stored doc")
}

/// Every archived `doc` of `id`, oldest first, from the store the versions route
/// serves.
async fn archived(pg: &TestPg, id: PassportId) -> Vec<Value> {
    PgPassportVersionRepo::new(pg.dal.clone())
        .versions(&id.to_string())
        .await
        .expect("read the archive")
        .into_iter()
        .map(|version| version.doc)
        .collect()
}

/// Every stored key a status change does not own is byte-identical to what was
/// signed: the change wrote `status` and `updatedAt`, and nothing it only read.
fn only_the_status_moved(before: &Value, after: &Value) {
    let keys: std::collections::BTreeSet<&String> = before
        .as_object()
        .expect("object")
        .keys()
        .chain(after.as_object().expect("object").keys())
        .collect();
    for key in keys {
        if matches!(key.as_str(), "id" | "status" | "updatedAt") {
            continue;
        }
        assert_eq!(
            after.get(key),
            before.get(key),
            "`{key}` must stay as it was stored, not take this build's reading of it"
        );
    }
}

#[tokio::test]
async fn a_passport_published_before_a_lens_hop_can_still_change_status() {
    let pg = start_pg().await;
    let before = published_before_the_lens_hop();
    let id = seed(&pg, before.clone()).await;
    let repo = PgPassportRepo::new(pg.dal.clone());

    let suspended = repo
        .update_status(id, PassportStatus::Suspended)
        .await
        .expect("a published passport in an older shape must still change status");
    assert_eq!(suspended.status, PassportStatus::Suspended);

    let after = stored(&pg, id).await;
    assert_eq!(after["status"], "suspended");
    only_the_status_moved(&before, &after);

    let read = repo.find_by_id(id).await.expect("read").expect("exists");
    assert!(
        read.product_group_data
            .as_ref()
            .and_then(dpp_domain::product_group::ProductGroupData::product_identifier)
            .is_some(),
        "reads still see the current shape: the lens runs on the way out"
    );
}

#[tokio::test]
async fn a_status_change_archives_the_record_as_it_was_stored() {
    let pg = start_pg().await;
    let id = seed(&pg, published_before_the_lens_hop()).await;
    let before = stored(&pg, id).await;

    PgPassportRepo::new(pg.dal.clone())
        .update_status(id, PassportStatus::Suspended)
        .await
        .expect("suspend");

    assert_eq!(
        archived(&pg, id).await,
        [before],
        "the version is the stored record, still carrying its `gtin`, not this build's reading"
    );
}

#[tokio::test]
async fn the_state_change_log_archives_the_record_as_it_was_stored() {
    let pg = start_pg().await;
    let id = seed(&pg, published_before_the_lens_hop()).await;
    let before = stored(&pg, id).await;

    PgStateChangeLog::new(pg.dal.clone())
        .commit(
            StateChange::new(PassportAuditEntry::new(
                &id.to_string(),
                "suspended",
                "locked-upcast-test",
                Some("active"),
                Some("suspended"),
            ))
            .with_passport(PassportWrite::Status(id, PassportStatus::Suspended)),
        )
        .await
        .expect("the change commits");

    assert_eq!(archived(&pg, id).await, [before]);
}

/// A draft in the old shape, patched. The patch writes the stored document back
/// with the change merged in, and the version is that document before it.
#[tokio::test]
async fn a_patch_archives_the_record_as_it_was_stored() {
    let pg = start_pg().await;
    let mut draft = published_before_the_lens_hop();
    draft["status"] = "draft".into();
    draft["retentionLocked"] = false.into();
    let id = seed(&pg, draft).await;
    let before = stored(&pg, id).await;

    PgPassportRepo::new(pg.dal.clone())
        .patch_fields(id, serde_json::json!({ "productName": "Renamed" }))
        .await
        .expect("patch the draft");

    assert_eq!(archived(&pg, id).await, [before]);
}

/// `commit_publish` writes through the same statement as an update, so it
/// archives what it replaces like any other change.
#[tokio::test]
async fn a_publish_through_the_registry_outbox_archives_the_record_as_it_was_stored() {
    let pg = start_pg().await;
    let id = seed(&pg, published_before_the_lens_hop()).await;
    let repo = PgPassportRepo::new(pg.dal.clone());
    let mut passport = repo
        .update_status(id, PassportStatus::Suspended)
        .await
        .expect("suspend");
    let suspended = stored(&pg, id).await;

    passport.status = PassportStatus::Published;
    PgRegistrySyncRepo::new(pg.dal.clone())
        .commit_publish(&passport, serde_json::json!({}))
        .await
        .expect("re-publish");

    assert_eq!(
        archived(&pg, id).await.last(),
        Some(&suspended),
        "the re-publish archives the suspended record it replaced"
    );
}

#[tokio::test]
async fn the_state_change_log_suspends_it_too() {
    let pg = start_pg().await;
    let before = published_before_the_lens_hop();
    let id = seed(&pg, before.clone()).await;

    let written = PgStateChangeLog::new(pg.dal.clone())
        .commit(
            StateChange::new(PassportAuditEntry::new(
                &id.to_string(),
                "suspended",
                "locked-upcast-test",
                Some("active"),
                Some("suspended"),
            ))
            .with_passport(PassportWrite::Status(id, PassportStatus::Suspended)),
        )
        .await
        .expect("the change commits")
        .expect("a status change returns the passport");
    assert_eq!(written.status, PassportStatus::Suspended);

    let after = stored(&pg, id).await;
    assert_eq!(after["status"], "suspended");
    only_the_status_moved(&before, &after);
}

#[tokio::test]
async fn a_real_edit_to_its_product_group_data_is_still_refused() {
    let pg = start_pg().await;
    let before = published_before_the_lens_hop();
    let id = seed(&pg, before.clone()).await;
    let repo = PgPassportRepo::new(pg.dal.clone());

    let read = repo.find_by_id(id).await.expect("read").expect("exists");
    let mut edited = serde_json::to_value(&read).expect("serialise");
    edited["productGroupData"]["batteryWeightKg"] = serde_json::json!(1.0);
    let edited: Passport = serde_json::from_value(edited).expect("still a passport");

    let err = repo
        .update(edited)
        .await
        .expect_err("a published passport's data cannot be edited");
    assert!(
        matches!(err, DppError::RetentionLocked),
        "expected the retention guard's refusal, got: {err}"
    );
    assert_eq!(
        stored(&pg, id).await["productGroupData"],
        before["productGroupData"]
    );
    assert!(
        archived(&pg, id).await.is_empty(),
        "a refused change archives nothing: the version rolls back with the write"
    );
}

/// A write built from a reading taken before a concurrent publish carries
/// `retentionLocked: false`. That differs from the stored `true`, and the guard
/// lets the flag change, so it would unlock the row.
#[tokio::test]
async fn a_write_from_a_reading_before_publish_does_not_unlock_it() {
    let pg = start_pg().await;
    let id = seed(&pg, published_before_the_lens_hop()).await;
    let repo = PgPassportRepo::new(pg.dal.clone());

    let mut stale = repo.find_by_id(id).await.expect("read").expect("exists");
    stale.retention_locked = false;
    repo.update(stale)
        .await
        .expect("the write itself is harmless");

    let locked: bool =
        sqlx::query_scalar("SELECT retention_locked FROM odal.passport WHERE id = $1")
            .bind(id.0)
            .fetch_one(&admin(&pg).await)
            .await
            .expect("read the column");
    assert!(locked, "a retention-locked row stays locked");
    assert_eq!(stored(&pg, id).await["retentionLocked"], true);
}

/// Re-publishing a suspended passport goes through the registry outbox's
/// `commit_publish`, the third writer, and must work on the old shape too.
#[tokio::test]
async fn it_can_be_republished_through_the_registry_outbox() {
    let pg = start_pg().await;
    let before = published_before_the_lens_hop();
    let id = seed(&pg, before.clone()).await;
    let repo = PgPassportRepo::new(pg.dal.clone());

    let mut passport = repo
        .update_status(id, PassportStatus::Suspended)
        .await
        .expect("suspend");
    passport.status = PassportStatus::Published;
    PgRegistrySyncRepo::new(pg.dal.clone())
        .commit_publish(&passport, serde_json::json!({}))
        .await
        .expect("a suspended passport in an older shape can be re-published");

    let after = stored(&pg, id).await;
    assert_eq!(after["status"], "active");
    only_the_status_moved(&before, &after);
}
