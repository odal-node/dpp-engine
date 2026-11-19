//! `PgOperatorConfigRepo::update`: overlapping updates to different fields both
//! survive, including when no row exists yet.
//!
//! # Why this test exists
//!
//! An update used to read the row, patch it in memory and write the whole row
//! back, with nothing held between the read and the write. Two overlapping
//! updates both read the old row, and the second write restored the field the
//! first had changed. `enterpriseSize` decides whether the ESPR Art. 25(1)
//! destruction ban reaches the operator, so a lost correction changes that
//! outcome without anyone seeing it.
//!
//! # How the overlap is made deterministic
//!
//! Each test holds a lock itself, starts the two updates, and waits until
//! PostgreSQL reports both queued behind it (`sessions_waiting_for_a_lock`)
//! before letting go, so no sleep has to be long enough. What the updates wait
//! on is the point of each test:
//!
//! - with a row, the test holds the row `FOR UPDATE`, where an update waits to
//!   read it;
//! - with no row, the test holds an uncommitted insert of the row, where an
//!   update waits to create it.
//!
//! Without the lock, the updates read at once and queue at their write, still
//! holding the row as they read it, and the later write restores the stale
//! field.

#![cfg(feature = "integration-tests")]

use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::{DateTime, TimeZone, Utc};
use dpp_dal::pg::PgOperatorConfigRepo;
use dpp_dal::test_harness::{TestPg, sessions_waiting_for_a_lock, start_pg};
use dpp_domain::DppError;
use dpp_domain::unsold_goods::EnterpriseSize;
use dpp_types::operator::{
    OperatorConfig, OperatorConfigRepository, STANDALONE_OPERATOR_ID, UpdateOperatorConfig,
};

fn nothing() -> UpdateOperatorConfig {
    UpdateOperatorConfig {
        legal_name: None,
        trade_name: None,
        address: None,
        country: None,
        contact_email: None,
        did_web_url: None,
        product_categories: None,
        brand_primary: None,
        brand_secondary: None,
        brand_logo_url: None,
        custom_domain: None,
        data_residency: None,
        retention_policy_days: None,
        feature_flags: None,
        registry_verified_at: None,
        enterprise_size: None,
    }
}

fn size_correction() -> UpdateOperatorConfig {
    UpdateOperatorConfig {
        enterprise_size: Some(EnterpriseSize::Large),
        ..nothing()
    }
}

fn rebranding() -> UpdateOperatorConfig {
    UpdateOperatorConfig {
        brand_primary: Some("#112233".into()),
        ..nothing()
    }
}

fn verified_on() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2025, 3, 4, 5, 6, 7).unwrap()
}

async fn seeded(pg: &TestPg) -> Arc<PgOperatorConfigRepo> {
    let repo = Arc::new(PgOperatorConfigRepo::new(pg.dal.clone()));
    let mut seed = OperatorConfig::empty(STANDALONE_OPERATOR_ID);
    seed.legal_name = "Acme GmbH".into();
    seed.address = "1 Allee, Berlin".into();
    seed.country = "DE".into();
    seed.contact_email = "ops@acme.example".into();
    seed.enterprise_size = Some(EnterpriseSize::Small);
    seed.registry_verified_at = Some(verified_on());
    repo.upsert(seed).await.expect("seed the operator");
    repo
}

/// Start two overlapping updates, the first before the second, and wait until
/// both are queued behind the lock the caller holds.
async fn start_two_updates_behind_a_held_lock(
    pg: &TestPg,
    repo: &Arc<PgOperatorConfigRepo>,
    first: UpdateOperatorConfig,
    second: UpdateOperatorConfig,
) -> Vec<tokio::task::JoinHandle<Result<OperatorConfig, DppError>>> {
    let patience = Duration::from_secs(10);
    let mut updates = Vec::new();
    for (waiting, patch, name) in [(1, first, "the first update"), (2, second, "the second")] {
        let repo = repo.clone();
        updates.push(tokio::spawn(async move {
            repo.update(STANDALONE_OPERATOR_ID, &patch).await
        }));
        let started = Instant::now();
        while sessions_waiting_for_a_lock(pg).await < waiting {
            assert!(
                started.elapsed() < patience,
                "{name} never queued behind the held lock"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
    updates
}

#[tokio::test(flavor = "multi_thread")]
async fn two_overlapping_updates_to_different_fields_both_survive() {
    let pg = start_pg().await;
    let repo = seeded(&pg).await;

    let mut hold = pg.dal.pool().begin().await.expect("begin");
    sqlx::query("SELECT 1 FROM odal.operator_config WHERE operator_id = $1 FOR UPDATE")
        .bind(STANDALONE_OPERATOR_ID)
        .execute(&mut *hold)
        .await
        .expect("hold the operator row");

    let updates =
        start_two_updates_behind_a_held_lock(&pg, &repo, size_correction(), rebranding()).await;
    hold.commit().await.expect("release the row");
    for update in updates {
        update.await.expect("join").expect("update");
    }

    let stored = repo
        .get(STANDALONE_OPERATOR_ID)
        .await
        .expect("read")
        .expect("exists");
    assert_eq!(
        stored.enterprise_size,
        Some(EnterpriseSize::Large),
        "the size correction was lost"
    );
    assert_eq!(
        stored.brand_primary.as_deref(),
        Some("#112233"),
        "the rebranding was lost"
    );
    assert_eq!(stored.legal_name, "Acme GmbH", "untouched fields stay");
}

#[tokio::test(flavor = "multi_thread")]
async fn two_first_updates_with_no_row_yet_both_survive() {
    let pg = start_pg().await;
    let repo = Arc::new(PgOperatorConfigRepo::new(pg.dal.clone()));

    // A competing first update has inserted the row and not committed. The two
    // updates below read a table with no visible row, so only the insert can
    // make them wait.
    let mut hold = pg.dal.pool().begin().await.expect("begin");
    sqlx::query(
        "INSERT INTO odal.operator_config (operator_id, legal_name, address, country, contact_email)
         VALUES ($1, '', '', '', '')",
    )
    .bind(STANDALONE_OPERATOR_ID)
    .execute(&mut *hold)
    .await
    .expect("insert the row, uncommitted");
    assert!(
        repo.get(STANDALONE_OPERATOR_ID)
            .await
            .expect("read")
            .is_none(),
        "the held insert must not be visible, or this test no longer starts from no row"
    );

    // Two fields the write replaces outright. `enterprise_size` is kept by a
    // `COALESCE` whatever an update read, which would hide a lost update here
    // whenever the update that carries it happens to write last.
    let domain = UpdateOperatorConfig {
        custom_domain: Some("passports.acme.example".into()),
        ..nothing()
    };
    let updates = start_two_updates_behind_a_held_lock(&pg, &repo, rebranding(), domain).await;
    hold.commit().await.expect("release the insert");
    for update in updates {
        update.await.expect("join").expect("update");
    }

    let stored = repo
        .get(STANDALONE_OPERATOR_ID)
        .await
        .expect("read")
        .expect("exists");
    assert_eq!(
        stored.brand_primary.as_deref(),
        Some("#112233"),
        "the rebranding was lost"
    );
    assert_eq!(
        stored.custom_domain.as_deref(),
        Some("passports.acme.example"),
        "the custom domain was lost"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_first_update_creates_the_row_from_the_empty_config() {
    let pg = start_pg().await;
    let repo = PgOperatorConfigRepo::new(pg.dal.clone());

    let written = repo
        .update(STANDALONE_OPERATOR_ID, &rebranding())
        .await
        .expect("update");

    let empty = OperatorConfig::empty(STANDALONE_OPERATOR_ID);
    assert_eq!(written.brand_primary.as_deref(), Some("#112233"));
    assert_eq!(written.retention_policy_days, empty.retention_policy_days);
    assert_eq!(written.data_residency, empty.data_residency);
    let stored = repo
        .get(STANDALONE_OPERATOR_ID)
        .await
        .expect("read")
        .expect("exists");
    assert_eq!(stored.brand_primary, written.brand_primary);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_update_that_carries_no_size_or_date_keeps_the_stored_ones() {
    let pg = start_pg().await;
    let repo = seeded(&pg).await;

    let written = repo
        .update(STANDALONE_OPERATOR_ID, &rebranding())
        .await
        .expect("update");

    assert_eq!(written.enterprise_size, Some(EnterpriseSize::Small));
    assert_eq!(written.registry_verified_at, Some(verified_on()));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_retention_beyond_the_column_is_refused_and_leaves_no_row_behind() {
    let pg = start_pg().await;
    let repo = PgOperatorConfigRepo::new(pg.dal.clone());
    let too_long = UpdateOperatorConfig {
        retention_policy_days: Some(i64::from(i32::MAX) + 1),
        ..nothing()
    };

    let refused = repo.update(STANDALONE_OPERATOR_ID, &too_long).await;

    assert!(
        matches!(refused, Err(DppError::Validation(_))),
        "got {refused:?}"
    );
    assert!(
        repo.get(STANDALONE_OPERATOR_ID)
            .await
            .expect("read")
            .is_none(),
        "the refused first update left the row it created"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_retention_beyond_the_column_leaves_the_stored_config_unchanged() {
    let pg = start_pg().await;
    let repo = seeded(&pg).await;
    let before = repo
        .get(STANDALONE_OPERATOR_ID)
        .await
        .expect("read")
        .expect("exists");
    let too_long = UpdateOperatorConfig {
        retention_policy_days: Some(i64::from(i32::MAX) + 1),
        brand_primary: Some("#445566".into()),
        ..nothing()
    };

    let refused = repo.update(STANDALONE_OPERATOR_ID, &too_long).await;

    assert!(
        matches!(refused, Err(DppError::Validation(_))),
        "got {refused:?}"
    );
    let after = repo
        .get(STANDALONE_OPERATOR_ID)
        .await
        .expect("read")
        .expect("exists");
    assert_eq!(after.brand_primary, before.brand_primary);
    assert_eq!(after.retention_policy_days, before.retention_policy_days);
}
