//! `PgNodeFailureRepo`: refusals are counted per kind, the count outlives the repo
//! that wrote it, as it does for a node that restarts, and each kind carries the
//! time of its latest refusal.

#![cfg(feature = "integration-tests")]

use chrono::{DateTime, Utc};
use dpp_dal::pg::{PgDal, PgNodeFailureRepo};
use dpp_dal::test_harness::start_pg;
use dpp_types::node_failure::{FailureCounts, FailureKind, NodeFailureCounter};

async fn db_now(dal: &PgDal) -> DateTime<Utc> {
    sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(dal.pool())
        .await
        .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn refusals_are_counted_per_kind_and_survive_a_restart() {
    let pg = start_pg().await;
    let before = PgNodeFailureRepo::new(pg.dal.clone())
        .counts()
        .await
        .unwrap();
    assert_eq!(before, FailureCounts::default(), "nothing refused yet");

    let repo = PgNodeFailureRepo::new(pg.dal.clone());
    repo.record(FailureKind::Signing).await.unwrap();
    let first = repo.counts().await.unwrap().signing.last_at;
    let between = db_now(&pg.dal).await;
    repo.record(FailureKind::Signing).await.unwrap();
    repo.record(FailureKind::RulesetLoad).await.unwrap();

    // A new repo over the same database, as a node that has restarted holds.
    let after_restart = PgNodeFailureRepo::new(pg.dal.clone())
        .counts()
        .await
        .unwrap();
    assert_eq!(after_restart.signing.total, 2);
    assert_eq!(after_restart.ruleset_load.total, 1);

    // The time is the latest refusal's, not the first's.
    let first = first.expect("set by the first refusal");
    let latest = after_restart.signing.last_at.expect("set");
    assert!(first < between, "{first} < {between}");
    assert!(between < latest, "the second refusal moved it: {latest}");
    assert!(
        after_restart.ruleset_load.last_at.expect("set") > between,
        "each kind keeps its own"
    );
}
