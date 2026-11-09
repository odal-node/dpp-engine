//! `PgNodeFailureRepo`: failures are counted per kind, the count outlives the repo
//! that wrote it, as it does for a node that restarts, and each kind carries the
//! time of its latest failure.

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
async fn failures_are_counted_per_kind_and_survive_a_restart() {
    let pg = start_pg().await;
    let before = PgNodeFailureRepo::new(pg.dal.clone())
        .counts()
        .await
        .unwrap();
    assert_eq!(before, FailureCounts::default(), "nothing failed yet");

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

    // The time is the latest failure's, not the first's.
    let first = first.expect("set by the first failure");
    let latest = after_restart.signing.last_at.expect("set");
    assert!(first < between, "{first} < {between}");
    assert!(between < latest, "the second failure moved it: {latest}");
    assert!(
        after_restart.ruleset_load.last_at.expect("set") > between,
        "each kind keeps its own"
    );
}

/// Failures recorded at the same moment are each counted, both when they race to
/// create a kind's row and when they race to add to it. A read-then-write would
/// lose some of them.
#[tokio::test(flavor = "multi_thread")]
async fn failures_racing_each_other_are_all_counted() {
    const RACERS: i64 = 16;
    let pg = start_pg().await;
    let race = || async {
        let mut writes = tokio::task::JoinSet::new();
        for _ in 0..RACERS {
            let repo = PgNodeFailureRepo::new(pg.dal.clone());
            writes.spawn(async move { repo.record(FailureKind::Signing).await });
        }
        while let Some(write) = writes.join_next().await {
            write.expect("task ran").expect("failure recorded");
        }
    };

    race().await;
    let repo = PgNodeFailureRepo::new(pg.dal.clone());
    assert_eq!(
        repo.counts().await.unwrap().signing.total,
        RACERS,
        "racing to create the row"
    );

    race().await;
    assert_eq!(
        repo.counts().await.unwrap().signing.total,
        2 * RACERS,
        "racing to add to it"
    );
}
