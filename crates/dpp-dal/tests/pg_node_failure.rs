//! `PgNodeFailureRepo`: refusals are counted per kind, and the count outlives the
//! repo that wrote it, as it does for a node that restarts.

#![cfg(feature = "integration-tests")]

use dpp_dal::pg::PgNodeFailureRepo;
use dpp_dal::test_harness::start_pg;
use dpp_types::node_failure::{FailureCounts, FailureKind, NodeFailureCounter};

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
    repo.record(FailureKind::Signing).await.unwrap();
    repo.record(FailureKind::RulesetLoad).await.unwrap();

    // A new repo over the same database, as a node that has restarted holds.
    let after_restart = PgNodeFailureRepo::new(pg.dal.clone())
        .counts()
        .await
        .unwrap();
    assert_eq!(
        after_restart,
        FailureCounts {
            signing: 2,
            ruleset_load: 1,
        }
    );
}
