//! `PgNodeSignalRepo`: outcomes are recorded per signal, outlive the repo that
//! wrote them, as they do for a node that restarts, and say whether a signal is
//! failing now.

#![cfg(feature = "integration-tests")]

use chrono::{DateTime, Utc};
use dpp_dal::pg::{PgDal, PgNodeSignalRepo};
use dpp_dal::test_harness::start_pg;
use dpp_types::node_signal::{NodeSignals, Outcome, Signal, SignalState};

async fn db_now(dal: &PgDal) -> DateTime<Utc> {
    sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(dal.pool())
        .await
        .unwrap()
}

async fn state_of(repo: &PgNodeSignalRepo, signal: Signal) -> SignalState {
    repo.states()
        .await
        .unwrap()
        .into_iter()
        .find_map(|(s, state)| (s == signal).then_some(state))
        .expect("every signal is listed")
}

#[tokio::test(flavor = "multi_thread")]
async fn every_signal_is_listed_before_anything_is_recorded() {
    let pg = start_pg().await;
    let states = PgNodeSignalRepo::new(pg.dal.clone())
        .states()
        .await
        .unwrap();
    let expected: Vec<_> = Signal::ALL
        .into_iter()
        .map(|signal| (signal, SignalState::default()))
        .collect();
    assert_eq!(states, expected);
}

#[tokio::test(flavor = "multi_thread")]
async fn outcomes_are_recorded_per_signal_and_survive_a_restart() {
    let pg = start_pg().await;
    let repo = PgNodeSignalRepo::new(pg.dal.clone());

    repo.record(Signal::Signing, Outcome::Failed).await.unwrap();
    let first = state_of(&repo, Signal::Signing).await.last_failed_at;
    let between = db_now(&pg.dal).await;
    repo.record(Signal::Signing, Outcome::Failed).await.unwrap();
    repo.record(Signal::RulesetLoad, Outcome::Succeeded)
        .await
        .unwrap();

    // A new repo over the same database, as a node that has restarted holds.
    let restarted = PgNodeSignalRepo::new(pg.dal.clone());
    let signing = state_of(&restarted, Signal::Signing).await;
    assert_eq!(signing.failures, 2);
    assert!(signing.is_failing(), "failed, never succeeded");
    let (first, latest) = (
        first.expect("set by the first failure"),
        signing.last_failed_at.expect("set"),
    );
    assert!(first < between, "{first} < {between}");
    assert!(between < latest, "the second failure moved it: {latest}");

    let ruleset = state_of(&restarted, Signal::RulesetLoad).await;
    assert_eq!(ruleset.failures, 0, "a success is not counted as a failure");
    assert!(!ruleset.is_failing());
    assert!(ruleset.last_succeeded_at.expect("set") > between);
}

/// A success after a failure clears `failing` and keeps the count; a failure
/// after that sets it again.
#[tokio::test(flavor = "multi_thread")]
async fn the_latest_outcome_decides_whether_a_signal_is_failing() {
    let pg = start_pg().await;
    let repo = PgNodeSignalRepo::new(pg.dal.clone());

    repo.record(Signal::Signing, Outcome::Failed).await.unwrap();
    repo.record(Signal::Signing, Outcome::Succeeded)
        .await
        .unwrap();
    let recovered = state_of(&repo, Signal::Signing).await;
    assert!(!recovered.is_failing(), "{recovered:?}");
    assert_eq!(
        recovered.failures, 1,
        "recovering does not forget a failure"
    );

    repo.record(Signal::Signing, Outcome::Failed).await.unwrap();
    let again = state_of(&repo, Signal::Signing).await;
    assert!(again.is_failing(), "{again:?}");
    assert_eq!(again.failures, 2);
}

/// Failures recorded at the same moment are each counted, both when they race to
/// create a signal's row and when they race to add to it. A read-then-write would
/// lose some of them.
#[tokio::test(flavor = "multi_thread")]
async fn failures_racing_each_other_are_all_counted() {
    const RACERS: i64 = 16;
    let pg = start_pg().await;
    let race = || async {
        let mut writes = tokio::task::JoinSet::new();
        for _ in 0..RACERS {
            let repo = PgNodeSignalRepo::new(pg.dal.clone());
            writes.spawn(async move { repo.record(Signal::Signing, Outcome::Failed).await });
        }
        while let Some(write) = writes.join_next().await {
            write.expect("task ran").expect("failure recorded");
        }
    };

    race().await;
    let repo = PgNodeSignalRepo::new(pg.dal.clone());
    assert_eq!(
        state_of(&repo, Signal::Signing).await.failures,
        RACERS,
        "racing to create the row"
    );

    race().await;
    assert_eq!(
        state_of(&repo, Signal::Signing).await.failures,
        2 * RACERS,
        "racing to add to it"
    );
}
