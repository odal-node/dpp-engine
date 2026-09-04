//! Postgres integration tests for the idempotency store (migration 0036).
//!
//! Run with:
//! ```sh
//! cargo test -p dpp-dal --features integration-tests --test pg_idempotency -- --nocapture
//! ```
//!
//! Its own file rather than more of `pg_integration.rs`: nothing here touches a
//! passport, and the suite next door is organised around the passport tables.
//!
//! What these cover is the half `dpp-common`'s flow suite cannot. That one
//! drives the middleware against an in-memory stand-in and proves the
//! *decisions* are right. Whether the claim is genuinely atomic, genuinely
//! lease-reclaimable and genuinely swept is a property of the SQL, and only a
//! real Postgres can answer it.

#![cfg(feature = "integration-tests")]

use std::{sync::Arc, time::Duration};

use dpp_common::idempotency::{Claim, IdempotencyStore, RequestKey, StoredResponse, fingerprint};
use dpp_dal::pg::{PgIdempotencyRepo, sqlx};
use dpp_dal::test_harness::start_pg;

const LEASE: Duration = Duration::from_secs(60);
const RETENTION: Duration = Duration::from_secs(86_400);

fn key(k: &str) -> RequestKey {
    RequestKey {
        principal: "operator@example.com".into(),
        method: "POST".into(),
        path: "/vault/api/v1/dpp".into(),
        key: k.into(),
    }
}

fn stored(status: u16) -> StoredResponse {
    StoredResponse {
        status,
        body: br#"{"id":"p1"}"#.to_vec(),
        content_type: Some("application/json".into()),
    }
}

/// The core loop: claim once, complete, then replay — and never claim twice
/// while the first attempt is running.
#[tokio::test]
async fn claim_complete_replay() {
    let pg = start_pg().await;
    let repo = PgIdempotencyRepo::new(pg.dal.clone());
    let k = key("k-1");
    let fp = fingerprint(b"body");

    assert_eq!(
        repo.claim(&k, &fp, LEASE, RETENTION).await.unwrap(),
        Claim::Claimed
    );
    assert_eq!(
        repo.claim(&k, &fp, LEASE, RETENTION).await.unwrap(),
        Claim::InFlight,
        "a concurrent duplicate must never be told it owns the key"
    );

    repo.complete(&k, &stored(201)).await.unwrap();

    assert_eq!(
        repo.claim(&k, &fp, LEASE, RETENTION).await.unwrap(),
        Claim::Replay(stored(201)),
        "the replay must reproduce status, body and content type exactly"
    );
}

/// A different body under the same key is a mismatch in either state. The
/// fingerprint is checked before the state precisely so that a caller who
/// changed its request is told *that*, rather than "still running".
#[tokio::test]
async fn a_different_body_is_a_mismatch_in_either_state() {
    let pg = start_pg().await;
    let repo = PgIdempotencyRepo::new(pg.dal.clone());
    let k = key("k-1");
    let first = fingerprint(b"body-a");
    let other = fingerprint(b"body-b");

    repo.claim(&k, &first, LEASE, RETENTION).await.unwrap();
    assert_eq!(
        repo.claim(&k, &other, LEASE, RETENTION).await.unwrap(),
        Claim::FingerprintMismatch
    );

    repo.complete(&k, &stored(201)).await.unwrap();
    assert_eq!(
        repo.claim(&k, &other, LEASE, RETENTION).await.unwrap(),
        Claim::FingerprintMismatch
    );
}

/// The crash case: a claim whose lease has run out is reclaimable, so a key is
/// never wedged by a process that died mid-request.
#[tokio::test]
async fn an_expired_lease_is_reclaimable() {
    let pg = start_pg().await;
    let repo = PgIdempotencyRepo::new(pg.dal.clone());
    let k = key("k-1");
    let fp = fingerprint(b"body");

    repo.claim(&k, &fp, LEASE, RETENTION).await.unwrap();
    assert_eq!(
        repo.claim(&k, &fp, LEASE, RETENTION).await.unwrap(),
        Claim::InFlight
    );

    // Moved into the past rather than slept through.
    let past = chrono::Utc::now() - chrono::Duration::seconds(1);
    repo.backdate_for_test(&k, past, chrono::Utc::now() + chrono::Duration::hours(24))
        .await
        .unwrap();

    assert_eq!(
        repo.claim(&k, &fp, LEASE, RETENTION).await.unwrap(),
        Claim::Claimed,
        "a dead claim must be reclaimable, or the key is unusable until it expires"
    );
}

/// Past retention the key is no longer honoured, and the sweep reaches it.
#[tokio::test]
async fn an_expired_key_is_claimable_again_and_is_swept() {
    let pg = start_pg().await;
    let repo = PgIdempotencyRepo::new(pg.dal.clone());
    let k = key("k-1");
    let fp = fingerprint(b"body");

    repo.claim(&k, &fp, LEASE, RETENTION).await.unwrap();
    repo.complete(&k, &stored(201)).await.unwrap();

    let past = chrono::Utc::now() - chrono::Duration::seconds(1);
    repo.backdate_for_test(&k, past, past).await.unwrap();

    assert_eq!(
        repo.claim(&k, &fp, LEASE, RETENTION).await.unwrap(),
        Claim::Claimed,
        "an expired key must not keep replaying a day-old answer"
    );

    // Backdated again, because the successful claim above reset the horizon.
    repo.backdate_for_test(&k, past, past).await.unwrap();
    assert_eq!(repo.purge_expired().await.unwrap(), 1);
    assert_eq!(
        repo.purge_expired().await.unwrap(),
        0,
        "a second sweep must find nothing — this DELETE is the only reason the \
         table carries the grant"
    );
}

/// Release frees the key at once, which is what a `5xx` needs: the request
/// failed, so the client must be able to retry it unchanged. A *completed* key
/// is not releasable, or a late failure could erase a good record.
#[tokio::test]
async fn release_frees_an_in_flight_key_but_never_a_completed_one() {
    let pg = start_pg().await;
    let repo = PgIdempotencyRepo::new(pg.dal.clone());
    let k = key("k-1");
    let fp = fingerprint(b"body");

    repo.claim(&k, &fp, LEASE, RETENTION).await.unwrap();
    repo.release(&k).await.unwrap();
    assert_eq!(
        repo.claim(&k, &fp, LEASE, RETENTION).await.unwrap(),
        Claim::Claimed
    );

    repo.complete(&k, &stored(201)).await.unwrap();
    repo.release(&k).await.unwrap();
    assert_eq!(
        repo.claim(&k, &fp, LEASE, RETENTION).await.unwrap(),
        Claim::Replay(stored(201))
    );
}

/// All four parts of the key are load-bearing: the same string under a
/// different principal or a different route is a different key.
#[tokio::test]
async fn the_key_is_scoped_by_principal_and_route() {
    let pg = start_pg().await;
    let repo = PgIdempotencyRepo::new(pg.dal.clone());
    let fp = fingerprint(b"body");

    let mine = key("shared");
    repo.claim(&mine, &fp, LEASE, RETENTION).await.unwrap();
    repo.complete(&mine, &stored(201)).await.unwrap();

    let mut theirs = key("shared");
    theirs.principal = "someone-else@example.com".into();
    assert_eq!(
        repo.claim(&theirs, &fp, LEASE, RETENTION).await.unwrap(),
        Claim::Claimed,
        "one caller must never be served another caller's stored response"
    );

    let mut other_route = key("shared");
    other_route.path = "/vault/api/v1/facilities".into();
    assert_eq!(
        repo.claim(&other_route, &fp, LEASE, RETENTION)
            .await
            .unwrap(),
        Claim::Claimed,
        "one key fanned across several routes is normal and must not collide"
    );
}

/// The atomicity everything else rests on: of many simultaneous first attempts,
/// exactly one may be told it owns the key. A split `SELECT`-then-`INSERT`
/// would let several through here.
#[tokio::test]
async fn only_one_of_many_concurrent_claims_wins() {
    let pg = start_pg().await;
    let repo = Arc::new(PgIdempotencyRepo::new(pg.dal.clone()));
    let fp = fingerprint(b"body");

    let mut handles = Vec::new();
    for _ in 0..8 {
        let repo = repo.clone();
        let fp = fp.clone();
        handles.push(tokio::spawn(async move {
            repo.claim(&key("race"), &fp, LEASE, RETENTION)
                .await
                .unwrap()
        }));
    }

    let mut claimed = 0;
    for handle in handles {
        if handle.await.unwrap() == Claim::Claimed {
            claimed += 1;
        }
    }

    assert_eq!(claimed, 1, "exactly one claimant, or the write runs twice");
}

/// The migration refuses a completed row that cannot be replayed — a client
/// told "already done" and handed nothing is worse off than one that retries.
#[tokio::test]
async fn the_database_refuses_a_completed_row_with_no_response() {
    let pg = start_pg().await;
    let admin = sqlx::postgres::PgPoolOptions::new()
        .connect(&pg.admin_url)
        .await
        .expect("admin");

    let result = sqlx::query(
        r#"INSERT INTO odal.idempotency_key
             (principal, method, path, idem_key, fingerprint, state,
              lease_expires_at, expires_at)
           VALUES ('p','POST','/x','k', repeat('a', 64), 'completed',
                   now() + interval '1 minute', now() + interval '1 day')"#,
    )
    .execute(&admin)
    .await;

    assert!(
        result.is_err(),
        "the completed_rows_can_be_replayed CHECK must refuse this"
    );
    admin.close().await;
}
