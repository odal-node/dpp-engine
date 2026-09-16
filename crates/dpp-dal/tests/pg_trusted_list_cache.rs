//! The trusted-list cache, against a real PostgreSQL.
//!
//! What these cover that a unit test structurally cannot: the migration's
//! `CHECK` constraint, and that a territory moving between the two states leaves
//! nothing of the other behind. Both are properties of the database rather than
//! of the Rust, and both are load-bearing — the whole value of this table is
//! that "verified" and "could not be verified" stay told apart.

#![cfg(feature = "integration-tests")]

use chrono::{TimeZone as _, Utc};
use dpp_dal::pg::PgTrustedListRepo;
use dpp_dal::test_harness::start_pg;
use dpp_types::trust::{CachedTrustedList, TrustedListStore};
use serde_json::json;

fn verified(signed_by: &str) -> CachedTrustedList {
    CachedTrustedList::Verified {
        content: json!({ "territory": "FI", "providers": [] }),
        signed_by: signed_by.to_owned(),
        verified_at: Utc.with_ymd_and_hms(2026, 9, 16, 12, 0, 0).unwrap(),
    }
}

/// A verified list is stored and comes back as the same two facts.
#[tokio::test]
async fn a_verified_list_round_trips() {
    let pg = start_pg().await;
    let repo = PgTrustedListRepo::new(pg.dal.clone());

    repo.put("FI", &verified("abc=")).await.expect("stored");

    let loaded = repo.load().await.expect("loaded");
    assert_eq!(loaded.get("FI"), Some(&verified("abc=")));
}

/// An unavailable territory is recorded, and is not the same as absent.
///
/// The distinction the table exists for. A territory absent from the cache was
/// never named by the list of trusted lists; one recorded unavailable was named
/// and could not be read, and a verdict of "no list names this issuer" is not a
/// statement about the Union while any of those exist.
#[tokio::test]
async fn an_unavailable_territory_is_not_an_absent_one() {
    let pg = start_pg().await;
    let repo = PgTrustedListRepo::new(pg.dal.clone());

    repo.put(
        "DE",
        &CachedTrustedList::Unavailable {
            reason: "the list does not verify against the mandated signature profile".to_owned(),
        },
    )
    .await
    .expect("stored");

    let loaded = repo.load().await.expect("loaded");
    let Some(CachedTrustedList::Unavailable { reason }) = loaded.get("DE") else {
        panic!(
            "DE must read back as unavailable, got {:?}",
            loaded.get("DE")
        );
    };
    assert!(reason.contains("signature profile"), "{reason}");
    assert!(
        !loaded.contains_key("XX"),
        "a territory never named must stay absent rather than appearing unavailable"
    );
}

/// Moving between the two states leaves nothing of the other behind.
///
/// The case the migration's `CHECK` would otherwise catch in production. A write
/// that updated only the columns its own state uses would leave a stale
/// `content` beside a fresh `unavailable_reason` — a row claiming both, which
/// the constraint refuses and which would surface as a failing refresh rather
/// than as the bug it is.
///
/// Both directions, because they fail differently: verified→unavailable has to
/// clear three columns, and unavailable→verified has to clear one.
#[tokio::test]
async fn a_territory_can_move_between_states_in_both_directions() {
    let pg = start_pg().await;
    let repo = PgTrustedListRepo::new(pg.dal.clone());

    repo.put("FI", &verified("first=")).await.expect("stored");
    let unavailable = CachedTrustedList::Unavailable {
        reason: "the scheme operator is mid-rotation".to_owned(),
    };
    repo.put("FI", &unavailable).await.expect("still stored");

    let loaded = repo.load().await.expect("loaded");
    assert_eq!(
        loaded.get("FI"),
        Some(&unavailable),
        "a list that became unverifiable must not keep serving its old content"
    );

    repo.put("FI", &verified("second="))
        .await
        .expect("stored again");
    let loaded = repo.load().await.expect("loaded");
    assert_eq!(
        loaded.get("FI"),
        Some(&verified("second=")),
        "and a recovered list must not keep its stale reason"
    );
}

/// A refresh that touches one territory leaves every other row alone.
///
/// Why `put` is per-territory rather than a bulk replace: a refresh failing for
/// one Member State must not empty the cache for the rest, and the Union is
/// fetched one document at a time.
#[tokio::test]
async fn writing_one_territory_does_not_disturb_another() {
    let pg = start_pg().await;
    let repo = PgTrustedListRepo::new(pg.dal.clone());

    repo.put("FI", &verified("fi=")).await.expect("stored");
    repo.put("FR", &verified("fr=")).await.expect("stored");
    repo.put(
        "FI",
        &CachedTrustedList::Unavailable {
            reason: "fetch failed".to_owned(),
        },
    )
    .await
    .expect("stored");

    let loaded = repo.load().await.expect("loaded");
    assert_eq!(loaded.get("FR"), Some(&verified("fr=")));
    assert_eq!(loaded.len(), 2);
}
