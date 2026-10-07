//! Unit tests for `cache.rs`.

use super::*;
use dpp_types::trust::CachedTrustedList;

fn cache(
    entries: Vec<(&str, CachedTrustedList)>,
) -> std::collections::BTreeMap<String, CachedTrustedList> {
    entries
        .into_iter()
        .map(|(t, e)| (t.to_owned(), e))
        .collect()
}

fn verified(territory: &str) -> CachedTrustedList {
    CachedTrustedList::Verified {
        content: serde_json::json!({ "territory": territory, "providers": [] }),
        signed_by: "a base64 digest".to_owned(),
        verified_at: chrono::Utc::now(),
    }
}

/// A verified entry becomes a list to search.
#[test]
fn a_verified_entry_is_a_list_the_verdict_consults() {
    let (lists, unchecked) = from_cache(&cache(vec![("FI", verified("FI"))]));

    assert_eq!(lists.len(), 1);
    assert_eq!(lists[0].territory(), Some("FI"));
    assert!(unchecked.is_empty());
}

/// An unavailable entry becomes a territory the verdict admits it missed.
///
/// 🚨 It must not simply be absent. Absent means the list of trusted lists
/// never named the territory, which is a different fact — and the one that
/// would let `notListed` claim a completeness it does not have.
#[test]
fn an_unavailable_entry_is_a_territory_the_verdict_admits_it_missed() {
    let (lists, unchecked) = from_cache(&cache(vec![(
        "DE",
        CachedTrustedList::Unavailable {
            reason: "did not verify".to_owned(),
        },
    )]));

    assert!(lists.is_empty());
    assert_eq!(unchecked.len(), 1);
    assert_eq!(unchecked[0].territory, "DE");
    assert_eq!(
        unchecked[0].reason, "did not verify",
        "and the reason survives to the operator"
    );
}

/// 🚨 A cached entry that will not read back is **unavailable**, not dropped.
///
/// This is the rule this function turns on, and it had no test. Dropping a
/// malformed entry would narrow `consulted` by one with no matching
/// `unchecked` — so the verdict would look *more* complete than it is, which
/// is precisely the overclaim the two counts exist to prevent.
///
/// The cache is this node's own writing, so it should not happen; a rule
/// that only matters when something has already gone wrong is a rule that
/// gets tested only if somebody writes the test.
#[test]
fn a_cached_entry_that_will_not_read_back_is_unavailable_rather_than_dropped() {
    let (lists, unchecked) = from_cache(&cache(vec![(
        "FR",
        CachedTrustedList::Verified {
            content: serde_json::json!({ "providers": "not an array" }),
            signed_by: "a base64 digest".to_owned(),
            verified_at: chrono::Utc::now(),
        },
    )]));

    assert!(
        lists.is_empty(),
        "an entry that will not deserialize is not a list to search"
    );
    assert_eq!(
        unchecked.len(),
        1,
        "and it is admitted rather than quietly narrowing the verdict"
    );
    assert_eq!(unchecked[0].territory, "FR");
    assert!(
        unchecked[0].reason.contains("could not be read back"),
        "naming the cache as the problem, not the Member State: {}",
        unchecked[0].reason
    );
}

/// Both halves come out of one pass over the cache.
#[test]
fn a_mixed_cache_yields_both_halves() {
    let (lists, unchecked) = from_cache(&cache(vec![
        ("FI", verified("FI")),
        (
            "DE",
            CachedTrustedList::Unavailable {
                reason: "over the parser ceiling".to_owned(),
            },
        ),
        ("EE", verified("EE")),
    ]));

    assert_eq!(lists.len(), 2);
    assert_eq!(unchecked.len(), 1);
}
