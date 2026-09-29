//! One pass over the EU Trusted Lists, filling the node's cache.
//!
//! ✅ COMPLIANCE-PIN: Regulation (EU) No 910/2014 Art. 22 (Member States publish
//! trusted lists) and Art. 32(1)(a)–(b), reached for seals by Art. 40 — whether
//! the certificate behind a seal was issued by a qualified trust service
//! provider is a question only a trusted list can answer.
//!
//! `dpp_seal::qualification::qualify` has always taken the verified lists to
//! consult as an argument, and nothing supplied them at runtime. So the seal
//! route could report *who* issued a certificate, which needs no list, and never
//! whether that issuer was qualified. This is the thing that supplies them.
//!
//! # 🚨 A pass is the unit, not a territory
//!
//! `IssuerStanding::NotListed` is the only verdict that claims an **absence**,
//! and an absence is only as wide as what was looked at. That makes the set of
//! territories — not any one of them — the thing a pass has to get right, which
//! decides the shape of everything here:
//!
//! - **The list of trusted lists comes first, and its failure abandons the
//!   pass.** It is what says which territories exist. Without it a sweep cannot
//!   know whether it covered the Union or half of it, and a cache that cannot
//!   describe its own completeness makes every `NotListed` unsound. The previous
//!   contents are left exactly as they were: stale and honest about its width
//!   beats fresh and silent about what is missing.
//! - **A territory that cannot be read is recorded, not skipped.** Skipping
//!   leaves it *absent*, and absent means "the list of trusted lists never named
//!   it" — a different fact, and the one that makes a missing Member State
//!   invisible. `CachedTrustedList::Unavailable` carries why, and the verdict
//!   carries the count.
//!
//! # 🚨 Any failure to re-verify records the territory unavailable
//!
//! Including a fetch that merely timed out, and this is the deliberate part.
//! `TrustedListStore::put`'s own documentation leaves the choice here, because
//! only a caller can tell "I could not refresh this" from "this is not
//! available" — so: **fail closed.**
//!
//! Keeping the previous copy would mean answering `NotListed` from a list this
//! node can no longer confirm is current, and a provider whose status was
//! withdrawn yesterday would still read as qualified. Recording the territory
//! unavailable costs width — the verdict says so, in `unchecked` — and never
//! costs correctness. A verdict that is narrow says so; one that is wrong does
//! not.
//!
//! The cost is real: a transient blip drops a territory to `unchecked` until the
//! next pass. The refinement that would soften it is honouring the list's own
//! `NextUpdate` — the publisher's statement that its copy is still current — and
//! that needs the parser to read the field, which it does not today. Worth
//! having; not worth inventing a freshness rule of our own in the meantime.
//!
//! # Why this is not in `dpp-seal`
//!
//! Same reason `seal_drain` is not. What a trusted list *is*, and what verifying
//! one means, is the seal crate's. *When* a deployment gets around to fetching
//! them, how often, and what it does with a failure is operational, so it lives
//! here beside the other background passes.

use std::sync::Arc;

use dpp_seal::trustlist::{
    TrustedListPointer, fetch_lotl_pointers, fetch_trusted_list_xml, national_pointers,
    verify_trusted_list,
};
use dpp_types::trust::{CachedTrustedList, TrustedListStore};

/// What belongs in the cache for one territory, given what the fetch returned.
///
/// 🚨 **Pure, and separated from the fetch for exactly that reason.** This is
/// where the fail-closed rule lives — that a list which could not be re-read is
/// recorded unavailable rather than left at its previous copy — and a rule that
/// can only be exercised by reaching the Union over the network is a rule
/// nothing tests. `Err(why)` is the sentence an operator reads; every route to
/// it ends in the same place, so they are one type rather than a taxonomy
/// nothing branches on.
///
/// The document arrives as **XML** rather than parsed, because the XAdES
/// signature is over the document: a caller holding only the parsed form has
/// nothing left to verify.
fn entry_for(pointer: &TrustedListPointer, fetched: Result<String, String>) -> CachedTrustedList {
    let entry = fetched.and_then(|xml| {
        let verified = verify_trusted_list(&xml, pointer).map_err(|e| {
            format!("did not verify against the certificates the list of trusted lists names: {e}")
        })?;

        Ok(CachedTrustedList::Verified {
            // The parsed list, not the document. The Union is roughly 40 MB of
            // XML and this is the reduction of it a verdict actually reads —
            // providers, services, histories and certificates. Keeping the
            // documents would be storing something already published and signed
            // elsewhere, at a size the cache exists to avoid.
            content: serde_json::to_value(verified.content())
                .map_err(|e| format!("verified, and could not be stored: {e}"))?,
            signed_by: verified.signed_by().to_owned(),
            // Stamped here rather than taken from the document: this is when
            // *this node* checked, which is the age of the evidence. The list's
            // own dates are the publisher's claim about the list.
            verified_at: chrono::Utc::now(),
        })
    });

    entry.unwrap_or_else(|reason| CachedTrustedList::Unavailable { reason })
}

/// Give every named territory a row before any of them is read.
///
/// 🚨 **This is what makes the verdict's completeness claim true.** A territory
/// present-and-unavailable is one the reader knows was missed; a territory
/// *absent* means the list of trusted lists never named it. So a cache holding
/// five rows out of twenty-seven answers `unchecked: 0` and reads as "as
/// complete as the list of trusted lists allows" — the exact overclaim the two
/// counts exist to prevent.
///
/// That state is reachable without anything going wrong: a node booting while
/// the first pass is still running, or after one that was interrupted, holds
/// exactly that partial cache.
///
/// Only territories the cache does not already hold are written, so a node
/// refreshing a complete cache seeds nothing and never drops a good list to
/// `unavailable` on its way to re-reading it. Returns how many were claimed.
async fn claim_unheld(store: &Arc<dyn TrustedListStore>, national: &[&TrustedListPointer]) -> u32 {
    let held = match store.load().await {
        Ok(h) => h,
        // Seed everything rather than nothing: a pass that cannot see what is
        // already held must not assume it is complete.
        Err(e) => {
            tracing::warn!(error = %e, "could not read the trusted-list cache before a pass");
            std::collections::BTreeMap::new()
        }
    };

    let mut seeded = 0;
    for pointer in national {
        let Some(territory) = pointer.territory.as_deref() else {
            continue;
        };
        if held.contains_key(territory) {
            continue;
        }
        let entry = CachedTrustedList::Unavailable {
            reason: "named by the EU list of trusted lists and not read in this pass yet"
                .to_owned(),
        };
        if let Err(e) = store.put(territory, &entry).await {
            tracing::warn!(%territory, error = %e, "could not claim a territory before reading it");
        } else {
            seeded += 1;
        }
    }
    seeded
}

/// Classify one territory's fetch and write it to the cache.
///
/// 🚨 The **write happens either way**, and that is the point of lifting this out
/// of the loop. Failing to read a Member State records it
/// [`Unavailable`](CachedTrustedList::Unavailable); it does not `continue`.
/// A skipped territory is *absent* from the cache, and absent means "the list of
/// trusted lists never named it" — so a Member State that went down would become
/// invisible rather than unchecked, and `notListed` would quietly start claiming
/// more than it can support.
///
/// A store that refuses the write leaves the row at whatever it held, which is
/// the one case where a previous copy survives: nothing decided to keep it.
async fn record(
    store: &Arc<dyn TrustedListStore>,
    territory: &str,
    pointer: &TrustedListPointer,
    fetched: Result<String, String>,
    stats: &mut RefreshStats,
) {
    let entry = entry_for(pointer, fetched);

    if let CachedTrustedList::Unavailable { reason } = &entry {
        tracing::warn!(
            %territory,
            %reason,
            "a Member State's trusted list could not be verified — a provider listed \
             there is indistinguishable from one listed nowhere, and the seal \
             qualification verdict reports the territory as unchecked"
        );
    }

    // 🚨 **Counted after the write, never before.**
    //
    // These counters describe the *cache*, and the cache is what a verdict is
    // answered from — `unavailable` is documented as the width of every
    // `notListed` this node will give until the next pass. Incrementing before
    // `put` made them describe the pass's intent instead, so a pass whose writes
    // all failed still reported a full, healthy refresh while the cache silently
    // stopped ageing and every log line said it had not.
    if let Err(e) = store.put(territory, &entry).await {
        // Loud, because a pass that cannot write is a cache that silently stops
        // ageing while every log line says it refreshed.
        tracing::warn!(%territory, error = %e, "could not store a trusted list");
        stats.unwritten += 1;
        stats.unwritten_territories.push(territory.to_owned());
        return;
    }

    match &entry {
        CachedTrustedList::Verified { .. } => stats.verified += 1,
        CachedTrustedList::Unavailable { .. } => stats.unavailable += 1,
    }
}

/// What one pass over the Union found.
///
/// Returned rather than only logged so the caller can set gauges and a test can
/// assert on it — the same arrangement `DrainStats` and `SealAudit` use.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RefreshStats {
    /// Territories whose list was fetched and verified this pass.
    pub verified: u32,
    /// Territories the list of trusted lists named and this pass could not read.
    pub unavailable: u32,
    /// Pointers the list of trusted lists carried that name no territory.
    ///
    /// Not an error and not a finding: a list without a `SchemeTerritory` cannot
    /// be filed under one, and the cache is keyed by territory. Counted so that
    /// a Union which grew such a pointer is visible rather than silently short.
    pub unnamed: u32,
    /// Territories this pass decided about and could **not** write.
    ///
    /// 🚨 Counted apart from the two above because the cache does not reflect
    /// them, and it is the cache a verdict is answered from. A territory in here
    /// still holds whatever the last successful pass left — which for a list
    /// that verified last week and failed today is a `Verified` row the
    /// fail-closed rule exists to replace.
    ///
    /// They are named in [`Self::unwritten_territories`] rather than only
    /// counted, because the publish step has to admit them: see
    /// `spawn_trusted_list_refresh`.
    pub unwritten: u32,
    /// Which territories those were, so a caller can narrow its verdict to
    /// match what the cache actually holds.
    ///
    /// The database being briefly unavailable is the ordinary cause, and it hits
    /// every territory in the pass at once — so this is a list rather than a
    /// flag, and unbounded rather than capped: a pass that could write nothing
    /// must be able to say so about all of them.
    pub unwritten_territories: Vec<String>,
}

/// Run one pass: verify the list of trusted lists, then every national list it
/// names.
///
/// Returns `None` when the list of trusted lists could not be established, which
/// abandons the pass without touching the cache — see the module header.
pub async fn refresh_once(store: &Arc<dyn TrustedListStore>) -> Option<RefreshStats> {
    let pointers = match fetch_lotl_pointers().await {
        Ok(p) => p,
        Err(e) => {
            // Deliberately not a per-territory failure. Nothing is written,
            // because a pass that cannot say which territories exist cannot say
            // anything about completeness either.
            tracing::warn!(
                error = %e,
                "the EU list of trusted lists could not be verified — this pass is abandoned \
                 and the cache is left as it was. The seal qualification verdict keeps \
                 reporting the width it had"
            );
            return None;
        }
    };

    let national = national_pointers(&pointers);
    tracing::info!(
        pointers = pointers.len(),
        national = national.len(),
        "the EU list of trusted lists verified against the pinned Official Journal anchor"
    );

    // 🚨 Claim every named territory **before** reading any of them.
    //
    // The verdict's completeness comes from the cache's own contents: a
    // territory present-and-unavailable is one the reader knows was missed, and
    // a territory *absent* means the list of trusted lists never named it. So a
    // cache holding five rows out of twenty-seven answers `unchecked: 0` and
    // reads as "as complete as the list of trusted lists allows" — which is the
    // exact overclaim the two counts exist to prevent.
    //
    // That is reachable without anything going wrong: a node booting while the
    // first pass is still running, or after one that was interrupted, has
    // exactly that partial cache. Seeding closes it — from the moment the list
    // of trusted lists is verified, every territory it names has a row, and the
    // loop below replaces each one with what it found.
    //
    // Cheap, because it only writes territories the cache does not already hold:
    // a node refreshing a complete cache seeds nothing and never drops a good
    // list to `unavailable` on its way to re-reading it.
    let seeded = claim_unheld(store, &national).await;
    if seeded > 0 {
        tracing::info!(
            seeded,
            "claimed territories the cache did not hold, so a verdict given before this \
             pass finishes reports them as unchecked rather than omitting them"
        );
    }

    let mut stats = RefreshStats::default();
    for pointer in national {
        let Some(territory) = pointer.territory.as_deref() else {
            stats.unnamed += 1;
            tracing::warn!(
                location = %pointer.location,
                "a national trusted list pointer names no scheme territory, so there is \
                 nothing to file it under"
            );
            continue;
        };

        // Fail closed on either leg — see the module header and `entry_for`.
        let fetched = fetch_trusted_list_xml(&pointer.location)
            .await
            .map_err(|e| format!("could not be fetched: {e}"));
        record(store, territory, pointer, fetched, &mut stats).await;
    }

    if stats.unwritten > 0 {
        tracing::warn!(
            unwritten = stats.unwritten,
            territories = %stats.unwritten_territories.join(", "),
            "a pass decided about these territories and could not write them — the cache \
             still holds whatever the last successful pass left there, so the verdict is \
             narrowed to admit them and the next pass comes sooner"
        );
    }

    tracing::info!(
        verified = stats.verified,
        unavailable = stats.unavailable,
        unnamed = stats.unnamed,
        unwritten = stats.unwritten,
        "trusted list refresh completed a pass over the Union"
    );
    Some(stats)
}

#[cfg(test)]
mod tests {
    use super::*;
    use dpp_seal::trustlist::verify_lotl;

    // The real published documents rather than fixtures assembled here. What is
    // being tested is the decision made about a Member State's actual list, and
    // a hand-built one would prove the classifier agrees with the builder.
    const EU_LOTL: &str = include_str!("../../../dpp-seal/tests/fixtures/eu-lotl.xml");
    const FI_LIST: &str = include_str!("../../../dpp-seal/tests/fixtures/fi-trusted-list.xml");

    fn finnish_pointer() -> TrustedListPointer {
        verify_lotl(EU_LOTL)
            .expect("the LOTL verifies against the pinned anchor")
            .pointers()
            .iter()
            .find(|p| p.territory.as_deref() == Some("FI"))
            .expect("the LOTL points at Finland")
            .clone()
    }

    /// A list that fetches and verifies is held, with what checked it.
    #[test]
    fn a_verified_list_is_cached_with_its_signer_and_the_moment_it_was_checked() {
        let before = chrono::Utc::now();

        match entry_for(&finnish_pointer(), Ok(FI_LIST.to_owned())) {
            CachedTrustedList::Verified {
                content,
                signed_by,
                verified_at,
            } => {
                assert_eq!(
                    content.get("territory").and_then(|t| t.as_str()),
                    Some("FI"),
                    "the parsed list is what is stored, not the document"
                );
                assert!(
                    content
                        .get("providers")
                        .and_then(|p| p.as_array())
                        .is_some_and(|p| !p.is_empty()),
                    "and it carries the providers a verdict reads"
                );
                assert!(!signed_by.is_empty(), "the certificate that checked it");
                assert!(
                    verified_at >= before,
                    "stamped when this node checked, which is the age of the evidence"
                );
            }
            other => panic!("Finland's real list must verify: {other:?}"),
        }
    }

    /// 🚨 A list that cannot be fetched is recorded **unavailable**, not skipped
    /// and not left at its previous copy.
    ///
    /// This is the fail-closed rule, and it is the whole reason `entry_for` is a
    /// separate function: exercising it through the real path means arranging for
    /// a Member State to be unreachable.
    ///
    /// Skipping would leave the territory *absent*, and absent means "the list of
    /// trusted lists never named it" — so a Member State that went down would
    /// become invisible rather than unchecked, and `notListed` would quietly
    /// start claiming more than it can support.
    #[test]
    fn a_list_that_cannot_be_fetched_is_recorded_unavailable_rather_than_skipped() {
        let entry = entry_for(
            &finnish_pointer(),
            Err("could not be fetched: connection refused".to_owned()),
        );

        match entry {
            CachedTrustedList::Unavailable { reason } => {
                assert!(
                    reason.contains("could not be fetched"),
                    "and the reason survives to the operator: {reason}"
                );
            }
            other => panic!("a fetch failure must not be cached as a verified list: {other:?}"),
        }
    }

    /// A document that arrives and does not verify is unavailable too.
    ///
    /// The other leg of failing closed, and the one that matters most: something
    /// answered, so a node reading only the fetch result would think it had a
    /// list. What it has is bytes that the certificates the list of trusted lists
    /// names did not sign.
    #[test]
    fn a_document_that_does_not_verify_is_not_cached_as_a_list() {
        let tampered = FI_LIST.replacen("<TSPName>", "<TSPName>Not ", 1);
        assert_ne!(tampered, FI_LIST, "the edit must actually change the bytes");

        match entry_for(&finnish_pointer(), Ok(tampered)) {
            CachedTrustedList::Unavailable { reason } => {
                assert!(
                    reason.contains("did not verify"),
                    "and says which check refused it: {reason}"
                );
            }
            other => panic!("an altered list must not be cached as verified: {other:?}"),
        }
    }

    /// The wrong Member State's list does not satisfy a pointer.
    ///
    /// Not a tampering finding — the document is genuine and signed — but it is
    /// signed by a certificate *this* pointer does not name, so caching it under
    /// this territory would file one country's providers under another's.
    #[test]
    fn a_genuine_list_under_the_wrong_pointer_is_refused() {
        let elsewhere = verify_lotl(EU_LOTL)
            .expect("the LOTL verifies")
            .pointers()
            .iter()
            .find(|p| {
                p.territory.as_deref() != Some("FI")
                    && p.territory.is_some()
                    && !p.certificates.is_empty()
            })
            .expect("the LOTL points at more than one territory")
            .clone();

        match entry_for(&elsewhere, Ok(FI_LIST.to_owned())) {
            CachedTrustedList::Unavailable { reason } => {
                assert!(reason.contains("did not verify"), "{reason}");
            }
            other => panic!("Finland's list must not verify under another pointer: {other:?}"),
        }
    }

    /// A store that records what it was asked to hold.
    #[derive(Default)]
    struct Recording(std::sync::Mutex<std::collections::BTreeMap<String, CachedTrustedList>>);

    #[async_trait::async_trait]
    impl TrustedListStore for Recording {
        async fn load(
            &self,
        ) -> Result<std::collections::BTreeMap<String, CachedTrustedList>, dpp_domain::DppError>
        {
            Ok(self.0.lock().expect("lock").clone())
        }

        async fn put(
            &self,
            territory: &str,
            entry: &CachedTrustedList,
        ) -> Result<(), dpp_domain::DppError> {
            self.0
                .lock()
                .expect("lock")
                .insert(territory.to_owned(), entry.clone());
            Ok(())
        }
    }

    /// A store that refuses every write, as a database briefly down would.
    struct RefusesToWrite;

    #[async_trait::async_trait]
    impl TrustedListStore for RefusesToWrite {
        async fn load(
            &self,
        ) -> Result<std::collections::BTreeMap<String, CachedTrustedList>, dpp_domain::DppError>
        {
            Ok(std::collections::BTreeMap::new())
        }

        async fn put(
            &self,
            _territory: &str,
            _entry: &CachedTrustedList,
        ) -> Result<(), dpp_domain::DppError> {
            Err(dpp_domain::DppError::Validation(
                "the database is down".into(),
            ))
        }
    }

    /// 🚨 A write that fails is **not** counted as a refresh.
    ///
    /// The counters describe the cache, and a verdict is answered from the
    /// cache — `unavailable` is documented as the width of every `notListed`
    /// this node gives until the next pass. Counting before the write made them
    /// describe the pass's *intent*, so a pass whose every write failed still
    /// published a full healthy pair of gauges while the cache silently stopped
    /// ageing.
    ///
    /// The territory is named rather than only counted, because the publish step
    /// has to admit it: what the cache holds for it is no longer what the pass
    /// found, and a stale `Verified` row left behind by a failed `Unavailable`
    /// write would otherwise be served as though it had been refreshed.
    #[tokio::test]
    async fn a_write_that_fails_is_not_counted_as_a_refresh() {
        let store: Arc<dyn TrustedListStore> = Arc::new(RefusesToWrite);
        let mut stats = RefreshStats::default();

        // A list that verifies perfectly — so the only thing that can go wrong
        // below is the write, and `verified` would have counted it before.
        record(
            &store,
            "FI",
            &finnish_pointer(),
            Ok(FI_LIST.to_owned()),
            &mut stats,
        )
        .await;

        assert_eq!(
            stats.verified, 0,
            "a list that could not be written is not a list the cache holds"
        );
        assert_eq!(stats.unavailable, 0, "and it is not unavailable either");
        assert_eq!(stats.unwritten, 1);
        assert_eq!(
            stats.unwritten_territories,
            vec!["FI".to_owned()],
            "named, so the publish step can narrow the verdict to match the cache"
        );
    }

    /// The same holds when the entry being written is itself an unavailable one.
    ///
    /// This is the case the fail-closed rule is about: the territory verified on
    /// a previous pass, fails today, and the row that would replace its
    /// `Verified` copy cannot be written. Counting it as `unavailable` would say
    /// the cache had been narrowed when it had not.
    #[tokio::test]
    async fn an_unavailable_entry_that_cannot_be_written_is_unwritten_not_unavailable() {
        let store: Arc<dyn TrustedListStore> = Arc::new(RefusesToWrite);
        let mut stats = RefreshStats::default();

        record(
            &store,
            "DE",
            &finnish_pointer(),
            Err("could not be fetched: connection refused".to_owned()),
            &mut stats,
        )
        .await;

        assert_eq!(
            stats.unavailable, 0,
            "the cache was not narrowed, so the count that describes its width must not say it was"
        );
        assert_eq!(stats.unwritten, 1);
        assert_eq!(stats.unwritten_territories, vec!["DE".to_owned()]);
    }

    /// 🚨 An unreachable Member State reaches the cache as **unavailable**.
    ///
    /// The claim `entry_for` alone cannot make: that the pass *writes* the
    /// failure rather than moving on. A `continue` here would leave the territory
    /// absent, and absent is the cache's way of saying the list of trusted lists
    /// never named it — so a Member State that went down would stop being counted
    /// as unchecked and `notListed` would silently widen.
    #[tokio::test]
    async fn a_member_state_that_cannot_be_read_is_written_to_the_cache_as_unchecked() {
        let store: Arc<dyn TrustedListStore> = Arc::new(Recording::default());
        let mut stats = RefreshStats::default();

        record(
            &store,
            "FI",
            &finnish_pointer(),
            Err("could not be fetched: connection refused".to_owned()),
            &mut stats,
        )
        .await;

        let held = store.load().await.expect("load");
        assert!(
            matches!(held.get("FI"), Some(CachedTrustedList::Unavailable { .. })),
            "the territory must be present and unavailable, never absent: {held:?}"
        );
        assert_eq!(stats.unavailable, 1);
        assert_eq!(stats.verified, 0);
    }

    /// 🚨 Every territory the list of trusted lists names gets a row before any
    /// of them is read.
    ///
    /// The completeness bug this closes is reachable with nothing broken: a node
    /// booting mid-pass, or after an interrupted one, holds a partial cache —
    /// and a partial cache answers `unchecked: 0`, which `IssuerStanding`'s own
    /// documentation defines as "as complete as the list of trusted lists
    /// allows". Twenty-two territories never looked at would read as twenty-two
    /// territories that hold nothing.
    #[tokio::test]
    async fn every_named_territory_is_claimed_before_any_of_them_is_read() {
        let store: Arc<dyn TrustedListStore> = Arc::new(Recording::default());
        let fi = finnish_pointer();
        let mut de = fi.clone();
        de.territory = Some("DE".to_owned());

        let seeded = claim_unheld(&store, &[&fi, &de]).await;
        assert_eq!(seeded, 2);

        let held = store.load().await.expect("load");
        for territory in ["FI", "DE"] {
            match held.get(territory) {
                Some(CachedTrustedList::Unavailable { reason }) => assert!(
                    reason.contains("not read in this pass yet"),
                    "and it says why it is not an answer: {reason}"
                ),
                other => panic!(
                    "{territory} must hold a row before it is read, not be absent: {other:?}"
                ),
            }
        }
    }

    /// A territory already held is left exactly as it was.
    ///
    /// Seeding unconditionally would drop a verified list to `unavailable` on
    /// every pass, for as long as it took to re-read it — turning a refresh into
    /// a window where the node knows less than it did.
    #[tokio::test]
    async fn a_territory_already_held_is_not_dropped_to_unavailable_to_re_read_it() {
        let store: Arc<dyn TrustedListStore> = Arc::new(Recording::default());
        let fi = finnish_pointer();

        let mut stats = RefreshStats::default();
        record(&store, "FI", &fi, Ok(FI_LIST.to_owned()), &mut stats).await;

        let seeded = claim_unheld(&store, &[&fi]).await;
        assert_eq!(seeded, 0, "nothing to claim — it is already held");

        assert!(
            matches!(
                store.load().await.expect("load").get("FI"),
                Some(CachedTrustedList::Verified { .. })
            ),
            "and the verified list it held survives the claim pass"
        );
    }

    /// And a readable one reaches it verified, counted on the other side.
    #[tokio::test]
    async fn a_member_state_that_reads_is_written_to_the_cache_as_verified() {
        let store: Arc<dyn TrustedListStore> = Arc::new(Recording::default());
        let mut stats = RefreshStats::default();

        record(
            &store,
            "FI",
            &finnish_pointer(),
            Ok(FI_LIST.to_owned()),
            &mut stats,
        )
        .await;

        let held = store.load().await.expect("load");
        assert!(
            matches!(held.get("FI"), Some(CachedTrustedList::Verified { .. })),
            "{held:?}"
        );
        assert_eq!(stats.verified, 1);
        assert_eq!(stats.unavailable, 0);
    }
}
