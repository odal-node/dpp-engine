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

    match &entry {
        CachedTrustedList::Verified { .. } => stats.verified += 1,
        CachedTrustedList::Unavailable { reason } => {
            stats.unavailable += 1;
            tracing::warn!(
                %territory,
                %reason,
                "a Member State's trusted list could not be verified — a provider listed \
                 there is indistinguishable from one listed nowhere, and the seal \
                 qualification verdict reports the territory as unchecked"
            );
        }
    }

    if let Err(e) = store.put(territory, &entry).await {
        // Loud, because a pass that cannot write is a cache that silently stops
        // ageing while every log line says it refreshed.
        tracing::warn!(%territory, error = %e, "could not store a trusted list");
    }
}

/// What one pass over the Union found.
///
/// Returned rather than only logged so the caller can set gauges and a test can
/// assert on it — the same arrangement `DrainStats` and `SealAudit` use.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
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

    tracing::info!(
        verified = stats.verified,
        unavailable = stats.unavailable,
        unnamed = stats.unnamed,
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
