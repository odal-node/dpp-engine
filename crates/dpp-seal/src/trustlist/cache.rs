//! Reading the node's trusted-list cache back into a verdict's inputs.

use super::model::UnverifiedTrustedList;
use super::verify::VerifiedTrustedList;

/// Turn a node's trusted-list cache into what [`crate::qualification::qualify`]
/// consults.
///
/// ✅ Reg. (EU) No 910/2014 Art. 22 — the lists are what Art. 32(1)(a)–(b),
/// reached for seals by Art. 40, is answered from.
///
/// 🚨 **Both halves come out together, and that is the point.** The verified
/// lists are what gets searched; the unavailable territories are what stops
/// `IssuerStanding::NotListed` overclaiming. A caller that took only the first
/// would answer "this issuer is on no list" for a perfectly qualified provider
/// in a Member State whose list could not be read, and nothing in the verdict
/// would distinguish that from a genuine miss. `TrustedListStore::load` returns
/// them together for the same reason.
///
/// A cached entry whose stored content will not deserialize is reported as
/// **unavailable**, not dropped: dropping it would make the territory *absent*,
/// and absent means the list of trusted lists never named it. The cache is this
/// node's own writing, so this should not happen — and if it does, the verdict
/// says the territory could not be consulted rather than quietly narrowing.
#[must_use]
pub fn from_cache(
    cached: &std::collections::BTreeMap<String, dpp_types::trust::CachedTrustedList>,
) -> (
    Vec<VerifiedTrustedList>,
    Vec<dpp_types::qualification::UncheckedTerritory>,
) {
    let mut lists = Vec::new();
    let mut unchecked = Vec::new();

    for (territory, entry) in cached {
        match entry {
            dpp_types::trust::CachedTrustedList::Verified {
                content, signed_by, ..
            } => match serde_json::from_value::<UnverifiedTrustedList>(content.clone()) {
                Ok(parsed) => {
                    lists.push(VerifiedTrustedList::from_store(parsed, signed_by.clone()));
                }
                Err(e) => unchecked.push(dpp_types::qualification::UncheckedTerritory {
                    territory: territory.clone(),
                    reason: format!("the cached copy could not be read back: {e}"),
                }),
            },
            dpp_types::trust::CachedTrustedList::Unavailable { reason } => {
                unchecked.push(dpp_types::qualification::UncheckedTerritory {
                    territory: territory.clone(),
                    reason: reason.clone(),
                });
            }
        }
    }

    (lists, unchecked)
}
