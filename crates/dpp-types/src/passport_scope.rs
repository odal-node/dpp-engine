//! What `passportScope.status` says on the wire, and the one place it is spelt.
//!
//! The Art. 77(1) answer is dpp-core's, with its own words: `required`,
//! `notCovered`, `belowThreshold`, `capacityUnknown`, `notYetBinding`. This node
//! used to translate core's enum into those strings by hand, and the CLI read them
//! against a table of its own that still listed a word the node had stopped
//! sending and none of four it had started. Both now read the enum.

pub use dpp_rules::batteries::passport_scope::PassportScope;
use serde::{Deserialize, Serialize};

/// The `status` of a lint response's passport-scope report: core's Art. 77(1)
/// answer, spelt as core spells it, or `notApplicable` for a record that is not a
/// battery.
///
/// `notApplicable` is the node's word and not core's. Core's rule takes a battery
/// type, so it has no answer for a record that is not one, and the node says so
/// rather than inventing an outcome for it.
///
/// [`Other`](Self::Other) is for a reader. A node newer than the reader can report
/// an outcome core added since, and it is carried under the word it arrived with
/// rather than refused: the reader prints it and does not guess its meaning. The
/// node never builds one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ScopeStatus {
    /// Core's answer to whether Art. 77(1) owes this battery a passport.
    Art77(PassportScope),
    /// The record is not a battery, so the article has nothing to say.
    NotApplicable(NotApplicable),
    /// A word this build does not know. Read, never written.
    Other(String),
}

/// The one word of [`ScopeStatus`] that is not core's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum NotApplicable {
    /// Spelt `notApplicable`.
    NotApplicable,
}

impl From<Option<PassportScope>> for ScopeStatus {
    /// `None` is the record that is not a battery: core was not asked.
    fn from(scope: Option<PassportScope>) -> Self {
        scope.map_or(
            Self::NotApplicable(NotApplicable::NotApplicable),
            Self::Art77,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wire(status: &ScopeStatus) -> String {
        serde_json::to_value(status)
            .expect("serialises")
            .as_str()
            .expect("a string")
            .to_owned()
    }

    /// Core's five words, and the node's one, are what goes on the wire. A
    /// rename in core is a break for every reader, so the spelling is pinned
    /// here and not only in core.
    #[test]
    fn the_words_are_core_s_and_one_more() {
        let mut words: Vec<String> = PassportScope::ALL
            .iter()
            .map(|s| wire(&ScopeStatus::Art77(*s)))
            .collect();
        words.push(wire(&ScopeStatus::from(None)));
        assert_eq!(
            words,
            [
                "notCovered",
                "belowThreshold",
                "capacityUnknown",
                "notYetBinding",
                "required",
                "notApplicable"
            ]
        );
    }

    /// Every word reads back as what wrote it, including the node's own, which a
    /// plain read of core's enum would refuse.
    #[test]
    fn every_word_reads_back() {
        let mut all: Vec<ScopeStatus> = PassportScope::ALL
            .iter()
            .map(|s| ScopeStatus::Art77(*s))
            .collect();
        all.push(ScopeStatus::from(None));
        for status in all {
            let back: ScopeStatus =
                serde_json::from_value(serde_json::to_value(&status).unwrap()).unwrap();
            assert_eq!(back, status);
        }
    }

    /// A word this build does not know is carried, not refused: a reader newer
    /// or older than the node it talks to prints what it was told.
    #[test]
    fn a_word_this_build_does_not_know_is_carried() {
        let status: ScopeStatus =
            serde_json::from_value(serde_json::json!("somethingNew")).unwrap();
        assert_eq!(status, ScopeStatus::Other("somethingNew".to_owned()));
        assert_eq!(wire(&status), "somethingNew");
    }
}
