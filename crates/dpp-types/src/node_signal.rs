//! Signals about the node's own work that leave no other trace, kept in the
//! database so a restart does not clear them.
//!
//! What belongs here is narrow on purpose. A signal is an outcome nothing else
//! records: a publish refused because signing failed returns before any write,
//! and a ruleset load that failed leaves the old ruleset in place and no row
//! behind. Anything the node can work out from rows it already holds, such as an
//! outbox's depth, is read live where it is served and never copied here, because
//! a copy is a second answer that drifts. Rates and histories belong to the
//! metrics endpoint.
//!
//! Each signal keeps how many times it has failed, and when it last failed and
//! last succeeded. The count never resets, so it says nothing about *now*. The two
//! times do: a signal is failing while its latest outcome is a failure. The
//! PostgreSQL implementation is `dpp-dal`'s `PgNodeSignalRepo` (`ops/pg/0048`).

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use dpp_domain::DppError;

/// A signal the node keeps.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Signal {
    /// Signing a passport at publish. It fails when the signer refuses, and the
    /// publish is refused with it.
    Signing,
    /// Loading the Compliance Current ruleset from its channel, at boot, on each
    /// poll, or on an operator's reload. It fails when the channel cannot be read
    /// or the bundle it served is refused. The node keeps the ruleset it had.
    RulesetLoad,
}

impl Signal {
    /// Every signal, in the order the node reports them.
    pub const ALL: [Signal; 2] = [Signal::Signing, Signal::RulesetLoad];

    /// The name the signal is stored and served under. The one spelling of it:
    /// the database holds no list of names, so a new signal needs no migration.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Signal::Signing => "signing",
            Signal::RulesetLoad => "rulesetLoad",
        }
    }

    /// The signal stored under `name`, if this node knows it.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|signal| signal.name() == name)
    }
}

/// How one attempt went.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The attempt did what it was for.
    Succeeded,
    /// The attempt failed, and the node fell back or refused.
    Failed,
}

/// What the node has recorded for one signal.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SignalState {
    /// Failures since the node was first started. Never resets.
    pub failures: i64,
    /// When the latest failure was recorded, by the database clock.
    pub last_failed_at: Option<DateTime<Utc>>,
    /// When the latest success was recorded, by the database clock.
    pub last_succeeded_at: Option<DateTime<Utc>>,
}

impl SignalState {
    /// Whether the latest recorded outcome is a failure. A signal that has never
    /// failed is not failing; one that has failed and never succeeded is.
    #[must_use]
    pub fn is_failing(&self) -> bool {
        match (self.last_failed_at, self.last_succeeded_at) {
            (Some(failed), Some(succeeded)) => failed > succeeded,
            (Some(_), None) => true,
            (None, _) => false,
        }
    }
}

/// The durable signal store.
#[async_trait]
pub trait NodeSignals: Send + Sync {
    /// Record one outcome. A failure adds one to the signal's count; either
    /// outcome becomes the latest of its kind.
    async fn record(&self, signal: Signal, outcome: Outcome) -> Result<(), DppError>;

    /// Every signal in [`Signal::ALL`] order, with what has been recorded for it.
    /// A signal never recorded reads as [`SignalState::default`].
    async fn states(&self) -> Result<Vec<(Signal, SignalState)>, DppError>;
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;

    fn at(second: u32) -> Option<DateTime<Utc>> {
        Some(Utc.with_ymd_and_hms(2026, 11, 9, 12, 0, second).unwrap())
    }

    fn state(
        last_failed_at: Option<DateTime<Utc>>,
        last_succeeded_at: Option<DateTime<Utc>>,
    ) -> SignalState {
        SignalState {
            failures: i64::from(last_failed_at.is_some()),
            last_failed_at,
            last_succeeded_at,
        }
    }

    /// Failing means the latest outcome was a failure, whatever the count says.
    #[test]
    fn a_signal_is_failing_only_while_its_latest_outcome_is_a_failure() {
        assert!(!state(None, None).is_failing(), "never recorded");
        assert!(!state(None, at(1)).is_failing(), "only ever succeeded");
        assert!(state(at(1), None).is_failing(), "failed, never succeeded");
        assert!(state(at(2), at(1)).is_failing(), "failed after succeeding");
        assert!(!state(at(1), at(2)).is_failing(), "recovered");
    }

    /// Each name reads back as its signal, and no two share one.
    #[test]
    fn every_signal_has_its_own_name() {
        for signal in Signal::ALL {
            assert_eq!(Signal::from_name(signal.name()), Some(signal));
        }
        assert_eq!(Signal::from_name("retired"), None);
    }
}
