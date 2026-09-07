//! Port for the signed compliance-ruleset channel — read the version in force,
//! and re-read the channel to adopt a new bundle without a restart. Implemented
//! by the node's `ActiveRuleset` and consumed by the vault's admin endpoint and
//! its node-state report.
//!
//! This lives in `dpp-common`, not `dpp-core`: *when* a node adopts a published
//! ruleset is a deployment/operations concern, not a regulatory one (the Golden
//! Rule). What a bundle **is**, and the fail-closed rules for accepting one,
//! stay in `dpp_rules::bundle` where they belong. Both `dpp-vault` (the
//! consumer) and `dpp-node` (the implementor) already depend on `dpp-common`,
//! so the trait sits at their shared floor without a new crate edge — the same
//! placement argument as [`crate::plugin_admin`].
//!
//! # Why the vault holds a port rather than a version string
//!
//! It held a `String`, cloned once at boot into `AppState`. That made the
//! version the node reported a statement about *when the process started*, not
//! about which rules it is running — so the moment a swap became possible, the
//! report would have gone stale and stayed stale. `/api/v1/node/state` exists
//! to be honest about exactly this (it is why the field is not on the public
//! `/health`), so the version has to be read through a live handle.

use async_trait::async_trait;
use serde::Serialize;

/// The outcome of a successful [`RulesetAdmin::reload`].
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RulesetReload {
    /// The bundle version in force after the reload.
    pub ruleset_version: String,
    /// Whether this reload actually replaced the ruleset.
    ///
    /// `false` means the channel re-offered the bundle already in force and
    /// nothing changed — the ordinary answer on a quiet channel. A caller that
    /// reported every successful reload as an adoption would turn a poller into
    /// a stream of false change events.
    pub changed: bool,
}

/// Failure reloading the ruleset channel.
///
/// Every variant is fail-closed: the ruleset in force is unchanged, and the
/// node keeps validating against it.
///
/// [`Self::NotYetEffective`] and [`Self::Superseded`] are separate variants
/// rather than one `Rejected` because `dpp_rules::bundle` distinguishes them
/// deliberately and they tell an operator opposite things: a not-yet-effective
/// bundle should be held and re-offered once its date arrives, a superseded one
/// should be discarded. Collapsing them here would throw that away at the only
/// boundary where an operator can see it.
#[derive(Debug, thiserror::Error)]
pub enum RulesetReloadError {
    /// This node has no signed channel configured, so there is nothing to
    /// re-read. It is running its compiled-in baseline.
    #[error("no signed ruleset channel is configured on this node")]
    NotConfigured,
    /// The channel could not produce bytes — the file is missing or unreadable,
    /// the feed is unreachable, or what arrived was not a bundle at all.
    /// Transport-level, and says nothing about whether a bundle is acceptable.
    #[error("ruleset channel unavailable: {0}")]
    Unavailable(String),
    /// The bundle failed verification: bad signature, content-hash mismatch, or
    /// a malformed manifest.
    #[error("ruleset bundle rejected: {0}")]
    Rejected(String),
    /// The bundle is authentic but its rules do not take effect yet. Hold the
    /// bytes and re-offer them once its effective date arrives.
    #[error("ruleset bundle is not yet effective: {0}")]
    NotYetEffective(String),
    /// The bundle is authentic but older than the one already in force.
    /// Discard it — this is the rollback refusal.
    #[error("ruleset bundle is superseded: {0}")]
    Superseded(String),
}

/// The node's signed ruleset channel, as the vault sees it.
#[async_trait]
pub trait RulesetAdmin: Send + Sync {
    /// The bundle version in force **right now**. Read live on every call; a
    /// cached copy is what this port exists to stop.
    fn active_version(&self) -> String;

    /// Re-read the configured channel and, if it yields a bundle that verifies
    /// against the pinned publisher key and is current, swap it in atomically.
    ///
    /// Requests in flight keep serving throughout — the swap replaces a pointer
    /// and never blocks a reader.
    ///
    /// # Errors
    /// [`RulesetReloadError`] on every failure path, each of which leaves the
    /// ruleset in force untouched.
    async fn reload(&self) -> Result<RulesetReload, RulesetReloadError>;
}
