//! Ghost-honesty invariant.
//!
//! The system refuses to present placeholder trust as real trust. Every trust
//! port (seal, registry sync, back-up copy, …) reports the *tier* that produced it —
//! `Ghost` (placeholder), `Sandbox` (real service, non-production), or `Live` —
//! and a production node **fails to boot** if a required port resolved to a
//! ghost. The guard is list-driven: a newly-added port inherits the invariant
//! by appearing in the report, never by editing a hardcoded check.
//!
//! Corollary — the one failure mode of a list-driven guard: a port that is
//! never added to [`NodeTrustReport::ports`] is invisible to it. The check
//! only ever sees what the composition root put in the list, so wiring a new
//! required trust port anywhere in `dpp-node`'s boot sequence must include
//! registering it here, or `enforce_profile` will silently pass regardless of
//! that port's real tier.

use std::collections::BTreeMap;

use async_trait::async_trait;
use dpp_domain::DppError;
use serde::Serialize;

/// Trust tier a resolved adapter operates at. Gauge encoding: Ghost=0, Sandbox=1,
/// Live=2 (`trust_mode{port="…"}`).
/// Ordered deliberately: `Ghost < Sandbox < Live`. The ordering is what lets a
/// profile state a floor rather than enumerate the tiers it rejects, so adding a
/// tier later does not silently pass an existing guard.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TrustMode {
    /// Placeholder — no real trust authority behind it (test double).
    Ghost,
    /// A real external service, but a non-production/sandbox instance.
    Sandbox,
    /// Production trust authority.
    Live,
}

impl TrustMode {
    /// Lower-case label used in the trust posture and in logs.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Ghost => "ghost",
            Self::Sandbox => "sandbox",
            Self::Live => "live",
        }
    }

    /// Prometheus gauge encoding (Ghost=0, Sandbox=1, Live=2).
    #[must_use]
    pub fn gauge_value(&self) -> f64 {
        match self {
            Self::Ghost => 0.0,
            Self::Sandbox => 1.0,
            Self::Live => 2.0,
        }
    }

    /// True for the placeholder tier — the one a production node refuses.
    #[must_use]
    pub fn is_ghost(&self) -> bool {
        matches!(self, Self::Ghost)
    }
}

/// Deployment profile — which trust tiers this environment will boot on.
///
/// Three environments, not two, because "sandbox" is a property of the
/// **deployment** rather than a tier a production node may quietly carry. A
/// sandbox node is a full node in every respect except that the authorities
/// behind it are test ones; running it separately is the closest rehearsal of
/// production there is, and keeping the profiles apart is what stops a test
/// certificate ever sealing a passport that claims to be real.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum NodeProfile {
    /// Ghosts allowed; the default and the licensed dev-environment profile.
    Development,
    /// A real deployment against **test** authorities. Ghosts on required ports
    /// are a hard boot failure, exactly as in production — what differs is that
    /// `Sandbox` tiers are accepted, so the environment can be exercised
    /// end-to-end without a production credential.
    Sandbox,
    /// Ghosts **and** sandboxes on required ports are a hard boot failure.
    /// Only `Live` will do: a production node states that its passports are
    /// backed by real authorities, and a sandbox tier makes that untrue.
    Production,
}

impl NodeProfile {
    /// Read `NODE_PROFILE` from the environment. Anything other than
    /// `production` or `sandbox` (including unset) is `Development`.
    #[must_use]
    pub fn from_env() -> Self {
        match std::env::var("NODE_PROFILE").ok().as_deref() {
            Some("production") => Self::Production,
            Some("sandbox") => Self::Sandbox,
            _ => Self::Development,
        }
    }

    /// The lowest trust tier this profile will boot a required port on.
    #[must_use]
    pub fn minimum_tier(self) -> Option<TrustMode> {
        match self {
            Self::Development => None,
            Self::Sandbox => Some(TrustMode::Sandbox),
            Self::Production => Some(TrustMode::Live),
        }
    }
}

/// One resolved trust port and the tier it operates at.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct TrustPort {
    /// Stable port name (`"seal"`, `"registry_sync"`, `"backup"`).
    pub port: &'static str,
    /// The tier the resolved adapter operates at.
    pub mode: TrustMode,
    /// If true, a production node must not boot while this port is `Ghost`.
    /// (Archive is optional — NoOp is tolerated with a warning until EN 18221
    /// backup work lands.)
    pub required: bool,
}

/// The node's resolved trust posture — logged at boot, served on the
/// authenticated node-state route, exported as gauges, and enforced against
/// the profile.
#[derive(Debug, Clone)]
pub struct NodeTrustReport {
    /// Active deployment profile.
    pub profile: NodeProfile,
    /// Every trust port the composition root resolved.
    pub ports: Vec<TrustPort>,
}

impl NodeTrustReport {
    /// Build a report from the profile and the resolved ports.
    #[must_use]
    pub fn new(profile: NodeProfile, ports: Vec<TrustPort>) -> Self {
        Self { profile, ports }
    }

    /// The tier one named port resolved to, if the composition root resolved it.
    ///
    /// `None` means the port was never resolved — a deployment that wires no such
    /// adapter at all — which is **not** the same as `Ghost`, a port that was
    /// resolved and landed on a placeholder. A caller reporting "not configured"
    /// and one reporting "configured with a stand-in" are telling an operator two
    /// different things, and only one of them is a boot blocker.
    #[must_use]
    pub fn mode_of(&self, port: &str) -> Option<TrustMode> {
        self.ports.iter().find(|p| p.port == port).map(|p| p.mode)
    }

    /// Required ports that resolved to `Ghost` — the production boot blockers.
    #[must_use]
    pub fn ghosted_required(&self) -> Vec<&'static str> {
        self.ports
            .iter()
            .filter(|p| p.required && p.mode.is_ghost())
            .map(|p| p.port)
            .collect()
    }

    /// Enforce the profile. In `Production`, returns `Err` with an actionable
    /// message naming every offending port if any required port is a ghost.
    /// In `Development`, always `Ok`.
    ///
    /// # Errors
    /// The offending-port message when a production node would boot on ghosts.
    pub fn enforce_profile(&self) -> Result<(), String> {
        let Some(minimum) = self.profile.minimum_tier() else {
            return Ok(());
        };

        // Below the floor, not merely ghosted. `Production` demands `Live`, so a
        // sandbox tier fails it too — a production node asserts that real
        // authorities stand behind its passports, and a provider's test
        // certificate makes that assertion false while looking identical.
        let below: Vec<&str> = self
            .ports
            .iter()
            .filter(|p| p.required && p.mode < minimum)
            .map(|p| p.port)
            .collect();
        if below.is_empty() {
            return Ok(());
        }

        let profile = match self.profile {
            NodeProfile::Production => "production",
            NodeProfile::Sandbox => "sandbox",
            NodeProfile::Development => "development",
        };
        Err(format!(
            "NODE_PROFILE={profile} refuses to boot: required trust port(s) [{}] resolved \
             below `{}`. Configure a real adapter, or run a profile that admits the tier \
             you have.",
            below.join(", "),
            minimum.as_str()
        ))
    }

    /// The node's trust posture as an API fragment:
    /// `{ "profile": …, "trustMode": { port: mode, … } }`.
    ///
    /// Named for the posture rather than for `/health`, which no longer carries
    /// it — the posture is served on the authenticated node-state route, and
    /// `camelCase` because that is what every other key on that response uses.
    #[must_use]
    pub fn posture_json(&self) -> serde_json::Value {
        let modes: serde_json::Map<String, serde_json::Value> = self
            .ports
            .iter()
            .map(|p| (p.port.to_owned(), serde_json::json!(p.mode.as_str())))
            .collect();
        serde_json::json!({
            "profile": self.profile,
            "trustMode": modes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ports(seal: TrustMode, registry: TrustMode, backup: TrustMode) -> Vec<TrustPort> {
        vec![
            TrustPort {
                port: "seal",
                mode: seal,
                required: true,
            },
            TrustPort {
                port: "registry_sync",
                mode: registry,
                required: true,
            },
            TrustPort {
                port: "backup",
                mode: backup,
                required: false,
            },
        ]
    }

    #[test]
    fn gauge_encoding_is_stable() {
        assert_eq!(TrustMode::Ghost.gauge_value(), 0.0);
        assert_eq!(TrustMode::Sandbox.gauge_value(), 1.0);
        assert_eq!(TrustMode::Live.gauge_value(), 2.0);
    }

    #[test]
    fn production_refuses_ghost_seal_and_names_it() {
        let report = NodeTrustReport::new(
            NodeProfile::Production,
            ports(TrustMode::Ghost, TrustMode::Sandbox, TrustMode::Ghost),
        );
        let err = report.enforce_profile().expect_err("must refuse");
        assert!(
            err.contains("seal"),
            "message names the offending port: {err}"
        );
        // backup is Ghost but not required → not a blocker.
        assert!(!err.contains("backup"));
        assert_eq!(report.ghosted_required(), vec!["seal"]);
    }

    #[test]
    fn production_boots_when_required_ports_real() {
        let report = NodeTrustReport::new(
            NodeProfile::Production,
            ports(TrustMode::Live, TrustMode::Live, TrustMode::Ghost),
        );
        assert!(
            report.enforce_profile().is_ok(),
            "ghost archive is tolerated"
        );
    }

    #[test]
    fn development_tolerates_ghosts() {
        let report = NodeTrustReport::new(
            NodeProfile::Development,
            ports(TrustMode::Ghost, TrustMode::Ghost, TrustMode::Ghost),
        );
        assert!(report.enforce_profile().is_ok());
    }

    #[test]
    fn a_named_port_reports_its_own_mode() {
        let report = NodeTrustReport::new(
            NodeProfile::Development,
            ports(TrustMode::Live, TrustMode::Ghost, TrustMode::Sandbox),
        );
        assert_eq!(report.mode_of("seal"), Some(TrustMode::Live));
        assert_eq!(report.mode_of("registry_sync"), Some(TrustMode::Ghost));
    }

    /// A port nobody resolved is `None`, not `Ghost`.
    ///
    /// The distinction a caller serves to an operator: "this deployment wires no
    /// such adapter" and "this deployment wired a placeholder" are different
    /// states, and only the second refuses a production boot. Defaulting the
    /// first to `Ghost` would report a blocker that does not exist — and, worse,
    /// would make a *renamed* port indistinguishable from a ghosted one.
    #[test]
    fn a_port_that_was_never_resolved_is_none_rather_than_ghost() {
        let report = NodeTrustReport::new(
            NodeProfile::Development,
            ports(TrustMode::Live, TrustMode::Live, TrustMode::Live),
        );
        assert_eq!(report.mode_of("no_such_port"), None);
    }

    #[test]
    fn posture_json_surfaces_each_port_mode() {
        let report = NodeTrustReport::new(
            NodeProfile::Production,
            ports(TrustMode::Ghost, TrustMode::Sandbox, TrustMode::Live),
        );
        let j = report.posture_json();
        assert_eq!(j["profile"], "production");
        assert_eq!(j["trustMode"]["seal"], "ghost");
        assert_eq!(j["trustMode"]["registry_sync"], "sandbox");
        assert_eq!(j["trustMode"]["backup"], "live");
    }

    /// A production node refuses a **sandbox** tier, not only a ghost.
    ///
    /// This is the separation stated as a test. Before it, `Production`
    /// admitted `Sandbox`, so a production deployment could seal passports with
    /// a provider's test certificate and assert nothing was wrong — the two
    /// look identical from outside, and only the tier distinguishes them.
    #[test]
    fn production_refuses_a_sandbox_seal() {
        let report = NodeTrustReport::new(
            NodeProfile::Production,
            ports(TrustMode::Sandbox, TrustMode::Live, TrustMode::Live),
        );
        let err = report
            .enforce_profile()
            .expect_err("production must not boot on a test certificate");
        assert!(err.contains("seal"), "{err}");
        assert!(err.contains("live"), "the message names the floor: {err}");
    }

    /// A sandbox node boots on sandbox tiers, and still refuses ghosts.
    ///
    /// The point of the profile: a full rehearsal of production against test
    /// authorities. Admitting ghosts too would make it a development node with
    /// a different name.
    #[test]
    fn sandbox_admits_sandbox_but_not_ghost() {
        let ok = NodeTrustReport::new(
            NodeProfile::Sandbox,
            ports(TrustMode::Sandbox, TrustMode::Sandbox, TrustMode::Ghost),
        );
        assert!(ok.enforce_profile().is_ok(), "sandbox tiers are the point");

        let bad = NodeTrustReport::new(
            NodeProfile::Sandbox,
            ports(TrustMode::Ghost, TrustMode::Sandbox, TrustMode::Live),
        );
        assert!(
            bad.enforce_profile().is_err(),
            "a ghost on a required port is a boot failure in sandbox too"
        );
    }

    /// Development boots on anything, including all ghosts.
    #[test]
    fn development_admits_every_tier() {
        let report = NodeTrustReport::new(
            NodeProfile::Development,
            ports(TrustMode::Ghost, TrustMode::Ghost, TrustMode::Ghost),
        );
        assert!(report.enforce_profile().is_ok());
    }

    /// The ordering the floor comparison relies on.
    #[test]
    fn trust_tiers_are_ordered_ghost_sandbox_live() {
        assert!(TrustMode::Ghost < TrustMode::Sandbox);
        assert!(TrustMode::Sandbox < TrustMode::Live);
    }
}

/// One territory's row in the trusted-list cache.
///
/// A row is in exactly one of two states, and keeping them apart is the whole
/// value of the cache. A qualification verdict that says "no list names this
/// issuer" is a statement about the Union only when nothing is
/// [`Unavailable`](Self::Unavailable); while any territory is, a provider listed
/// *there* is indistinguishable from one listed nowhere.
///
/// The parsed list travels as `serde_json::Value` rather than a typed list
/// because the type belongs to `dpp-seal` and this crate sits below it. The
/// store does not interpret it — it writes what it is handed and returns it
/// unchanged — so a type here would buy nothing and invert the dependency.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CachedTrustedList {
    /// The list verified, and this is what it said.
    Verified {
        /// The parsed list, as `dpp_seal::trustlist::UnverifiedTrustedList`.
        content: serde_json::Value,
        /// Base64 SHA-256 of the certificate whose signature was checked.
        signed_by: String,
        /// When that check ran. Evidence is only ever as fresh as this.
        verified_at: chrono::DateTime<chrono::Utc>,
    },
    /// The list of trusted lists names this territory and it could not be read.
    ///
    /// **Not the same as absent.** A territory absent from the cache was never
    /// named; one recorded here was named and could not be verified, which is
    /// the fact a verdict has to carry.
    Unavailable {
        /// Why, in terms an operator can act on.
        reason: String,
    },
}

/// Where a node keeps the trusted lists it has verified.
///
/// # Why this is persisted rather than held in memory
///
/// Fetching and verifying the Union costs roughly 40 MB of XML and an XAdES
/// signature check per document. In memory, every restart pays that again, and
/// for the length of a whole refresh the node reports "nothing consulted" —
/// which is indistinguishable from a node whose refresh is broken. The same
/// argument `SealAuditStore` makes for the audit's cursor and report applies
/// here without modification.
///
/// # What it deliberately is not
///
/// A record of validations. Under Reg. (EU) No 910/2014 Art. 33, reached for
/// seals by Art. 40, a *qualified* validation service is a QTSP service whose
/// result carries the provider's own seal. Nothing stored here is signed and
/// nothing here is qualified — a row is this node's note that it read a
/// published list, and must never be presented as an attestation.
#[async_trait]
pub trait TrustedListStore: Send + Sync {
    /// Every territory the cache holds, verified or not.
    ///
    /// Returned together because a caller needs both halves to know how wide its
    /// answer is: the verified lists to search, and the unavailable ones to
    /// admit. Splitting them into two calls would make it possible to read one
    /// and forget the other, which is the exact failure the cache exists to
    /// prevent.
    ///
    /// # Errors
    ///
    /// Propagates the store's own failure.
    async fn load(&self) -> Result<BTreeMap<String, CachedTrustedList>, DppError>;

    /// Write one territory's state, replacing whatever was there.
    ///
    /// Per-territory rather than a bulk replace, and that is load-bearing: a
    /// refresh that fails for one Member State must leave every other row alone,
    /// and must leave *that* row's previous good copy in place rather than
    /// emptying it. A caller deciding to record it as unavailable is making a
    /// different choice from failing to refresh it, and only the caller can tell
    /// those apart.
    ///
    /// # Errors
    ///
    /// Propagates the store's own failure.
    async fn put(&self, territory: &str, entry: &CachedTrustedList) -> Result<(), DppError>;
}
