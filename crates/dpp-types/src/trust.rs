//! Ghost-honesty invariant (chunk 03).
//!
//! The system refuses to present placeholder trust as real trust. Every trust
//! port (seal, registry sync, archive, …) reports the *tier* that produced it —
//! `Ghost` (placeholder), `Sandbox` (real service, non-production), or `Live` —
//! and a production node **fails to boot** if a required port resolved to a
//! ghost. The guard is list-driven: a newly-added port inherits the invariant
//! by appearing in the report, never by editing a hardcoded check.

use serde::Serialize;

/// Trust tier a resolved adapter operates at. Gauge encoding: Ghost=0, Sandbox=1,
/// Live=2 (`trust_mode{port="…"}`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
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
    /// Lower-case label used in `/health` and logs.
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

/// Deployment profile. Defaults to `Development`; `NODE_PROFILE=production`
/// opts into the strict boot guard.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum NodeProfile {
    /// Ghosts allowed; the default and the licensed dev-environment profile.
    Development,
    /// Ghosts on required ports are a hard boot failure.
    Production,
}

impl NodeProfile {
    /// Read `NODE_PROFILE` from the environment. Anything other than
    /// `production` (including unset) is `Development`.
    #[must_use]
    pub fn from_env() -> Self {
        match std::env::var("NODE_PROFILE").ok().as_deref() {
            Some("production") => Self::Production,
            _ => Self::Development,
        }
    }
}

/// One resolved trust port and the tier it operates at.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct TrustPort {
    /// Stable port name (`"seal"`, `"registry_sync"`, `"archive"`).
    pub port: &'static str,
    /// The tier the resolved adapter operates at.
    pub mode: TrustMode,
    /// If true, a production node must not boot while this port is `Ghost`.
    /// (Archive is optional — NoOp is tolerated with a warning until EN 18221
    /// backup work lands.)
    pub required: bool,
}

/// The node's resolved trust posture — logged at boot, surfaced on `/health`,
/// exported as gauges, and enforced against the profile.
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
        if self.profile != NodeProfile::Production {
            return Ok(());
        }
        let ghosts = self.ghosted_required();
        if ghosts.is_empty() {
            return Ok(());
        }
        Err(format!(
            "NODE_PROFILE=production refuses to boot: required trust port(s) [{}] resolved to a \
             placeholder (ghost). Configure a real adapter or run with NODE_PROFILE=development.",
            ghosts.join(", ")
        ))
    }

    /// `/health` fragment: `{ "profile": …, "trust_mode": { port: mode, … } }`.
    #[must_use]
    pub fn health_json(&self) -> serde_json::Value {
        let modes: serde_json::Map<String, serde_json::Value> = self
            .ports
            .iter()
            .map(|p| (p.port.to_owned(), serde_json::json!(p.mode.as_str())))
            .collect();
        serde_json::json!({
            "profile": self.profile,
            "trust_mode": modes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ports(seal: TrustMode, registry: TrustMode, archive: TrustMode) -> Vec<TrustPort> {
        vec![
            TrustPort { port: "seal", mode: seal, required: true },
            TrustPort { port: "registry_sync", mode: registry, required: true },
            TrustPort { port: "archive", mode: archive, required: false },
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
        assert!(err.contains("seal"), "message names the offending port: {err}");
        // archive is Ghost but not required → not a blocker.
        assert!(!err.contains("archive"));
        assert_eq!(report.ghosted_required(), vec!["seal"]);
    }

    #[test]
    fn production_boots_when_required_ports_real() {
        let report = NodeTrustReport::new(
            NodeProfile::Production,
            ports(TrustMode::Live, TrustMode::Live, TrustMode::Ghost),
        );
        assert!(report.enforce_profile().is_ok(), "ghost archive is tolerated");
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
    fn health_json_surfaces_each_port_mode() {
        let report = NodeTrustReport::new(
            NodeProfile::Production,
            ports(TrustMode::Ghost, TrustMode::Sandbox, TrustMode::Live),
        );
        let j = report.health_json();
        assert_eq!(j["profile"], "production");
        assert_eq!(j["trust_mode"]["seal"], "ghost");
        assert_eq!(j["trust_mode"]["registry_sync"], "sandbox");
        assert_eq!(j["trust_mode"]["archive"], "live");
    }
}
