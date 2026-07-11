//! `QtspSealAdapter` — stub impl of `SealPort`; wires to `GhostSeal` until
//! `QTSP_URL` + `QTSP_CLIENT_ID` are configured.

use async_trait::async_trait;
use dpp_domain::{
    domain::error::DppError,
    ports::seal::{
        GhostSeal, SealCapabilities, SealPort, SealRequest, SealVerification, SealedEnvelope,
    },
};
use tracing::warn;

/// Stub QTSP adapter.
///
/// When `qtsp_url` is `None` (QTSP not yet configured) all calls delegate to
/// `GhostSeal` and log a warning. Once a QTSP contract is in place, set
/// `QTSP_URL` + `QTSP_CLIENT_ID` in the node config to wire the real CSC adapter.
pub struct QtspSealAdapter {
    qtsp_url: Option<String>,
}

impl QtspSealAdapter {
    pub fn new(qtsp_url: Option<String>) -> Self {
        Self { qtsp_url }
    }
}

#[async_trait]
impl SealPort for QtspSealAdapter {
    async fn seal(&self, req: SealRequest) -> Result<SealedEnvelope, DppError> {
        if self.qtsp_url.is_none() {
            warn!("QTSP not configured — using GhostSeal (placeholder, no legal validity)");
            return GhostSeal.seal(req).await;
        }
        // TODO: implement CSC sign-hash flow against self.qtsp_url
        Err(DppError::Internal(
            "QtspSealAdapter: real CSC integration not yet implemented".into(),
        ))
    }

    async fn verify(&self, env: &SealedEnvelope) -> Result<SealVerification, DppError> {
        if self.qtsp_url.is_none() {
            return GhostSeal.verify(env).await;
        }
        Err(DppError::Internal(
            "QtspSealAdapter: real CSC verification not yet implemented".into(),
        ))
    }

    fn capabilities(&self) -> SealCapabilities {
        if self.qtsp_url.is_none() {
            // Ghost-backed placeholder path — report exactly what `GhostSeal`
            // actually does (its seal()/verify() succeed with synthetic values).
            GhostSeal.capabilities()
        } else {
            // Configured, but the real CSC flow isn't implemented — seal() and
            // verify() both return errors. Report no capability rather than
            // advertising JAdES sealing the adapter cannot deliver, so a caller
            // that checks capabilities() first isn't contradicted by seal().
            SealCapabilities {
                supported_formats: Vec::new(),
                supported_modes: Vec::new(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unconfigured_reports_ghost_capabilities() {
        // The placeholder path genuinely produces (synthetic) seals.
        let caps = QtspSealAdapter::new(None).capabilities();
        assert!(!caps.supported_formats.is_empty());
    }

    #[test]
    fn configured_but_unimplemented_reports_no_capability() {
        // capabilities() must not contradict seal()/verify(), which error here.
        let caps = QtspSealAdapter::new(Some("https://qtsp.example".into())).capabilities();
        assert!(
            caps.supported_formats.is_empty(),
            "must not advertise sealing it cannot deliver"
        );
        assert!(caps.supported_modes.is_empty());
    }
}
