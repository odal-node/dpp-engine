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
        GhostSeal.capabilities()
    }
}
