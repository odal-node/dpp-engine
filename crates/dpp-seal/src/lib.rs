//! eIDAS qualified seal adapter for Odal Node.
//!
//! CSC/QTSP wire types and the stub `QtspSealAdapter`. The real implementation
//! calls a Qualified Trust Service Provider over the Cloud Signature Consortium
//! (CSC) API once a QTSP contract is in place and the EU registry API is live.
//!
//! # Structure
//!
//! - `csc` — CSC API wire types (credential handle, sign hash request/response)
//! - `QtspSealAdapter` — stub impl of `SealPort`; wires to `GhostSeal` until
//!   `QTSP_URL` + `QTSP_CLIENT_ID` are configured

pub mod csc;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn unconfigured_adapter_delegates_to_ghost() {
        use dpp_domain::ports::seal::{SealCredentialRef, SealFormat, SealMode};

        let adapter = QtspSealAdapter::new(None);
        let req = SealRequest {
            payload_hash: "deadbeef1234".into(),
            mode: SealMode::ProviderSeal,
            key_ref: SealCredentialRef {
                qtsp_id: "stub-qtsp".into(),
                credential_id: "cred-001".into(),
            },
            sig_format: SealFormat::Jades,
        };
        let env = adapter.seal(req).await.unwrap();
        assert!(env.placeholder);
        assert!(env.seal_value.starts_with("GHOST-SEAL-"));
    }

    #[tokio::test]
    async fn configured_adapter_returns_not_implemented() {
        use dpp_domain::ports::seal::{SealCredentialRef, SealFormat, SealMode};

        let adapter = QtspSealAdapter::new(Some("https://qtsp.example.com".into()));
        let req = SealRequest {
            payload_hash: "deadbeef1234".into(),
            mode: SealMode::ProviderSeal,
            key_ref: SealCredentialRef {
                qtsp_id: "real-qtsp".into(),
                credential_id: "cred-001".into(),
            },
            sig_format: SealFormat::Jades,
        };
        let result = adapter.seal(req).await;
        assert!(matches!(result, Err(DppError::Internal(_))));
    }
}
