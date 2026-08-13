//! `QtspSealAdapter` — the `SealPort` implementation.
//!
//! Two states, and no third: an eID Easy backend, or `GhostSeal`. The previous
//! "configured but unimplemented" tier is gone — it was a state that had to
//! report empty capabilities so it would not contradict a `seal()` that always
//! errored.

use async_trait::async_trait;
use chrono::Utc;
use dpp_domain::{
    domain::error::DppError,
    ports::seal::{
        GhostSeal, SealCapabilities, SealFormat, SealMode, SealPort, SealRequest, SealVerification,
        SealedEnvelope,
    },
};
use tracing::warn;

use crate::eideasy::EideasyConfig;
use crate::eideasy::client::EideasyClient;
use crate::error::SealError;

/// What `verify()` says instead of guessing.
const VERIFY_UNSUPPORTED: &str = "seal verification is not implemented: a detached CAdES must be validated by an independent \
     AdES validator (no Rust implementation exists), and this adapter will not report a seal \
     valid on a check it did not perform";

/// eIDAS seal adapter.
pub struct QtspSealAdapter {
    backend: Backend,
}

enum Backend {
    /// Live eID Easy Cloud Direct e-Sealing.
    Eideasy(Box<EideasyClient>),
    /// Placeholder with no legal validity; a production node refuses to boot on it.
    Ghost,
}

impl QtspSealAdapter {
    /// Adapter backed by eID Easy.
    pub fn eideasy(config: EideasyConfig) -> Result<Self, SealError> {
        Ok(Self {
            backend: Backend::Eideasy(Box::new(EideasyClient::new(config)?)),
        })
    }

    /// Placeholder adapter — synthetic envelopes, no legal validity.
    pub fn ghost() -> Self {
        Self {
            backend: Backend::Ghost,
        }
    }

    /// The configured backend, when there is one. `None` means ghost-backed.
    pub fn config(&self) -> Option<&EideasyConfig> {
        match &self.backend {
            Backend::Eideasy(c) => Some(c.config()),
            Backend::Ghost => None,
        }
    }
}

#[async_trait]
impl SealPort for QtspSealAdapter {
    async fn seal(&self, req: SealRequest) -> Result<SealedEnvelope, DppError> {
        let client = match &self.backend {
            Backend::Ghost => {
                warn!("eID Easy not configured — using GhostSeal (placeholder, no legal validity)");
                return GhostSeal.seal(req).await;
            }
            Backend::Eideasy(c) => c,
        };

        // The digest doubles as the correlation label: eID Easy echoes `fileName`
        // back, so deriving it from the digest makes a mismatched response visible
        // without holding request state. No extension — see `EsealFile::file_name`.
        let file_name = format!(
            "dpp-{}",
            &req.payload_hash[..req.payload_hash.len().min(16)]
        );
        let seal_value = client
            .seal_digest(&file_name, &req.payload_hash)
            .await
            .map_err(DppError::from)?;

        Ok(SealedEnvelope {
            format: SealFormat::Cades,
            seal_value,
            // The signing certificate travels *inside* the detached CAdES, and
            // reading it out needs the CMS parser this adapter deliberately does
            // not have. Left `None` rather than filled with a guess.
            signing_cert_ref: None,
            sealed_at: Utc::now(),
            placeholder: false,
        })
    }

    async fn verify(&self, env: &SealedEnvelope) -> Result<SealVerification, DppError> {
        match &self.backend {
            Backend::Ghost => GhostSeal.verify(env).await,
            Backend::Eideasy(_) => Err(SealError::Unsupported(VERIFY_UNSUPPORTED).into()),
        }
    }

    fn capabilities(&self) -> SealCapabilities {
        match &self.backend {
            // The placeholder path genuinely produces (synthetic) seals — report
            // what `GhostSeal` actually does.
            Backend::Ghost => GhostSeal.capabilities(),
            // eID Easy Direct e-Sealing offers the CAdES profile only, and this
            // node holds the seal on operators' behalf, so `ProviderSeal` is the
            // one mode. `verify()` is unsupported and no capability claims it.
            Backend::Eideasy(_) => SealCapabilities {
                supported_formats: vec![SealFormat::Cades],
                supported_modes: vec![SealMode::ProviderSeal],
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eideasy::config::{SANDBOX_BASE_URL, test_config};

    #[test]
    fn unconfigured_reports_ghost_capabilities() {
        let caps = QtspSealAdapter::ghost().capabilities();
        assert!(!caps.supported_formats.is_empty());
    }

    #[test]
    fn the_eideasy_backend_advertises_cades_only() {
        let caps = QtspSealAdapter::eideasy(test_config(SANDBOX_BASE_URL))
            .unwrap()
            .capabilities();
        assert_eq!(caps.supported_formats, vec![SealFormat::Cades]);
        assert_eq!(caps.supported_modes, vec![SealMode::ProviderSeal]);
    }
}
