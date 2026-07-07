//! Integration-style tests for [`crate::adapter::QtspSealAdapter`].

use dpp_domain::domain::error::DppError;

use crate::adapter::QtspSealAdapter;

#[tokio::test]
async fn unconfigured_adapter_delegates_to_ghost() {
    use dpp_domain::ports::seal::{SealCredentialRef, SealFormat, SealMode, SealPort, SealRequest};

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
    use dpp_domain::ports::seal::{SealCredentialRef, SealFormat, SealMode, SealPort, SealRequest};

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
