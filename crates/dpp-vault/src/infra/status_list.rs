//! Engine-side status-list fetch — bridges core's pure bit-decode and the network.
//!
//! Core (`dpp_crypto::status_list`) handles decoding a W3C Bitstring Status List
//! credential once its `encodedList` is in hand. This module owns the HTTP GET of
//! the credential and the JSON extraction of that field — the only piece that
//! cannot live in the `no_std`/infra-free core.
//!
//! ## Fail-closed contract
//!
//! Returns `None` on ANY failure (missing status, unreachable URL, bad JSON,
//! invalid encoding). Callers must pass the result directly to
//! `dpp_crypto::credential::verify_credential_with_revocation`:
//! a credential that declares a status but whose list is `None` is treated
//! as **revoked** by core — the credential cannot grant access until the list
//! is reachable and the bit is clear.

use dpp_crypto::{DppAccessCredential, StatusList};
use reqwest::Client;

/// Fetch and decode the W3C Bitstring Status List declared by `credential`.
///
/// Returns `None` when:
/// - `credential.credential_status` is absent (nothing to fetch),
/// - `status_list_credential` URL is missing from the status descriptor,
/// - the HTTP GET fails or returns a non-2xx status,
/// - the response is not valid JSON or lacks `credentialSubject.encodedList`, or
/// - the `encodedList` is not a valid multibase-base64url-gzipped bitstring.
///
/// Pass the result directly to `verify_credential_with_revocation` — `None`
/// triggers the fail-closed policy there.
pub async fn fetch_status_list_for(
    http: &Client,
    credential: &DppAccessCredential,
) -> Option<StatusList> {
    let url = credential
        .credential_status
        .as_ref()?
        .status_list_credential
        .as_ref()?;

    let resp = http
        .get(url.as_str())
        .timeout(std::time::Duration::from_secs(5))
        .send()
        .await
        .ok()?;

    if !resp.status().is_success() {
        tracing::debug!(
            status = %resp.status(),
            url = url.as_str(),
            "status list fetch returned non-2xx; treating credential as revoked (fail-closed)"
        );
        return None;
    }

    let body: serde_json::Value = resp.json().await.ok()?;

    // W3C Bitstring Status List v1.0 — the credential's credentialSubject
    // carries the encodedList field.
    let encoded = body
        .get("credentialSubject")
        .and_then(|cs| cs.get("encodedList"))
        .and_then(|v| v.as_str())?;

    match StatusList::from_encoded_list(encoded) {
        Ok(list) => Some(list),
        Err(e) => {
            tracing::debug!(error = %e, url = url.as_str(), "status list decode failed; treating credential as revoked (fail-closed)");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, routing::get};
    use dpp_crypto::{CredentialBuilder, CredentialRole, CredentialStatus, DppCredentialSubject};
    use flate2::{Compression, write::GzEncoder};
    use std::io::Write;
    use tokio::net::TcpListener;

    fn sample_credential(status_url: Option<String>) -> DppAccessCredential {
        let subject = DppCredentialSubject {
            id: "did:web:repair.example.com".into(),
            name: "Repair Co".into(),
            role: CredentialRole::AuthorisedRepairer,
            country: "DE".into(),
            sectors: vec!["battery".into()],
            product_categories: vec![],
        };
        let mut builder = CredentialBuilder::new("did:web:authority.example.com".into(), subject);
        if let Some(url) = status_url {
            builder = builder.with_status(CredentialStatus {
                id: format!("{url}#0"),
                status_type: "BitstringStatusListEntry".into(),
                status_list_index: Some("0".into()),
                status_list_credential: Some(url),
            });
        }
        builder.build()
    }

    /// Build a minimal (one-byte) Bitstring Status List VC body with the given
    /// bitstring byte. Bit 0 is the MSB (big-endian within byte).
    fn status_list_vc(bits: &[u8]) -> serde_json::Value {
        let mut enc = GzEncoder::new(Vec::new(), Compression::default());
        enc.write_all(bits).unwrap();
        let gz = enc.finish().unwrap();
        use base64::Engine;
        let encoded = format!(
            "u{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&gz)
        );
        serde_json::json!({
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiableCredential", "BitstringStatusList"],
            "credentialSubject": {
                "type": "BitstringStatusList",
                "statusPurpose": "revocation",
                "encodedList": encoded
            }
        })
    }

    /// Spawn a minimal Axum server on a random port; return its base URL.
    async fn serve(router: Router) -> String {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test server");
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            axum::serve(listener, router).await.expect("serve");
        });
        format!("http://127.0.0.1:{port}")
    }

    #[tokio::test]
    async fn returns_some_for_valid_status_list() {
        // Bit 0 is set (index 0 revoked), bit 1 clear (index 1 not revoked).
        let body = status_list_vc(&[0b1000_0000]);
        let base = serve(Router::new().route(
            "/status/1",
            get(move || {
                let b = body.clone();
                async move { axum::Json(b) }
            }),
        ))
        .await;

        let cred = sample_credential(Some(format!("{base}/status/1")));
        let http = Client::new();
        let list = fetch_status_list_for(&http, &cred).await;

        assert!(list.is_some(), "should decode a valid status list");
        let list = list.unwrap();
        assert_eq!(list.get(0), Some(true), "bit 0 should be set (revoked)");
        assert_eq!(list.get(1), Some(false), "bit 1 should be clear");
    }

    #[tokio::test]
    async fn returns_none_when_credential_has_no_status() {
        let cred = sample_credential(None);
        let http = Client::new();
        let result = fetch_status_list_for(&http, &cred).await;
        assert!(
            result.is_none(),
            "no credentialStatus → None (no fetch needed)"
        );
    }

    #[tokio::test]
    async fn returns_none_on_http_404() {
        let base = serve(Router::new().route(
            "/status/missing",
            get(|| async { axum::http::StatusCode::NOT_FOUND }),
        ))
        .await;

        let cred = sample_credential(Some(format!("{base}/status/missing")));
        let http = Client::new();
        let result = fetch_status_list_for(&http, &cred).await;
        assert!(result.is_none(), "404 → None (fail-closed)");
    }

    #[tokio::test]
    async fn returns_none_on_missing_encoded_list_field() {
        let body = serde_json::json!({ "credentialSubject": { "type": "BitstringStatusList" } });
        let base = serve(Router::new().route(
            "/status/bad",
            get(move || {
                let b = body.clone();
                async move { axum::Json(b) }
            }),
        ))
        .await;

        let cred = sample_credential(Some(format!("{base}/status/bad")));
        let http = Client::new();
        let result = fetch_status_list_for(&http, &cred).await;
        assert!(result.is_none(), "missing encodedList → None (fail-closed)");
    }

    #[tokio::test]
    async fn returns_none_on_invalid_encoded_list() {
        let body = serde_json::json!({
            "credentialSubject": { "encodedList": "u!!!not-base64!!!" }
        });
        let base = serve(Router::new().route(
            "/status/garbage",
            get(move || {
                let b = body.clone();
                async move { axum::Json(b) }
            }),
        ))
        .await;

        let cred = sample_credential(Some(format!("{base}/status/garbage")));
        let http = Client::new();
        let result = fetch_status_list_for(&http, &cred).await;
        assert!(result.is_none(), "invalid encodedList → None (fail-closed)");
    }
}
