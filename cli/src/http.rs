//! HTTP client wrapper (`OdalClient`) that authenticates to the node with a bearer API key.

use anyhow::Result;
use base64::Engine;
use reqwest::{Client, StatusCode};

/// Shared HTTP client wrapper that authenticates with the vault using a
/// `Authorization: Bearer <token>` header.
///
/// The configured `api_key` is forwarded verbatim — an Odal API key
/// (`odal_sk_…`) validated by the node's `ApiKeyAuthProvider`. (There is no
/// unsigned/dev-JWT fallback: the node accepts only real API keys and
/// local-admin Basic auth.)
pub struct OdalClient {
    inner: Client,
    bearer: String,
}

impl OdalClient {
    pub fn new(api_key: impl Into<String>) -> Self {
        Self {
            inner: Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .unwrap(),
            bearer: api_key.into(),
        }
    }

    /// Build a client that authenticates with the node's **local admin**
    /// credential — `Authorization: Bearer base64(user:pass)`, which the node's
    /// `LocalAuthProvider` accepts. Used during first-run setup before any API
    /// key exists.
    pub fn with_local_admin(user: &str, pass: &str) -> Self {
        let token =
            base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}").as_bytes());
        Self {
            inner: Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .unwrap(),
            bearer: token,
        }
    }

    /// GET `url` with Bearer token. Returns the response body as a string.
    pub async fn get(&self, url: &str) -> Result<(StatusCode, String)> {
        let resp = self.inner.get(url).bearer_auth(&self.bearer).send().await?;
        let status = resp.status();
        let body = resp.text().await?;
        Ok((status, body))
    }

    /// POST JSON `payload` to `url` with Bearer token.
    pub async fn post_json(
        &self,
        url: &str,
        payload: &serde_json::Value,
    ) -> Result<(StatusCode, String)> {
        let resp = self
            .inner
            .post(url)
            .bearer_auth(&self.bearer)
            .json(payload)
            .send()
            .await?;
        let status = resp.status();
        let body = resp.text().await?;
        Ok((status, body))
    }

    /// POST raw JSON `bytes` to `url` with Bearer token, sent verbatim (no
    /// reserialisation) — so a server-side content check sees exactly what
    /// was on disk.
    pub async fn post_bytes(&self, url: &str, bytes: Vec<u8>) -> Result<(StatusCode, String)> {
        let resp = self
            .inner
            .post(url)
            .bearer_auth(&self.bearer)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(bytes)
            .send()
            .await?;
        let status = resp.status();
        let body = resp.text().await?;
        Ok((status, body))
    }

    /// POST with an empty body to `url` with Bearer token — for endpoints
    /// that take no request payload.
    pub async fn post_empty(&self, url: &str) -> Result<(StatusCode, String)> {
        let resp = self
            .inner
            .post(url)
            .bearer_auth(&self.bearer)
            .send()
            .await?;
        let status = resp.status();
        let body = resp.text().await?;
        Ok((status, body))
    }

    /// PATCH JSON `payload` to `url` with Bearer token.
    pub async fn patch_json(
        &self,
        url: &str,
        payload: &serde_json::Value,
    ) -> Result<(StatusCode, String)> {
        let resp = self
            .inner
            .patch(url)
            .bearer_auth(&self.bearer)
            .json(payload)
            .send()
            .await?;
        let status = resp.status();
        let body = resp.text().await?;
        Ok((status, body))
    }

    /// DELETE `url` with Bearer token.
    pub async fn delete(&self, url: &str) -> Result<(StatusCode, String)> {
        let resp = self
            .inner
            .delete(url)
            .bearer_auth(&self.bearer)
            .send()
            .await?;
        let status = resp.status();
        let body = resp.text().await?;
        Ok((status, body))
    }

    /// Upload a file as `multipart/form-data` (field name `file`) to `url` with
    /// Bearer token — the shape the integrator's `POST /api/v1/import/{sector}`
    /// expects. The filename is preserved so the server can detect CSV vs XLSX.
    pub async fn upload_file(
        &self,
        url: &str,
        filename: &str,
        bytes: Vec<u8>,
    ) -> Result<(StatusCode, String)> {
        let part = reqwest::multipart::Part::bytes(bytes).file_name(filename.to_owned());
        let form = reqwest::multipart::Form::new().part("file", part);
        let resp = self
            .inner
            .post(url)
            .bearer_auth(&self.bearer)
            .multipart(form)
            .send()
            .await?;
        let status = resp.status();
        let body = resp.text().await?;
        Ok((status, body))
    }

    /// Upload a signed plugin as `multipart/form-data` — a `wasm` file part
    /// (filename preserved so the node can derive the sector) plus a `sig` part
    /// carrying the detached Ed25519 signature. Mirrors `POST /api/v1/plugins`.
    pub async fn install_plugin(
        &self,
        url: &str,
        wasm_filename: &str,
        wasm: Vec<u8>,
        sig: Vec<u8>,
    ) -> Result<(StatusCode, String)> {
        let wasm_part = reqwest::multipart::Part::bytes(wasm).file_name(wasm_filename.to_owned());
        let sig_part = reqwest::multipart::Part::bytes(sig);
        let form = reqwest::multipart::Form::new()
            .part("wasm", wasm_part)
            .part("sig", sig_part);
        let resp = self
            .inner
            .post(url)
            .bearer_auth(&self.bearer)
            .multipart(form)
            .send()
            .await?;
        let status = resp.status();
        let body = resp.text().await?;
        Ok((status, body))
    }

    /// GET `url` without auth (used for public health endpoints).
    pub async fn get_public(&self, url: &str) -> Result<(StatusCode, String)> {
        let resp = self.inner.get(url).send().await?;
        let status = resp.status();
        let body = resp.text().await?;
        Ok((status, body))
    }
}

/// Load the active profile and build an authenticated client from its API
/// key — the standard startup glue every stateless command and console menu
/// action needs before it can talk to the node.
pub fn load_client() -> Result<(OdalClient, crate::config::Config)> {
    let cfg = crate::config::Config::load()?;
    let client = OdalClient::new(&cfg.api_key);
    Ok((client, cfg))
}

/// Parsed subset of an RFC 7807 problem body — just enough to render a human
/// sentence instead of the raw JSON.
#[derive(serde::Deserialize)]
struct ProblemBody {
    title: String,
    detail: Option<String>,
}

/// Render a non-2xx response as a human-readable message. Every node service
/// (vault/identity/integrator/resolver) replies with an RFC 7807 problem body
/// on error — this extracts `title`/`detail` from it. Falls back to the raw
/// (truncated) body for anything that isn't that shape.
pub fn describe_error(status: StatusCode, body: &str) -> String {
    match serde_json::from_str::<ProblemBody>(body) {
        Ok(p) => match p.detail.filter(|d| !d.is_empty()) {
            Some(d) => format!("{} — {d}", p.title),
            None => p.title,
        },
        Err(_) => format!(
            "HTTP {status}: {}",
            crate::stateless::render::truncate(body, 300)
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn describe_error_extracts_title_and_detail() {
        let body = r#"{"type":"https://problems.odal-node.io/not-found","title":"Not Found","status":404,"detail":"passport abc123 does not exist"}"#;
        assert_eq!(
            describe_error(StatusCode::NOT_FOUND, body),
            "Not Found — passport abc123 does not exist"
        );
    }

    #[test]
    fn describe_error_falls_back_when_detail_absent() {
        let body = r#"{"type":"https://problems.odal-node.io/bad-request","title":"Bad Request","status":400}"#;
        assert_eq!(describe_error(StatusCode::BAD_REQUEST, body), "Bad Request");
    }

    #[test]
    fn describe_error_falls_back_for_non_problem_bodies() {
        let msg = describe_error(StatusCode::BAD_GATEWAY, "<html>502 Bad Gateway</html>");
        assert!(msg.starts_with("HTTP 502 Bad Gateway: "));
        assert!(msg.contains("<html>502 Bad Gateway</html>"));
    }

    #[test]
    fn describe_error_truncates_a_huge_fallback_body() {
        let body = "x".repeat(1000);
        let msg = describe_error(StatusCode::INTERNAL_SERVER_ERROR, &body);
        assert!(
            msg.len() < 350,
            "expected a truncated message, got {} chars",
            msg.len()
        );
        assert!(msg.ends_with('…'));
    }
}
