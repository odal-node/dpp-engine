//! HTTP client wrapper (`OdalClient`) that authenticates to the node with an
//! API key (`Bearer`) or the local-admin credential (`Basic`).

use anyhow::Result;
use base64::Engine;
use reqwest::{Client, StatusCode, header::AUTHORIZATION};

/// Shared HTTP client wrapper that authenticates with the vault via an
/// `Authorization` header.
///
/// The scheme is part of the credential, not an implementation detail: the
/// node routes by scheme and will only try the API-key providers for `Bearer`
/// and the local-admin provider for `Basic`. Sending the local-admin
/// credential as `Bearer` authenticates as nothing at all. (There is no
/// unsigned/dev-JWT fallback: the node accepts only real API keys and
/// local-admin Basic auth.)
pub struct OdalClient {
    inner: Client,
    /// Complete `Authorization` header value, scheme included.
    authorization: String,
}

impl OdalClient {
    pub fn new(api_key: impl Into<String>) -> Self {
        Self {
            inner: Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .unwrap(),
            authorization: format!("Bearer {}", api_key.into()),
        }
    }

    /// Build a client that authenticates with the node's **local admin**
    /// credential — `Authorization: Basic base64(user:pass)`, which the node's
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
            authorization: format!("Basic {token}"),
        }
    }

    /// GET `url` with the client's credential. Returns the response body as a string.
    pub async fn get(&self, url: &str) -> Result<(StatusCode, String)> {
        let resp = self
            .inner
            .get(url)
            .header(AUTHORIZATION, &self.authorization)
            .send()
            .await?;
        let status = resp.status();
        let body = resp.text().await?;
        Ok((status, body))
    }

    /// POST JSON `payload` to `url` with the client's credential.
    pub async fn post_json(
        &self,
        url: &str,
        payload: &serde_json::Value,
    ) -> Result<(StatusCode, String)> {
        let resp = self
            .inner
            .post(url)
            .header(AUTHORIZATION, &self.authorization)
            .json(payload)
            .send()
            .await?;
        let status = resp.status();
        let body = resp.text().await?;
        Ok((status, body))
    }

    /// POST raw JSON `bytes` to `url` with the client's credential, sent verbatim (no
    /// reserialisation) — so a server-side content check sees exactly what
    /// was on disk.
    pub async fn post_bytes(&self, url: &str, bytes: Vec<u8>) -> Result<(StatusCode, String)> {
        let resp = self
            .inner
            .post(url)
            .header(AUTHORIZATION, &self.authorization)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(bytes)
            .send()
            .await?;
        let status = resp.status();
        let body = resp.text().await?;
        Ok((status, body))
    }

    /// POST with an empty body to `url` with the client's credential — for endpoints
    /// that take no request payload.
    pub async fn post_empty(&self, url: &str) -> Result<(StatusCode, String)> {
        let resp = self
            .inner
            .post(url)
            .header(AUTHORIZATION, &self.authorization)
            .send()
            .await?;
        let status = resp.status();
        let body = resp.text().await?;
        Ok((status, body))
    }

    /// PATCH JSON `payload` to `url` with the client's credential.
    pub async fn patch_json(
        &self,
        url: &str,
        payload: &serde_json::Value,
    ) -> Result<(StatusCode, String)> {
        let resp = self
            .inner
            .patch(url)
            .header(AUTHORIZATION, &self.authorization)
            .json(payload)
            .send()
            .await?;
        let status = resp.status();
        let body = resp.text().await?;
        Ok((status, body))
    }

    /// DELETE `url` with the client's credential.
    pub async fn delete(&self, url: &str) -> Result<(StatusCode, String)> {
        let resp = self
            .inner
            .delete(url)
            .header(AUTHORIZATION, &self.authorization)
            .send()
            .await?;
        let status = resp.status();
        let body = resp.text().await?;
        Ok((status, body))
    }

    /// Upload a file as `multipart/form-data` (field name `file`) to `url` with
    /// the client's credential — the shape the integrator's
    /// `POST /api/v1/import/{product group}` expects. The filename is preserved so the
    /// server can detect CSV vs XLSX.
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
            .header(AUTHORIZATION, &self.authorization)
            .multipart(form)
            .send()
            .await?;
        let status = resp.status();
        let body = resp.text().await?;
        Ok((status, body))
    }

    /// Upload a signed plugin as `multipart/form-data` — a `wasm` file part
    /// (filename preserved so the node can derive the product group) plus a `sig` part
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
            .header(AUTHORIZATION, &self.authorization)
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
    let (client, cfg) = load_client_unchecked()?;
    // A fresh install has no profile and no credential. Reaching the node in
    // that state earns a 401, and the CLI then reports a credential problem to
    // someone who has not configured anything yet — the one thing they cannot
    // act on. An API key from the environment with no profile is a legitimate
    // 12-factor deployment, so the absence of *both* is what identifies this.
    if cfg.api_key.is_empty() && !crate::config::has_profiles() {
        anyhow::bail!(crate::config::NO_PROFILE_HINT);
    }
    Ok((client, cfg))
}

/// Load the active profile and build a client **without** requiring that
/// anything be configured.
///
/// For the two commands that authenticate nothing: `odal status` reads public
/// `/health` endpoints and `odal schema check` reads `/health` plus a public
/// upstream. On an unconfigured machine, probing the localhost defaults is a
/// truthful answer rather than a misleading one.
pub fn load_client_unchecked() -> Result<(OdalClient, crate::config::Config)> {
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
    /// The node's per-field extension member. Absent on older nodes and on
    /// problems that are not about fields, which is why it defaults rather
    /// than being required.
    #[serde(default)]
    errors: Vec<ProblemFieldError>,
}

#[derive(serde::Deserialize)]
struct ProblemFieldError {
    field: String,
    message: String,
}

/// Render a non-2xx response as a human-readable message. Every node service
/// (vault/identity/integrator/resolver) replies with an RFC 7807 problem body
/// on error — this extracts `title`/`detail` from it. Falls back to the raw
/// (truncated) body for anything that isn't that shape.
///
/// When the body carries the `errors` member, the per-field failures are
/// rendered one per line instead of as `detail`'s semicolon-joined sentence.
/// The result is multi-line: callers embedding it inside a wider line should
/// pass it through [`crate::stateless::render::indent_continuation`].
pub fn describe_error(status: StatusCode, body: &str) -> String {
    match serde_json::from_str::<ProblemBody>(body) {
        Ok(p) if !p.errors.is_empty() => render_field_errors(&p),
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

/// One line per rejected field, with any clause every message repeats lifted
/// out and stated once.
///
/// The repetition is not incidental. A `FieldError` has to stand alone — the
/// domain cannot know whether it will be read beside its siblings — so a rule
/// that explains itself, like the Battery Regulation's mandatory-content
/// check, appends the same justifying sentence to all thirty of its errors.
/// Read as a list, that is thirty copies of one sentence; printing it once at
/// the end says the same thing and leaves the per-field half legible.
fn render_field_errors(p: &ProblemBody) -> String {
    let shared = shared_trailing_clause(&p.errors);

    let mut out = format!(
        "{} — {} field{} rejected:",
        p.title,
        p.errors.len(),
        if p.errors.len() == 1 { "" } else { "s" }
    );
    for e in &p.errors {
        let message = shared
            .as_deref()
            .and_then(|s| e.message.strip_suffix(s))
            .map_or(e.message.as_str(), |m| m.trim_end().trim_end_matches(';'));
        if e.field.is_empty() {
            out.push_str(&format!("\n  {message}"));
        } else {
            out.push_str(&format!("\n  {}  {message}", e.field));
        }
    }
    if let Some(s) = shared {
        out.push_str(&format!("\n  (each of the above: {s})"));
    }
    out
}

/// The final `"; "`-separated clause, when every message ends with the same
/// one and has something else in front of it. `None` otherwise — including for
/// a single error, where there is nothing to share.
fn shared_trailing_clause(errors: &[ProblemFieldError]) -> Option<String> {
    if errors.len() < 2 {
        return None;
    }
    let last = |m: &str| m.rsplit("; ").next().map(str::to_owned);
    let candidate = last(&errors[0].message)?;
    // A message that is *only* the shared clause has no per-field half left to
    // print, so lifting it out would lose information rather than tidy it.
    let holds = errors.iter().all(|e| {
        last(&e.message).as_deref() == Some(candidate.as_str()) && e.message.len() > candidate.len()
    });
    holds.then_some(candidate)
}

#[cfg(test)]
mod tests {
    use super::*;

    // The node routes by Authorization scheme: `Bearer` only ever reaches the
    // API-key providers, `Basic` only ever reaches the local-admin provider.
    // Sending the local-admin credential as `Bearer` therefore authenticates
    // as nothing, which breaks first-run bootstrap — the one flow that has no
    // API key yet to fall back on.
    #[test]
    fn credentials_carry_the_scheme_the_node_routes_on() {
        let api_key = OdalClient::new("odal_sk_example");
        assert_eq!(api_key.authorization, "Bearer odal_sk_example");

        let admin = OdalClient::with_local_admin("alice", "secret123");
        let expected = base64::engine::general_purpose::STANDARD.encode("alice:secret123");
        assert_eq!(admin.authorization, format!("Basic {expected}"));
    }

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

    /// The shape a battery publish rejection actually arrives in: many fields,
    /// every message carrying the same justifying clause. One line per field,
    /// the shared clause stated once — not a single four-thousand-character
    /// line, which is what `detail` alone produced.
    #[test]
    fn field_errors_render_one_line_each_with_the_shared_clause_lifted_out() {
        let clause = "a passport omitting it does not carry the content the Battery \
                      Regulation requires of this category";
        let fields = ["batteryModelId", "manufacturingPlace", "cathodeMaterial"];
        let errors: Vec<_> = fields
            .iter()
            .map(|f| {
                serde_json::json!({
                    "field": format!("/productGroupData/{f}"),
                    "message": format!(
                        "'{f}' is mandatory for a 'industrial' battery and is absent; {clause}"
                    ),
                })
            })
            .collect();
        let body = serde_json::json!({
            "type": "https://problems.odal-node.io/unprocessable-entity",
            "title": "Unprocessable Entity",
            "status": 422,
            "detail": "joined; sentence",
            "errors": errors,
        })
        .to_string();

        let msg = describe_error(StatusCode::UNPROCESSABLE_ENTITY, &body);
        let lines: Vec<&str> = msg.lines().collect();

        assert_eq!(lines[0], "Unprocessable Entity — 3 fields rejected:");
        assert_eq!(
            lines[1],
            "  /productGroupData/batteryModelId  'batteryModelId' is mandatory for a 'industrial' battery and is absent"
        );
        assert_eq!(lines.len(), 5, "3 fields + header + shared clause: {msg}");
        assert_eq!(lines[4], format!("  (each of the above: {clause})"));
        assert!(
            !lines[1].contains("does not carry"),
            "the shared clause must not also be repeated per field"
        );
    }

    /// One error has no sibling to share a clause with, so nothing is lifted —
    /// pulling the tail off a lone message would only make it less complete.
    #[test]
    fn a_single_field_error_keeps_its_whole_message() {
        let body = serde_json::json!({
            "type": "https://problems.odal-node.io/unprocessable-entity",
            "title": "Unprocessable Entity",
            "status": 422,
            "errors": [{ "field": "/gtin", "message": "check digit is wrong; recompute it" }],
        })
        .to_string();

        let msg = describe_error(StatusCode::UNPROCESSABLE_ENTITY, &body);
        assert_eq!(
            msg,
            "Unprocessable Entity — 1 field rejected:\n  /gtin  check digit is wrong; recompute it"
        );
    }

    /// An older node, or any problem that is not about fields, must render
    /// exactly as it did before the extension member existed.
    #[test]
    fn a_body_without_the_errors_member_renders_as_before() {
        let body = r#"{"type":"https://problems.odal-node.io/not-found","title":"Not Found","status":404,"detail":"passport abc123 does not exist"}"#;
        assert_eq!(
            describe_error(StatusCode::NOT_FOUND, body),
            "Not Found — passport abc123 does not exist"
        );
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
