//! The ESPR Art. 24 and Art. 25 discard records, via the node API.
//!
//! # Why this is not under `passport`
//!
//! Art. 24's subject is an **operator over a financial year**: the discard is
//! the trigger, and no product is placed on the market. There is no digital
//! product passport anywhere in Art. 24 or Art. 25, so the records sit beside the
//! other operator-scoped actions and not under a passport id.
//!
//! # The CLI does not restate the record
//!
//! `record` sends the file as it is, and the node checks it against dpp-core's
//! discard-record schema and answers what is wrong. A client-side copy of that
//! shape would be a second gate that can only ever disagree with the first.

use std::path::Path;

use anyhow::{Context as _, Result};
use serde_json::Value;

use crate::{
    config::Config,
    http::{OdalClient, describe_error},
};

/// Record a discard: the record as the file holds it, and the passports of the
/// units it discards. Returns the stored record.
pub async fn action_discard_record(
    record: &Value,
    passport_ids: &[String],
    client: &OdalClient,
    cfg: &Config,
) -> Result<Value> {
    let url = format!("{}/api/v1/discard-records", cfg.vault_url);
    let body = serde_json::json!({ "record": record, "passportIds": passport_ids });
    let (status, response) = client.post_json_creating(&url, &body).await?;
    if !status.is_success() {
        anyhow::bail!(
            "recording the discard failed: {}",
            describe_error(status, &response)
        );
    }
    serde_json::from_str(&response)
        .context("the node recorded the discard but its response was not JSON")
}

/// The discard records discarded between `start` and `end`, inclusive.
pub async fn action_discard_list(
    start: &str,
    end: &str,
    client: &OdalClient,
    cfg: &Config,
) -> Result<Vec<Value>> {
    let url = list_url(&cfg.vault_url, start, end)?;
    let (status, response) = client.get(&url).await?;
    if !status.is_success() {
        anyhow::bail!(
            "listing the discards failed: {}",
            describe_error(status, &response)
        );
    }
    serde_json::from_str(&response).context("the node answered but its response was not JSON")
}

/// Attach the file at `path` to a record under `kind`. Returns the attachment.
pub async fn action_discard_attach(
    record_id: &str,
    kind: &str,
    path: &Path,
    client: &OdalClient,
    cfg: &Config,
) -> Result<Value> {
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let filename = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("evidence")
        .to_owned();
    let url = record_url(&cfg.vault_url, record_id, Some("evidence"))?;
    let (status, response) = client.upload_evidence(&url, kind, &filename, bytes).await?;
    if !status.is_success() {
        anyhow::bail!(
            "attaching the document failed: {}",
            describe_error(status, &response)
        );
    }
    serde_json::from_str(&response)
        .context("the node attached the document but its response was not JSON")
}

/// The evidence a record still lacks, read against the operator's size class.
pub async fn action_discard_missing(
    record_id: &str,
    client: &OdalClient,
    cfg: &Config,
) -> Result<Value> {
    let url = record_url(&cfg.vault_url, record_id, Some("missing-evidence"))?;
    let (status, response) = client.get(&url).await?;
    if !status.is_success() {
        anyhow::bail!(
            "reading what the record lacks failed: {}",
            describe_error(status, &response)
        );
    }
    serde_json::from_str(&response).context("the node answered but its response was not JSON")
}

/// `…/api/v1/discard-records`, with the year as two query parameters.
fn list_url(base: &str, start: &str, end: &str) -> Result<String> {
    let mut url = reqwest::Url::parse(&format!("{base}/api/v1/discard-records"))
        .with_context(|| format!("the configured vault URL is not a usable URL: {base}"))?;
    url.query_pairs_mut()
        .append_pair("financialYearStart", start)
        .append_pair("financialYearEnd", end);
    Ok(url.to_string())
}

/// `…/api/v1/discard-records/{id}[/{tail}]`, with the record id as one
/// percent-encoded path segment.
fn record_url(base: &str, record_id: &str, tail: Option<&str>) -> Result<String> {
    let mut url = reqwest::Url::parse(&format!("{base}/api/v1/discard-records"))
        .with_context(|| format!("the configured vault URL is not a usable URL: {base}"))?;
    {
        let mut segments = url.path_segments_mut().map_err(|()| {
            anyhow::anyhow!("the configured vault URL cannot carry a path: {base}")
        })?;
        segments.push(record_id);
        if let Some(tail) = tail {
            segments.push(tail);
        }
    }
    Ok(url.to_string())
}

#[cfg(test)]
mod url_tests {
    use super::{list_url, record_url};

    const BASE: &str = "http://localhost:8001/vault";

    /// A year is two parameters, and a value carrying a delimiter stays inside
    /// its own parameter.
    #[test]
    fn the_year_is_two_query_parameters() {
        let url = list_url(BASE, "2026-01-01", "2026-12-31").expect("a valid base");
        let parsed = reqwest::Url::parse(&url).expect("valid");
        let pairs: Vec<(String, String)> = parsed.query_pairs().into_owned().collect();
        assert_eq!(
            pairs,
            vec![
                ("financialYearStart".to_owned(), "2026-01-01".to_owned()),
                ("financialYearEnd".to_owned(), "2026-12-31".to_owned()),
            ]
        );
    }

    #[test]
    fn a_query_delimiter_in_a_date_stays_inside_its_parameter() {
        let url = list_url(BASE, "2026-01-01&x=1", "2026-12-31").expect("a valid base");
        let parsed = reqwest::Url::parse(&url).expect("valid");
        assert_eq!(parsed.query_pairs().count(), 2);
    }

    /// The record id is one path segment. A `/`, `?` or `#` in what the operator
    /// typed cannot reach another route.
    #[test]
    fn a_record_id_is_one_path_segment() {
        let url = record_url(BASE, "x/../../passport?y=1#z", Some("evidence")).expect("valid");
        let parsed = reqwest::Url::parse(&url).expect("valid");
        let segments: Vec<&str> = parsed.path_segments().expect("a path").collect();
        assert_eq!(
            segments,
            vec![
                "vault",
                "api",
                "v1",
                "discard-records",
                "x%2F..%2F..%2Fpassport%3Fy=1%23z",
                "evidence"
            ]
        );
        assert_eq!(parsed.query(), None);
        assert_eq!(parsed.fragment(), None);
    }
}
