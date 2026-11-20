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

use std::io::Read as _;
use std::path::Path;

use anyhow::{Context as _, Result};
use serde_json::Value;

use crate::{
    config::Config,
    http::{OdalClient, describe_error},
};

/// Appended to an error raised after the node has stored a record or a
/// document: the write has happened, and a retry would count it twice.
const STORED_NO_DELETE: &str = "; the record is stored and there is no delete, so do not record it again unless you pass the same --idempotency-key";

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
    serde_json::from_str(&response).with_context(|| {
        format!("the node recorded the discard but its response was not JSON{STORED_NO_DELETE}")
    })
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
    let bytes = read_evidence_file(path)?;
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

/// The id the node stored a discard record under. A reply without a usable id
/// is an error, not a record printed with a dash for its id.
pub fn stored_record_id(stored: &Value) -> Result<&str> {
    match stored.get("id").and_then(Value::as_str) {
        Some(id) if !id.trim().is_empty() => Ok(id),
        _ => anyhow::bail!(
            "the node recorded the discard but its reply has no usable `id`{STORED_NO_DELETE}"
        ),
    }
}

/// The SHA-256 the node computed for an attached document.
pub fn attached_sha256(attached: &Value) -> Result<&str> {
    match attached.get("sha256").and_then(Value::as_str) {
        Some(sha) if !sha.trim().is_empty() => Ok(sha),
        _ => anyhow::bail!(
            "the node attached the document but its reply has no usable `sha256`; the document \
             is attached"
        ),
    }
}

/// What a record still lacks: for each requirement, the evidence kinds that
/// meet it and the basis it rests on. An absent `missingEvidence` is an error,
/// not an empty list, because it would read as a record with nothing missing.
pub fn missing_requirements(answer: &Value) -> Result<Vec<(Vec<&str>, &str)>> {
    let Some(requirements) = answer.get("missingEvidence").and_then(Value::as_array) else {
        anyhow::bail!("the node's reply has no `missingEvidence` array");
    };
    requirements
        .iter()
        .map(|requirement| -> Result<(Vec<&str>, &str)> {
            let kinds = requirement
                .get("anyOf")
                .and_then(Value::as_array)
                .filter(|kinds| !kinds.is_empty())
                .context("a requirement in the node's reply has no non-empty `anyOf`")?
                .iter()
                .map(|kind| {
                    kind.as_str()
                        .context("a kind in a requirement's `anyOf` is not a string")
                })
                .collect::<Result<Vec<&str>>>()?;
            let basis = requirement
                .get("basis")
                .and_then(Value::as_str)
                .context("a requirement in the node's reply has no string `basis`")?;
            Ok((kinds, basis))
        })
        .collect()
}

/// The bytes of the evidence file at `path`. Reads at most one byte past the
/// node's limit, so a file too large for the node is refused without being
/// held in memory whole.
fn read_evidence_file(path: &Path) -> Result<Vec<u8>> {
    let file = std::fs::File::open(path).with_context(|| format!("reading {}", path.display()))?;
    let mut bytes = Vec::new();
    file.take(dpp_types::EVIDENCE_FILE_MAX_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("reading {}", path.display()))?;
    if bytes.len() > dpp_types::EVIDENCE_FILE_MAX_BYTES {
        anyhow::bail!(
            "{} is larger than the 25 MiB one evidence file may be",
            path.display()
        );
    }
    Ok(bytes)
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

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{attached_sha256, missing_requirements, read_evidence_file, stored_record_id};

    /// A reply that names no `missingEvidence` array is refused. Read as an empty
    /// list, it would print that nothing is missing.
    #[test]
    fn a_missing_evidence_reply_without_an_array_is_an_error() {
        for reply in [
            json!({}),
            json!({"missingEvidence": null}),
            json!({"missingEvidence": {}}),
        ] {
            let err = missing_requirements(&reply).expect_err("no array, no requirements");
            assert!(err.to_string().contains("missingEvidence"), "{err}");
        }
    }

    #[test]
    fn an_empty_missing_evidence_array_lists_no_requirements() {
        let reply = json!({"missingEvidence": []});
        let parsed = missing_requirements(&reply).expect("an empty list");
        assert!(parsed.is_empty());
    }

    /// A requirement needs both its kinds and its basis to be shown.
    #[test]
    fn a_requirement_needs_kinds_and_a_basis() {
        let no_basis = json!({"missingEvidence": [{"anyOf": ["receipt"]}]});
        let err = missing_requirements(&no_basis).expect_err("no basis");
        assert!(err.to_string().contains("basis"), "{err}");

        let no_kinds = json!({"missingEvidence": [{"anyOf": [], "basis": "x"}]});
        let err = missing_requirements(&no_kinds).expect_err("empty anyOf");
        assert!(err.to_string().contains("anyOf"), "{err}");
    }

    #[test]
    fn a_well_formed_requirement_parses_to_its_kinds_and_basis() {
        let reply = json!({"missingEvidence": [{
            "anyOf": ["deliveryDocumentation", "receipt"],
            "basis": "the operator's size class"
        }]});
        let parsed = missing_requirements(&reply).expect("a well-formed reply");
        assert_eq!(
            parsed,
            vec![(
                vec!["deliveryDocumentation", "receipt"],
                "the operator's size class"
            )]
        );
    }

    /// A blank id names no record, so a reply carrying one is refused.
    #[test]
    fn a_stored_record_needs_a_non_blank_id() {
        assert_eq!(
            stored_record_id(&json!({"id": "0190c0de"})).expect("an id"),
            "0190c0de"
        );
        for reply in [json!({}), json!({"id": ""}), json!({"id": "  "})] {
            let err = stored_record_id(&reply).expect_err("no usable id");
            assert!(err.to_string().contains("`id`"), "{err}");
            assert!(
                err.to_string().contains("do not record it again"),
                "a retry would double-count, so the error says not to: {err}"
            );
        }
    }

    #[test]
    fn an_attachment_needs_a_sha256() {
        let err = attached_sha256(&json!({"kind": "receipt"})).expect_err("no sha256");
        assert!(err.to_string().contains("`sha256`"), "{err}");
        assert!(
            err.to_string().contains("the document is attached"),
            "{err}"
        );
        assert_eq!(
            attached_sha256(&json!({"sha256": "ab12"})).expect("a sha256"),
            "ab12"
        );
    }

    /// The cap is inclusive: a file of exactly the limit is read whole.
    #[test]
    fn a_file_at_the_cap_is_read_whole() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let path = dir.path().join("at-cap.pdf");
        std::fs::write(&path, vec![7u8; dpp_types::EVIDENCE_FILE_MAX_BYTES]).expect("write");

        let bytes = read_evidence_file(&path).expect("a file at the cap");
        assert_eq!(bytes.len(), dpp_types::EVIDENCE_FILE_MAX_BYTES);
    }

    #[test]
    fn a_file_one_byte_over_the_cap_is_refused() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let path = dir.path().join("over-cap.pdf");
        std::fs::write(&path, vec![7u8; dpp_types::EVIDENCE_FILE_MAX_BYTES + 1]).expect("write");

        let err = read_evidence_file(&path).expect_err("one byte over the cap");
        assert!(err.to_string().contains("larger than the 25 MiB"), "{err}");
    }
}
