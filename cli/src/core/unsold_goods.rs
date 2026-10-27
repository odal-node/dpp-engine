//! The ESPR Art. 24 disclosure of unsold consumer products, via the node API.
//!
//! # Why this is not under `passport`
//!
//! Art. 24's subject is an **operator over a financial year**: the figures are
//! published on the operator's own website, and the trigger is discarding
//! unsold stock, none of which is a product placed on the market. There is no
//! digital product passport anywhere in Art. 24 or Art. 25, so the disclosure
//! sits beside the other operator-scoped actions and not under a passport id.
//!
//! # The CLI does not restate the report
//!
//! A disclosure is one report per financial year, in the format Implementing
//! Regulation (EU) 2026/2 prescribes. `put` sends a report file as it is, and
//! the node checks it against the `unsold-goods` JSON Schema and answers what is
//! wrong. A client-side copy of that shape would be a second gate that can only
//! ever disagree with the first.

use anyhow::{Context as _, Result};
use serde_json::Value;

use crate::{
    config::Config,
    http::{OdalClient, describe_error},
};

/// Store `report` as the disclosure for its financial year, returning the
/// node's answer: the stored disclosure and its advisory lint findings.
///
/// The year is read from the report to address it. The node refuses a report
/// whose `financialYear.start` is not the year the path names, so the two can
/// never disagree in storage.
pub async fn action_unsold_goods_put(
    report: &Value,
    client: &OdalClient,
    cfg: &Config,
) -> Result<Value> {
    let start = report
        .pointer("/financialYear/start")
        .and_then(Value::as_str)
        .context("the report has no financialYear.start, which is the year it is stored under")?;
    let url = disclosure_url(&cfg.vault_url, Some(start))?;
    let (status, response) = client.put_json(&url, report).await?;
    if !status.is_success() {
        anyhow::bail!(
            "recording the disclosure failed: {}",
            describe_error(status, &response)
        );
    }
    serde_json::from_str(&response)
        .context("the node recorded the disclosure but its response was not JSON")
}

/// The disclosure for the financial year that starts on `start`.
pub async fn action_unsold_goods_get(
    start: &str,
    client: &OdalClient,
    cfg: &Config,
) -> Result<Value> {
    let url = disclosure_url(&cfg.vault_url, Some(start))?;
    let (status, response) = client.get(&url).await?;
    if !status.is_success() {
        anyhow::bail!(
            "reading the disclosure failed: {}",
            describe_error(status, &response)
        );
    }
    serde_json::from_str(&response).context("the node's response was not JSON")
}

/// Every stored disclosure, the latest financial year first.
pub async fn action_unsold_goods_list(client: &OdalClient, cfg: &Config) -> Result<Vec<Value>> {
    let url = disclosure_url(&cfg.vault_url, None)?;
    let (status, response) = client.get(&url).await?;
    if !status.is_success() {
        anyhow::bail!(
            "listing the disclosures failed: {}",
            describe_error(status, &response)
        );
    }
    let parsed: Value =
        serde_json::from_str(&response).context("the node's response was not JSON")?;
    Ok(parsed.as_array().cloned().unwrap_or_default())
}

/// The collection URL, or one financial year's URL with `start` as a single
/// percent-encoded path segment.
///
/// Appended as a segment rather than interpolated, so a `/`, `?` or `#` in a
/// date read from a file stays data and cannot address a different route or
/// drop part of the request. The node validates the date and answers `400`
/// naming the rule.
fn disclosure_url(base: &str, start: Option<&str>) -> Result<String> {
    let mut url = reqwest::Url::parse(&format!("{base}/api/v1/unsold-goods"))
        .with_context(|| format!("the configured vault URL is not a usable URL: {base}"))?;
    if let Some(start) = start {
        url.path_segments_mut()
            .map_err(|()| anyhow::anyhow!("the configured vault URL cannot carry a path: {base}"))?
            .push(start);
    }
    Ok(url.to_string())
}

#[cfg(test)]
mod disclosure_url_tests {
    use super::disclosure_url;

    const BASE: &str = "http://localhost:8001/vault";

    #[test]
    fn no_year_addresses_the_collection() {
        assert_eq!(
            disclosure_url(BASE, None).unwrap(),
            "http://localhost:8001/vault/api/v1/unsold-goods"
        );
    }

    #[test]
    fn a_year_is_one_path_segment() {
        assert_eq!(
            disclosure_url(BASE, Some("2026-01-01")).unwrap(),
            "http://localhost:8001/vault/api/v1/unsold-goods/2026-01-01"
        );
    }

    /// A value read from a file must stay one segment: a `/` cannot reach a
    /// different route, and a `?` or `#` cannot turn the rest into a query or a
    /// fragment the node never sees.
    #[test]
    fn delimiters_in_a_year_stay_inside_its_segment() {
        let url = disclosure_url(BASE, Some("2026/../x?y#z")).unwrap();
        let parsed = reqwest::Url::parse(&url).unwrap();
        assert_eq!(parsed.query(), None);
        assert_eq!(parsed.fragment(), None);
        assert_eq!(
            parsed.path_segments().unwrap().next_back(),
            Some("2026%2F..%2Fx%3Fy%23z")
        );
    }
}
