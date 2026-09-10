//! The ESPR Art. 24 disclosure of unsold consumer products, via the node API.
//!
//! # Why this is not under `passport`
//!
//! Art. 24's subject is an **operator over a financial year**: the figures are
//! published on the operator's own website, and the trigger is discarding
//! unsold stock, none of which is a product placed on the market. There is no
//! digital product passport anywhere in Art. 24 or Art. 25, so these lines sit
//! beside the other operator-scoped actions and not under a passport id.

use anyhow::{Context as _, Result};
use serde_json::{Value, json};

use crate::{
    config::Config,
    http::{OdalClient, describe_error},
};

/// One line of the disclosure, as the caller supplied it.
///
/// The operator is deliberately absent: the report is about this node's own
/// operator, taken from its config, and there is no second operator on a
/// single-tenant node for a caller to legitimately name.
pub struct DisclosureLine {
    pub period: String,
    pub units: i64,
    pub kg: f64,
    pub category: String,
    pub reason: String,
    pub destination: String,
    pub justification: Option<String>,
    pub country: String,
}

/// Record one disclosure line, returning the id the node minted for it.
///
/// The justification rules are the node's and are not re-implemented here:
/// `exemptDestruction` requires one and every other destination refuses one,
/// and the node answers `422` naming which. A client-side copy of that rule
/// would be a second gate that can disagree with the first — and this one is
/// load-bearing, since Art. 25 prohibits the destruction outright from
/// 19 July 2026 and the justification is what records why it was permitted.
///
/// Sent through `post_json_creating`, so a `--idempotency-key` on the
/// invocation reaches the node. This route is in the node's keyed set and the
/// reason is the one that matters here: it serves no `DELETE`, so a line
/// recorded twice is permanent, and Art. 24 figures are published for a
/// financial year — a discard counted twice overstates what the operator did.
/// Plain `post_json` sent no key at all, which made the retry advice this
/// command prints impossible to follow.
pub async fn action_unsold_goods_record(
    line: &DisclosureLine,
    client: &OdalClient,
    cfg: &Config,
) -> Result<String> {
    let url = format!("{}/api/v1/unsold-goods", cfg.vault_url);
    let mut body = json!({
        "reportingPeriod": line.period,
        "unitCount": line.units,
        "volumeKg": line.kg,
        "productCategory": line.category,
        "reason": line.reason,
        "destination": line.destination,
        "countryOfDisposal": line.country,
    });
    if let Some(j) = &line.justification {
        body["destructionJustification"] = json!(j);
    }
    let (status, response) = client.post_json_creating(&url, &body).await?;
    if !status.is_success() {
        anyhow::bail!(
            "recording the disclosure line failed: {}",
            describe_error(status, &response)
        );
    }
    recorded_id(&response)
}

/// Read the recorded line's id out of a successful response.
///
/// An unreadable body is an error, never a placeholder. The status was already
/// a success when this is reached, so the line HAS been written — and this
/// route serves no `DELETE`, so it cannot be taken back. Printing
/// `(not reported)` where an id belongs told the operator the write had
/// succeeded while withholding the one value that lets them find it again, on
/// the one route where a duplicate is permanent and publicly disclosed.
fn recorded_id(response: &str) -> Result<String> {
    let body: Value = serde_json::from_str(response)
        .context("the node recorded the line but its response was not JSON")?;
    body.get("id")
        .and_then(Value::as_str)
        .filter(|id| !id.trim().is_empty())
        .map(str::to_owned)
        .context(
            "the node recorded the line but did not name it in its response. The line HAS \
             been written and there is no delete — list the disclosure for this period to \
             confirm it before recording it again.",
        )
}

/// List recorded disclosure lines, newest first, optionally for one year.
pub async fn action_unsold_goods_list(
    period: Option<&str>,
    client: &OdalClient,
    cfg: &Config,
) -> Result<Vec<Value>> {
    let url = list_url(&cfg.vault_url, period)?;
    let (status, response) = client.get(&url).await?;
    if !status.is_success() {
        anyhow::bail!(
            "listing the disclosure failed: {}",
            describe_error(status, &response)
        );
    }
    let parsed: Value = serde_json::from_str(&response).unwrap_or_default();
    Ok(parsed.as_array().cloned().unwrap_or_default())
}

/// Build the list URL with the reporting period as an encoded query parameter.
///
/// The period used to be interpolated straight into the query string, where an
/// `&` in the value stopped being data and became syntax: `2026&unitCount=1`
/// arrived as two parameters rather than one wrong one. A `#` was worse — the
/// remainder became a URL fragment and never left this process, so the node saw
/// a request for every year and answered it, and the operator read a full
/// disclosure as though it were the filtered one they asked for.
///
/// The value comes from `--period` rather than from a network peer, so this is
/// a correctness fault and not an injection route. It is still worth fixing on
/// those terms: the symptom is a report that silently answered a different
/// question, which is the failure mode an Art. 24 figure can least afford.
///
/// Deliberately no four-digit check here. The node validates the period and
/// answers `422` naming it, and a client-side copy of a node rule is the second
/// gate this module's header refuses — it can only ever disagree with the first.
fn list_url(base: &str, period: Option<&str>) -> Result<String> {
    let mut url = reqwest::Url::parse(&format!("{base}/api/v1/unsold-goods"))
        .with_context(|| format!("the configured vault URL is not a usable URL: {base}"))?;
    if let Some(p) = period {
        url.query_pairs_mut().append_pair("reportingPeriod", p);
    }
    Ok(url.to_string())
}

#[cfg(test)]
mod list_url_query {
    use super::list_url;

    const BASE: &str = "http://localhost:8001/vault";

    /// Assert the URL carries exactly one query parameter and return its value.
    ///
    /// The count is the assertion that matters: the fault being guarded against
    /// turned one parameter into two, so a helper that only read the value back
    /// would pass on the very input that motivated the fix.
    fn sole_period(url: &str) -> String {
        let parsed = reqwest::Url::parse(url).expect("the builder returns a valid URL");
        let pairs: Vec<_> = parsed.query_pairs().collect();
        assert_eq!(pairs.len(), 1, "expected exactly one parameter in {url}");
        assert_eq!(pairs[0].0.as_ref(), "reportingPeriod");
        pairs[0].1.to_string()
    }

    #[test]
    fn no_period_asks_for_every_year() {
        let url = list_url(BASE, None).expect("a valid base");
        assert_eq!(url, "http://localhost:8001/vault/api/v1/unsold-goods");
    }

    #[test]
    fn a_financial_year_becomes_one_query_parameter() {
        let url = list_url(BASE, Some("2026")).expect("a valid base");
        assert_eq!(sole_period(&url), "2026");
    }

    /// The fault this function exists for: an `&` in the value must stay part
    /// of the value instead of starting a second parameter.
    #[test]
    fn a_period_carrying_a_query_delimiter_stays_a_single_parameter() {
        let url = list_url(BASE, Some("2026&unitCount=1")).expect("a valid base");
        assert_eq!(sole_period(&url), "2026&unitCount=1");
    }

    /// A `#` truncated the request inside the client — everything after it was
    /// a fragment and was never sent, so the node answered a wider question.
    #[test]
    fn a_period_carrying_a_fragment_marker_is_still_sent_whole() {
        let url = list_url(BASE, Some("2026#2025")).expect("a valid base");
        let parsed = reqwest::Url::parse(&url).expect("valid");
        assert_eq!(parsed.fragment(), None, "nothing may become a fragment");
        assert_eq!(sole_period(&url), "2026#2025");
    }

    /// Validation belongs to the node. A period that is not a year is sent so
    /// the node can refuse it with the message that names the rule, rather than
    /// being rejected here by a second copy of that rule.
    #[test]
    fn a_period_that_is_not_a_year_is_sent_for_the_node_to_refuse() {
        let url = list_url(BASE, Some("not-a-year")).expect("a valid base");
        assert_eq!(sole_period(&url), "not-a-year");
    }

    /// A base with no scheme at all is a relative URL, which cannot be
    /// resolved without one — failing here names the configured value instead
    /// of surfacing later as an opaque client error.
    #[test]
    fn a_base_with_no_scheme_is_an_error() {
        assert!(list_url("not a url", None).is_err());
    }

    /// But this is not a config validator, and reading it as one would be a
    /// mistake: `localhost:8001` parses, with `localhost` taken as the scheme
    /// and `8001` as the path. It is a misconfiguration that this function
    /// cannot catch and the request will, so the check that belongs here is
    /// only the one above.
    #[test]
    fn a_schemeless_host_and_port_still_parses_and_is_not_caught_here() {
        assert!(list_url("localhost:8001", None).is_ok());
    }
}

#[cfg(test)]
mod recorded_line {
    use super::recorded_id;

    #[test]
    fn the_id_is_read_from_the_body() {
        let body = r#"{"id":"01a08610-bce5-79e2-b85f-bdbe158446b2","reportingPeriod":"2026"}"#;
        assert_eq!(
            recorded_id(body).expect("an id is present"),
            "01a08610-bce5-79e2-b85f-bdbe158446b2"
        );
    }

    /// The case the `(not reported)` placeholder absorbed: a success that
    /// cannot name what it wrote. On a route with no `DELETE`, reporting it as
    /// a clean success is how a duplicate gets recorded next.
    #[test]
    fn a_body_without_an_id_is_an_error() {
        assert!(recorded_id(r#"{"reportingPeriod":"2026"}"#).is_err());
    }

    #[test]
    fn an_unparseable_body_is_an_error() {
        assert!(recorded_id("<html>502 Bad Gateway</html>").is_err());
    }

    #[test]
    fn a_non_string_or_blank_id_is_an_error() {
        assert!(recorded_id(r#"{"id":42}"#).is_err());
        assert!(recorded_id(r#"{"id":"  "}"#).is_err());
    }

    /// The message has to say the line was written and that there is no delete,
    /// or the operator's next move is to record it a second time — which is
    /// exactly the overstated Art. 24 figure this route cannot take back.
    #[test]
    fn the_error_says_the_line_was_written_and_cannot_be_deleted() {
        let err = recorded_id(r#"{}"#).unwrap_err().to_string();
        assert!(err.contains("HAS been written"), "message was: {err}");
        assert!(err.contains("no delete"), "message was: {err}");
    }
}
