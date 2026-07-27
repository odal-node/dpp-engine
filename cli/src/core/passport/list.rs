//! List / browse: paginated, filtered passport listing and single-doc fetch.

use anyhow::{Context, Result};

use super::super::types::{ListParams, PassportPage, PassportSummary};
use crate::{
    config::Config,
    http::{OdalClient, describe_error},
};

/// Fetch one page of passports, optionally filtered by status and free-text `q`.
/// Mirrors the vault's `GET /api/v1/dpps` (status + q + pagination + total).
pub async fn action_list(
    params: &ListParams,
    client: &OdalClient,
    cfg: &Config,
) -> Result<PassportPage> {
    let mut url = format!(
        "{}/api/v1/dpps?limit={}&skip={}",
        cfg.vault_url, params.limit, params.skip
    );
    if let Some(s) = params.status.as_deref().filter(|s| !s.is_empty()) {
        url.push_str(&format!("&status={s}"));
    }
    if let Some(q) = params.q.as_deref().filter(|s| !s.is_empty()) {
        url.push_str(&format!("&q={}", pct_encode(q)));
    }
    if let Some(f) = params.facility_id.as_deref().filter(|s| !s.is_empty()) {
        url.push_str(&format!("&facilityId={}", pct_encode(f)));
    }

    let (http_status, body) = client.get(&url).await?;
    if !http_status.is_success() {
        anyhow::bail!(
            "List request failed: {}",
            describe_error(http_status, &body)
        );
    }
    let envelope: serde_json::Value =
        serde_json::from_str(&body).context("Failed to parse vault response as JSON")?;
    let total = envelope.get("total").and_then(|v| v.as_u64()).unwrap_or(0);
    let rows: Vec<PassportSummary> = envelope
        .get("dpps")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().map(summary_from_doc).collect())
        .unwrap_or_default();

    // `total` is exact only without a text search (the vault's count ignores q).
    // So derive "more pages?" from total when we can, else from a full page.
    let searching = params.q.as_deref().is_some_and(|s| !s.is_empty());
    let shown = params.skip as u64 + rows.len() as u64;
    let has_more = if searching {
        rows.len() as u32 == params.limit
    } else {
        shown < total
    };

    Ok(PassportPage {
        rows,
        total,
        skip: params.skip,
        limit: params.limit,
        has_more,
    })
}

/// Fetch the full passport document by id (for the details view).
pub async fn action_get(id: &str, client: &OdalClient, cfg: &Config) -> Result<serde_json::Value> {
    let url = format!("{}/api/v1/dpp/{id}", cfg.vault_url);
    let (http_status, body) = client.get(&url).await?;
    if !http_status.is_success() {
        anyhow::bail!(
            "Read request failed: {}",
            describe_error(http_status, &body)
        );
    }
    serde_json::from_str(&body).context("Failed to parse passport JSON")
}

/// Map a passport doc to a list-row summary. Field names match the vault's
/// camelCase JSON; missing fields degrade gracefully.
fn summary_from_doc(doc: &serde_json::Value) -> PassportSummary {
    let s = |k: &str| doc.get(k).and_then(|v| v.as_str()).unwrap_or("").to_owned();
    let product_name = {
        let n = s("productName");
        if n.is_empty() {
            "(unnamed)".to_owned()
        } else {
            n
        }
    };
    let batch = {
        let b = s("batchId");
        if b.is_empty() { None } else { Some(b) }
    };
    // "2026-06-20T14:41:01Z" → "2026-06-20 14:41"
    let updated = {
        let u = s("updatedAt");
        u.get(..16).unwrap_or(&u).replace('T', " ")
    };
    PassportSummary {
        id: s("id"),
        product_name,
        sector: s("sector"),
        status: s("status"),
        batch,
        updated,
    }
}

/// Percent-encode a query value (RFC 3986 unreserved set passes through).
fn pct_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn summary_from_doc_maps_fields() {
        let doc = json!({
            "id": "019ee576-ca26-7532-8d21-730f17e65ce8",
            "productName": "Amor Linen Blouse",
            "sector": "textile",
            "status": "active",
            "batchId": "BATCH-SS26-004",
            "updatedAt": "2026-06-20T14:41:01.688Z"
        });
        let s = summary_from_doc(&doc);
        assert_eq!(s.id, "019ee576-ca26-7532-8d21-730f17e65ce8");
        assert_eq!(s.product_name, "Amor Linen Blouse");
        assert_eq!(s.sector, "textile");
        assert_eq!(s.status, "active");
        assert_eq!(s.batch.as_deref(), Some("BATCH-SS26-004"));
        assert_eq!(s.updated, "2026-06-20 14:41");
    }

    #[test]
    fn summary_from_doc_degrades_gracefully() {
        let s = summary_from_doc(&json!({ "id": "x", "status": "draft" }));
        assert_eq!(s.product_name, "(unnamed)");
        assert!(s.batch.is_none());
        assert_eq!(s.sector, "");
    }

    #[test]
    fn pct_encode_escapes_reserved() {
        assert_eq!(pct_encode("linen blouse"), "linen%20blouse");
        assert_eq!(pct_encode("a&b=c"), "a%26b%3Dc");
        assert_eq!(pct_encode("plain-Name_1.0~"), "plain-Name_1.0~");
    }
}
