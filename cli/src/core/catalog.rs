//! The regulatory catalog: which product groups need a passport, from when,
//! under which acts — plus the schemas and CSV templates for onboarding them.
//!
//! These routes are unauthenticated on the node, which is deliberate: "does my
//! product need a passport" is a question someone asks *before* they have a
//! node, let alone a key. The client reads them without a credential so the
//! answer is available on a fresh install.

use anyhow::Result;
use serde_json::Value;

use super::types::{InstrumentSummary, ProductGroupObligation, SchemaRow};
use crate::{
    config::Config,
    http::{OdalClient, describe_error},
};

/// Every product group an act reaches, whether or not it carries a schema.
pub async fn action_product_group_list(
    client: &OdalClient,
    cfg: &Config,
) -> Result<Vec<ProductGroupObligation>> {
    let url = format!("{}/api/v1/product-groups", cfg.integrator_url());
    let (status, body) = client.get_public(&url).await?;
    if !status.is_success() {
        anyhow::bail!(
            "failed to list product groups: {}",
            describe_error(status, &body)
        );
    }
    let v: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
    // The list route wraps its rows; the single-group route does not.
    let rows = v
        .get("productGroups")
        .and_then(Value::as_array)
        .or_else(|| v.as_array())
        .cloned()
        .unwrap_or_default();
    Ok(rows.iter().map(read_obligation).collect())
}

pub async fn action_product_group_show(
    product_group: &str,
    client: &OdalClient,
    cfg: &Config,
) -> Result<ProductGroupObligation> {
    let url = format!(
        "{}/api/v1/product-groups/{product_group}",
        cfg.integrator_url()
    );
    let (status, body) = client.get_public(&url).await?;
    if !status.is_success() {
        anyhow::bail!("{}", describe_error(status, &body));
    }
    let v: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
    Ok(read_obligation(&v))
}

/// `null` and absent mean different things here and both are preserved: a
/// `null` title says an act reaches this key while no descriptor names it, and
/// a missing date is not a date of `None` presented as fact — every date the
/// endpoint serves comes with the basis that qualifies it.
fn read_obligation(v: &Value) -> ProductGroupObligation {
    let passport = v.get("passport");
    let from = passport.and_then(|p| p.get("from"));

    ProductGroupObligation {
        product_group: v
            .get("productGroup")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        title: v.get("title").and_then(Value::as_str).map(str::to_owned),
        required: passport
            .and_then(|p| p.get("required"))
            .and_then(Value::as_bool)
            .unwrap_or_default(),
        from: from
            .and_then(|d| d.get("date"))
            .and_then(Value::as_str)
            .map(str::to_owned),
        from_basis: from
            .and_then(|d| d.get("basis"))
            .and_then(Value::as_str)
            .map(str::to_owned),
        determinable: v
            .get("determinable")
            .and_then(Value::as_bool)
            .unwrap_or_default(),
        granularity: v
            .get("granularity")
            .and_then(Value::as_str)
            .map(str::to_owned),
        retention_years: v
            .get("retention")
            .and_then(|r| r.get("years"))
            .and_then(Value::as_i64),
        retention_basis: v
            .get("retention")
            .and_then(|r| r.get("basis"))
            .and_then(Value::as_str)
            .map(str::to_owned),
        instruments: v
            .get("instruments")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .map(|i| InstrumentSummary {
                        instrument: i
                            .get("instrument")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_owned(),
                        instrument_status: i
                            .get("instrumentStatus")
                            .and_then(Value::as_str)
                            .map(str::to_owned),
                        binding_status: i
                            .get("bindingStatus")
                            .and_then(Value::as_str)
                            .map(str::to_owned),
                    })
                    .collect()
            })
            .unwrap_or_default(),
    }
}

/// Product group keys that have a schema, the version this node serves, and
/// every version it can still read.
///
/// The full list matters, not just `current`: a passport written against an
/// older version is upcast through a lens chain rather than refused, so the
/// versions behind `current` are the ones that chain covers.
pub async fn action_schema_list(client: &OdalClient, cfg: &Config) -> Result<Vec<SchemaRow>> {
    let url = format!("{}/api/v1/schemas", cfg.integrator_url());
    let (status, body) = client.get_public(&url).await?;
    if !status.is_success() {
        anyhow::bail!("failed to list schemas: {}", describe_error(status, &body));
    }
    let v: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
    let rows = v
        .get("schemas")
        .and_then(Value::as_array)
        .or_else(|| v.as_array())
        .cloned()
        .unwrap_or_default();

    Ok(rows
        .iter()
        .map(|r| {
            let s = |k: &str| {
                r.get(k)
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned()
            };
            SchemaRow {
                product_group: s("productGroup"),
                current: s("current"),
                versions: r
                    .get("versions")
                    .and_then(Value::as_array)
                    .map(|a| {
                        a.iter()
                            .filter_map(Value::as_str)
                            .map(str::to_owned)
                            .collect()
                    })
                    .unwrap_or_default(),
            }
        })
        .collect())
}

/// The raw JSON Schema document, returned verbatim so it can be piped into a
/// validator without this client reshaping it.
pub async fn action_schema_show(
    product_group: &str,
    version: Option<&str>,
    client: &OdalClient,
    cfg: &Config,
) -> Result<String> {
    let url = match version {
        Some(v) => format!(
            "{}/api/v1/schemas/{product_group}/{v}",
            cfg.integrator_url()
        ),
        None => format!("{}/api/v1/schemas/{product_group}", cfg.integrator_url()),
    };
    let (status, body) = client.get_public(&url).await?;
    if !status.is_success() {
        anyhow::bail!("{}", describe_error(status, &body));
    }
    Ok(body)
}

/// The CSV header row `odal passport import` expects for this product group.
///
/// Only the product groups with a row validator have one — the node answers
/// `404` for the rest, and that refusal is the honest answer: there is no
/// column set to publish for a group whose rows nothing can check.
pub async fn action_template(
    product_group: &str,
    client: &OdalClient,
    cfg: &Config,
) -> Result<String> {
    let url = format!("{}/api/v1/templates/{product_group}", cfg.integrator_url());
    let (status, body) = client.get_public(&url).await?;
    if !status.is_success() {
        anyhow::bail!("{}", describe_error(status, &body));
    }
    Ok(body)
}
