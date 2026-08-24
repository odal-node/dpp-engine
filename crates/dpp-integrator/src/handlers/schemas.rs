//! `GET /api/v1/schemas[/{product group}[/{version}]]` — serve the product group JSON Schemas
//! an SDK needs to build a passport body before it posts one.
//!
//! # Why this exists
//!
//! The only feedback available before this was a rejection from the create
//! route, or the CSV import template — which is an import artefact, not a
//! schema. The schemas already exist and the publish path already validates
//! against them; nothing served them.
//!
//! These are resolved through the same `VersionedSchemaRegistry` the publish
//! gate uses, never from a copy. A second copy would drift, and the direction it
//! drifts is the one where a body passes validation here and fails at publish.
//!
//! # Every `description` is stripped, deliberately and temporarily
//!
//! The schemas carry `description` fields that make regulatory assertions — act
//! numbers, adoption dates, effective dates, product-class scope, annex
//! references — and **none has been verified against primary text**. Two
//! electronics descriptions once asserted an adoption date, an effective date,
//! three named priority product classes and a phase-two date for an act that
//! does not exist.
//!
//! Inside a library those are developer-facing comments. On a public endpoint
//! they become a product surface that consumers read, cache and rely on, from a
//! compliance vendor — a much larger blast radius for a fabricated claim. So the
//! machine-readable contract is served and the prose is not.
//!
//! **This is a holding position, not the intended end state.** Restore the
//! descriptions once the prose audit has verified them against primary OJ text;
//! `strip_descriptions` and its call site are the only things to remove. Until
//! then an SDK gets what it actually needs to pre-validate — types, enums,
//! `required`, patterns, bounds — and no unaudited regulatory claim leaves the
//! node.
//!
//! `title` is kept: they are short labels ("Odal Node — Battery ProductGroup Data
//! (v2.6.0)"), not assertions.

use axum::{
    Json,
    extract::Path,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use dpp_common::http_problem;
use dpp_domain::catalog::ProductGroupCatalog;
use dpp_domain::schemas::VersionedSchemaRegistry;
use serde_json::{Value, json};

/// `GET /api/v1/schemas`
///
/// Every product group with a schema, and the versions it serves. `current` is the
/// version a new passport is written against; `versions` is everything a stored
/// passport may legitimately record.
pub async fn list_schemas() -> Response {
    let registry = VersionedSchemaRegistry::new();
    let catalog = ProductGroupCatalog::new();

    let mut product_groups: Vec<&str> = registry.product_groups();
    product_groups.sort_unstable();

    let entries: Vec<Value> = product_groups
        .into_iter()
        .map(|product_group| {
            let mut versions: Vec<String> = registry
                .versions_for(product_group)
                .into_iter()
                .map(ToString::to_string)
                .collect();
            versions.sort();
            json!({
                "productGroup": product_group,
                "current": catalog.current_schema_version(product_group),
                "versions": versions,
            })
        })
        .collect();

    (StatusCode::OK, Json(json!({ "schemas": entries }))).into_response()
}

/// `GET /api/v1/schemas/{product group}`
///
/// The product group's current schema — the one a passport created today is validated
/// against.
pub async fn get_current_schema(Path(product_group): Path<String>) -> Response {
    let catalog = ProductGroupCatalog::new();
    let Some(version) = catalog.current_schema_version(&product_group) else {
        return unknown_product_group(&product_group);
    };
    serve(&product_group, version)
}

/// `GET /api/v1/schemas/{product group}/{version}`
///
/// A pinned version. A stored passport records the `schemaVersion` it was
/// written under, so an SDK holding one needs to keep fetching that exact
/// schema rather than whatever is current.
pub async fn get_pinned_schema(Path((product_group, version)): Path<(String, String)>) -> Response {
    serve(&product_group, version.trim_start_matches('v'))
}

/// Resolve one `(product group, version)` from the registry and serve it, prose removed.
fn serve(product_group: &str, version: &str) -> Response {
    let registry = VersionedSchemaRegistry::new();
    let Ok(parsed) = version.parse() else {
        return http_problem::bad_request(format!(
            "'{version}' is not a semver version. Use the form '1.2.0'."
        ))
        .into_response();
    };
    let Some(raw) = registry.get(product_group, &parsed) else {
        return unknown_version(product_group, version);
    };

    // An embedded schema parsed at boot in the registry, so this cannot fail in
    // practice; a 500 is still the honest answer if it ever does.
    let Ok(mut schema) = serde_json::from_str::<Value>(raw) else {
        return http_problem::internal_error(format!(
            "the schema for {product_group} v{version} could not be read"
        ))
        .into_response();
    };
    strip_descriptions(&mut schema);

    (StatusCode::OK, Json(schema)).into_response()
}

fn unknown_product_group(product_group: &str) -> Response {
    let catalog = ProductGroupCatalog::new();
    let mut known: Vec<&str> = catalog.keys();
    known.sort_unstable();
    http_problem::not_found(format!(
        "No schema for product_group '{product_group}'. Known product_groups: {}.",
        known.join(", ")
    ))
    .into_response()
}

fn unknown_version(product_group: &str, version: &str) -> Response {
    let registry = VersionedSchemaRegistry::new();
    let mut versions: Vec<String> = registry
        .versions_for(product_group)
        .into_iter()
        .map(ToString::to_string)
        .collect();
    versions.sort();
    if versions.is_empty() {
        return unknown_product_group(product_group);
    }
    http_problem::not_found(format!(
        "No schema for product_group '{product_group}' at version '{version}'. Available: {}.",
        versions.join(", ")
    ))
    .into_response()
}

/// Remove every `description` **keyword** from a JSON Schema, in place.
///
/// Schema-aware rather than a blanket key removal: under `properties`,
/// `$defs`/`definitions` and `patternProperties` the keys are author-chosen
/// *names*, so a property legitimately called `description` would be deleted by
/// a naive walk — taking a real field out of the contract an SDK validates
/// against. No schema declares one today; this costs nothing and stops that
/// being a latent trap for whoever adds the first.
fn strip_descriptions(node: &mut Value) {
    /// Keywords whose object values are keyed by author-chosen names, not by
    /// schema keywords — descend into the values, never treat the keys as
    /// keywords.
    const NAME_KEYED: [&str; 4] = ["properties", "$defs", "definitions", "patternProperties"];

    match node {
        Value::Object(map) => {
            map.remove("description");
            for (key, value) in map.iter_mut() {
                if NAME_KEYED.contains(&key.as_str()) {
                    if let Value::Object(named) = value {
                        for schema in named.values_mut() {
                            strip_descriptions(schema);
                        }
                    }
                } else {
                    strip_descriptions(value);
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                strip_descriptions(item);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptions_are_removed_at_every_depth() {
        let mut schema = json!({
            "description": "root prose",
            "properties": {
                "gtin": { "type": "string", "description": "nested prose" },
                "parts": {
                    "type": "array",
                    "items": { "type": "object", "description": "deep prose" }
                }
            },
            "$defs": {
                "Thing": { "description": "def prose", "type": "object" }
            },
            "allOf": [{ "description": "branch prose" }]
        });
        strip_descriptions(&mut schema);

        let rendered = serde_json::to_string(&schema).unwrap();
        assert!(
            !rendered.contains("prose"),
            "no description may survive: {rendered}"
        );
    }

    #[test]
    fn a_property_named_description_survives() {
        // The trap a blanket key removal would fall into: deleting a real field
        // from the contract an SDK validates against.
        let mut schema = json!({
            "description": "root prose",
            "properties": {
                "description": { "type": "string", "maxLength": 200 }
            }
        });
        strip_descriptions(&mut schema);

        assert_eq!(
            schema["properties"]["description"]["type"], "string",
            "a property *named* description is a field, not prose"
        );
        assert!(schema.get("description").is_none(), "root prose must go");
    }

    #[test]
    fn the_validation_contract_survives_stripping() {
        // The point of serving these at all: an SDK must still be able to
        // pre-validate. Everything that decides accept/reject has to remain.
        let registry = VersionedSchemaRegistry::new();
        let raw = registry
            .get("battery", &"2.6.0".parse().unwrap())
            .expect("battery 2.6.0 is embedded");
        let mut schema: Value = serde_json::from_str(raw).unwrap();
        strip_descriptions(&mut schema);

        assert!(schema.get("required").is_some(), "required must survive");
        assert!(
            schema.get("properties").is_some(),
            "properties must survive"
        );
        assert_eq!(schema["additionalProperties"], json!(false));
        assert!(
            schema["properties"]["gtin"]["pattern"].is_string(),
            "a pattern is part of the contract"
        );
        assert!(
            serde_json::to_string(&schema).unwrap().contains("\"enum\""),
            "enums are part of the contract"
        );
    }

    #[test]
    fn no_embedded_schema_keeps_a_description_after_stripping() {
        let registry = VersionedSchemaRegistry::new();
        for (product_group, version) in registry.list() {
            let raw = registry.get(product_group, version).expect("just listed");
            let mut schema: Value = serde_json::from_str(raw).unwrap();
            strip_descriptions(&mut schema);
            assert!(
                !serde_json::to_string(&schema)
                    .unwrap()
                    .contains("\"description\""),
                "{product_group} v{version} still carries a description keyword after stripping"
            );
        }
    }
}
