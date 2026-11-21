//! The fields a redacted passport read always carries, derived from core's
//! disclosure policy and checked against the committed list.
//!
//! # What this is for
//!
//! `PassportResponse` lists `retentionLocked` as required, because every
//! authenticated read carries it. Core's redaction withholds it from the public,
//! so a public read that is served exactly as documented failed its own schema.
//! A redacted read is therefore documented with its own schema,
//! `RedactedPassportResponse`, whose `required` list is the one thing this file
//! generates: `api/components/schemas/passport/RedactedPassportRequired.yaml`.
//!
//! # Why generated, and why only that list
//!
//! Which fields survive a redaction is core's decision and changes with a
//! delegated act, a new product group or a new schema version. A list written by
//! hand would be a second copy of that decision, and nothing would notice the
//! day the two disagreed. The properties and descriptions stay hand-written:
//! only the list is a function of the policy.
//!
//! The derived list is the members of `PassportResponse`'s `required` that
//! survive `dpp_domain::access::redact_passport` for every product group in
//! core's catalog, every schema version core embeds for it, and every audience a
//! redacted door can serve. A field dropped for any one combination is dropped
//! from the list, because a schema that requires it would reject that read.
//!
//! The audiences are `Public` (the public doors, and the credential door without
//! a credential), `LegitimateInterest` (the roles this node issues) and
//! `Authority` (a credential from an issuer a member state vouches for, which
//! the credential door serves like any other verified one).
//!
//! # Why this lives in `dpp-node`'s tests
//!
//! It needs the bundle (which `openapi_contract` reads from here too) and core's
//! redaction and catalogs, and `dpp-node` already holds both. `dpp-vault`'s tests
//! only need the finished bundle, which they validate responses against.
//!
//! The committed file is the artifact: `the_committed_list_is_what_the_policy_derives`
//! recomputes it and fails, naming the recipe, when it differs.
//! `just regenerate-redacted-required` rewrites it. The full list is read from
//! the bundle, so the recipe bundles before it derives the list and again after,
//! to carry the new list into the bundle.

use std::collections::BTreeSet;
use std::path::Path;

use dpp_domain::access::{ProductGroupAccessPolicy, redact_passport};
use dpp_domain::passport::{Passport, PassportId};
use dpp_domain::product_group::ProductGroup;
use dpp_domain::schemas::VersionedSchemaRegistry;
use dpp_domain::status::PassportStatus;
use dpp_domain::{Audience, ManufacturerInfo, ProductGroupCatalog};
use serde_json::Value;

/// The committed bundle, for the full list and for what the bundle says the
/// redacted schema requires.
const SPEC_JSON: &str = include_str!("../../../api/openapi.bundled.json");

/// The generated file, embedded so a moved or deleted one is a build failure.
const COMMITTED: &str =
    include_str!("../../../api/components/schemas/passport/RedactedPassportRequired.yaml");

const RECIPE: &str = "just regenerate-redacted-required";

/// Every audience a redacted door can serve. `Audience` is non-exhaustive, so a
/// variant core adds is a decision to make here, not one to inherit by default.
const SERVED_AUDIENCES: [Audience; 3] = [
    Audience::Public,
    Audience::LegitimateInterest,
    Audience::Authority,
];

fn spec() -> Value {
    serde_json::from_str(SPEC_JSON).expect("api/openapi.bundled.json is not valid JSON")
}

/// The `required` list a composed schema declares, in the order it writes it.
fn required_of(schema: &Value) -> Vec<String> {
    schema["allOf"]
        .as_array()
        .into_iter()
        .flatten()
        .chain(std::iter::once(schema))
        .find_map(|branch| branch.get("required").and_then(Value::as_array))
        .unwrap_or_else(|| panic!("no `required` list in {schema}"))
        .iter()
        .map(|name| name.as_str().expect("a required name").to_owned())
        .collect()
}

/// A passport that serialises every field `PassportResponse` requires, in the
/// given group at the given schema version.
fn passport(product_group_key: &str, schema_version: &str) -> Passport {
    Passport {
        id: PassportId::new(),
        batch_id: None,
        serial_number: None,
        product_name: "Probe".into(),
        product_group: ProductGroup::from_wire_tag(product_group_key),
        applicable_instruments: Vec::new(),
        granularity: None,
        manufacturer: ManufacturerInfo {
            name: "Acme".into(),
            address: "Berlin, DE".into(),
            registered_trade_name: None,
            electronic_address: None,
            country: None,
            did_web_url: None,
        },
        materials: Vec::new(),
        co2e_per_unit: None,
        repairability_score: None,
        compliance_result: None,
        lint_result: None,
        product_group_data: None,
        personal_data: Default::default(),
        status: PassportStatus::Published,
        qr_code_url: None,
        jws_signature: None,
        public_jws_signature: None,
        disclosure_signatures: Default::default(),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        published_at: None,
        placed_on_market_date: None,
        schema_version: schema_version.into(),
        retention_locked: true,
        version: 1,
        supersedes_id: None,
        derived_from: Vec::new(),
        component_refs: Vec::new(),
        life_status: None,
        retention_until: None,
        product_id: None,
        commodity_code: None,
        operator_identifier: None,
        responsible_operator: None,
        facility: None,
        seal: None,
        carrier_serial: None,
    }
}

/// The members of `PassportResponse`'s `required` that every redacted view keeps.
fn derived_required() -> Vec<String> {
    let full = required_of(&spec()["components"]["schemas"]["PassportResponse"]);
    let catalog = ProductGroupCatalog::new();
    let registry = VersionedSchemaRegistry::new();

    let mut kept: BTreeSet<String> = full.iter().cloned().collect();
    let mut views = 0_usize;
    for key in catalog.keys() {
        let versions = registry.versions_for(key);
        assert!(
            !versions.is_empty(),
            "the catalog lists `{key}` and the schema registry embeds no version of it, so there \
             is no redaction to derive from"
        );
        for version in versions {
            let version = version.to_string();
            // Without a policy `redact_passport` falls back to the envelope
            // defaults, which is a different redaction from the one a served
            // passport gets. Fail rather than derive from the fallback.
            assert!(
                ProductGroupAccessPolicy::for_passport(key, &version).is_some(),
                "core resolves no access policy for `{key}` at {version}"
            );
            let probe = passport(key, &version);
            for audience in SERVED_AUDIENCES {
                let view = redact_passport(&probe, audience).into_value();
                let served = view
                    .as_object()
                    .unwrap_or_else(|| panic!("the {audience:?} view of `{key}` is not an object"));
                kept.retain(|field| served.contains_key(field));
                views += 1;
            }
        }
    }
    assert!(views > 0, "no redaction was evaluated");

    full.into_iter()
        .filter(|field| kept.contains(field))
        .collect()
}

/// The generated file's exact text for `required`.
fn render(required: &[String]) -> String {
    let mut out = format!(
        "# GENERATED by `{RECIPE}`. Do not edit by hand.\n\
         #\n\
         # The members of `PassportResponse`'s `required` that survive core's\n\
         # redaction for every product group, schema version and audience a redacted\n\
         # read serves. `RedactedPassportResponse` composes this with the shared\n\
         # properties.\n\
         required:\n"
    );
    for field in required {
        out.push_str("  - ");
        out.push_str(field);
        out.push('\n');
    }
    out
}

/// Rewrites `RedactedPassportRequired.yaml` from core's policy.
#[test]
#[ignore = "writes into the source tree; run via `just regenerate-redacted-required`"]
fn regenerate_redacted_required() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../api/components/schemas/passport/RedactedPassportRequired.yaml");
    let required = derived_required();
    std::fs::write(&path, render(&required)).expect("write RedactedPassportRequired.yaml");
    println!("regenerated {}: {}", path.display(), required.join(", "));
}

#[test]
fn the_committed_list_is_what_the_policy_derives() {
    let derived = render(&derived_required());
    assert_eq!(
        COMMITTED, derived,
        "api/components/schemas/passport/RedactedPassportRequired.yaml no longer matches what \
         core's disclosure policy derives. Run `{RECIPE}` (it bundles the description before \
         and after) and commit what it changes."
    );
}

#[test]
fn the_bundle_carries_the_committed_list() {
    let bundle = spec();
    let in_bundle = required_of(&bundle["components"]["schemas"]["RedactedPassportRequired"]);
    assert_eq!(
        in_bundle,
        derived_required(),
        "api/openapi.bundled.json does not carry the derived list. Run `just openapi-bundle` and \
         commit the result."
    );
}

#[test]
fn the_redacted_schema_requires_nothing_the_full_one_does_not() {
    let bundle = spec();
    let full = required_of(&bundle["components"]["schemas"]["PassportResponse"]);
    for field in derived_required() {
        assert!(
            full.contains(&field),
            "`{field}` is derived as required of a redacted read but `PassportResponse` does not \
             require it"
        );
    }
}
