//! The validator every vault test response passes through, tested on its own.
//!
//! The rest of the suites only show that it accepts what the vault serves. These
//! show that it refuses what it should: they need no database, and run once here
//! rather than in each of the suites that link the helper.

#![cfg(feature = "integration-tests")]

mod helpers;

use helpers::response_contract::{Contract, bundle, mounted_path};
use serde_json::{Value, json};

const PUBLIC_READ: &str = "/vault/public/dpp/{dppId}";
const ID: &str = "019723f4-1a2b-7c3d-8e4f-5a6b7c8d9e0f";

fn contract() -> Contract {
    Contract::from_bundle(bundle())
}

/// A public view as core redacts it: every field a redacted read always carries,
/// and no `retentionLocked`, which the policy withholds from the public.
fn public_view() -> Value {
    json!({
        "id": ID,
        "productName": "EcoCell Pro 48V",
        "productGroup": "battery",
        "manufacturer": { "name": "Acme", "address": "Berlin, DE" },
        "materials": [],
        "status": "active",
        "schemaVersion": "1.0.0",
        "createdAt": "2026-01-01T00:00:00Z",
        "updatedAt": "2026-01-01T00:00:00Z",
        "version": 1
    })
}

fn problem(status: u16) -> Value {
    json!({ "type": "about:blank", "title": "Problem", "status": status })
}

fn check_json(
    contract: &Contract,
    method: &str,
    target: &str,
    status: u16,
    content_type: &str,
    body: &Value,
) -> Result<(), String> {
    contract.check(
        method,
        target,
        status,
        Some(content_type),
        body.to_string().as_bytes(),
    )
}

#[test]
fn the_vault_is_documented_under_its_mount_point() {
    assert_eq!(mounted_path("/api/v1/dpp"), "/vault/api/v1/dpp");
    assert_eq!(mounted_path("/health"), "/vault/health");
    assert_eq!(
        mounted_path("http://127.0.0.1:41234/public/dpp/abc?batch=LOT-1#top"),
        "/vault/public/dpp/abc",
        "a full URL loses its scheme and host, and a query or fragment is not part of the path"
    );
    assert_eq!(mounted_path("http://127.0.0.1:41234"), "/vault/");
}

#[test]
fn a_parameter_segment_matches_exactly_one_segment() {
    let contract = contract();
    let documented = |target: &str| contract.documented_as("GET", target);

    assert_eq!(
        documented(&format!("/public/dpp/{ID}")).as_deref(),
        Some(PUBLIC_READ)
    );
    assert_eq!(
        documented(&format!("/api/v1/dpp/{ID}/history")).as_deref(),
        Some("/vault/api/v1/dpp/{dppId}/history"),
        "a parameter in the middle of a path matches one segment"
    );
    assert_eq!(
        documented(&format!("/public/dpp/{ID}/extra")),
        None,
        "a parameter never matches across a slash"
    );
    assert_eq!(
        documented("/public/dpp/"),
        None,
        "an empty segment is not a value for a parameter"
    );
}

#[test]
fn a_literal_segment_wins_over_a_parameter_that_also_matches() {
    let contract = contract();

    // `by-identity` is a literal segment of its own route and also a value the
    // `{dppId}` route would accept.
    assert_eq!(
        contract
            .documented_as("GET", "/api/v1/dpp/by-identity")
            .as_deref(),
        Some("/vault/api/v1/dpp/by-identity")
    );
    assert_eq!(
        contract
            .documented_as("GET", "/api/v1/dpp/by-identity?productGroup=battery")
            .as_deref(),
        Some("/vault/api/v1/dpp/by-identity"),
        "the query is not part of the match"
    );
    // The same text one segment longer is no longer that literal route.
    assert_eq!(
        contract
            .documented_as("GET", "/public/dpp/by-gtin/09506000134352")
            .as_deref(),
        Some("/vault/public/dpp/by-gtin/{gtin}")
    );
    // A request segment that is written like a template is still a value.
    assert_eq!(
        contract
            .documented_as("GET", "/public/dpp/{dppId}")
            .as_deref(),
        Some(PUBLIC_READ)
    );
    // The method is part of the match.
    assert_eq!(contract.documented_as("PATCH", "/public/dpp/abc"), None);
}

#[test]
fn a_served_public_view_validates_and_a_stripped_field_is_what_it_may_omit() {
    check_json(
        &contract(),
        "GET",
        &format!("/public/dpp/{ID}"),
        200,
        "application/json",
        &public_view(),
    )
    .expect("a redacted view that omits retentionLocked is documented");
}

/// The defect this check exists for: the public door documented with the schema
/// of the full read, which requires `retentionLocked`, a field core's redaction
/// withholds from the public.
#[test]
fn the_public_door_documented_with_the_full_schema_fails_for_the_field_it_strips() {
    let mut reverted = bundle();
    reverted["paths"][PUBLIC_READ]["get"]["responses"]["200"]["content"]["application/json"]["schema"] =
        json!({ "$ref": "#/components/schemas/PassportResponse" });

    let failure = check_json(
        &Contract::from_bundle(reverted),
        "GET",
        &format!("/public/dpp/{ID}"),
        200,
        "application/json",
        &public_view(),
    )
    .expect_err("a view without retentionLocked cannot satisfy PassportResponse");

    assert!(failure.contains("retentionLocked"), "{failure}");
    assert!(
        failure.contains(&format!("GET /vault/public/dpp/{ID} answered 200")),
        "the failure names the request: {failure}"
    );
}

#[test]
fn a_status_the_description_does_not_document_fails_and_names_the_request() {
    let body = problem(404);
    check_json(
        &contract(),
        "GET",
        &format!("/public/dpp/{ID}"),
        404,
        "application/problem+json",
        &body,
    )
    .expect("the read documents a 404");

    let mut trimmed = bundle();
    trimmed["paths"][PUBLIC_READ]["get"]["responses"]
        .as_object_mut()
        .expect("responses")
        .remove("404");
    let failure = check_json(
        &Contract::from_bundle(trimmed),
        "GET",
        &format!("/public/dpp/{ID}"),
        404,
        "application/problem+json",
        &body,
    )
    .expect_err("a 404 nothing documents");

    for named in [
        "GET",
        &format!("/vault/public/dpp/{ID}"),
        "404",
        "\"title\":\"Problem\"",
    ] {
        assert!(
            failure.contains(named),
            "{named} is missing from: {failure}"
        );
    }
}

#[test]
fn a_failure_quotes_no_more_than_the_start_of_the_body() {
    let long = "x".repeat(2_000);
    let failure = contract()
        .check(
            "GET",
            "/no/such/route",
            200,
            Some("text/plain"),
            long.as_bytes(),
        )
        .expect_err("no operation answers that path");

    assert!(failure.contains(&"x".repeat(300)), "{failure}");
    assert!(
        !failure.contains(&"x".repeat(301)),
        "the quote is cut at 300"
    );
    assert!(
        failure.contains("documents no operation"),
        "an unknown path says so: {failure}"
    );
}

#[test]
fn a_body_in_a_content_type_the_response_does_not_document_fails() {
    let failure = contract()
        .check(
            "GET",
            &format!("/public/dpp/{ID}"),
            200,
            Some("text/plain"),
            b"hello",
        )
        .expect_err("the public read documents JSON only");

    assert!(failure.contains("text/plain"), "{failure}");
}

#[test]
fn a_problem_document_is_validated_against_the_problem_schema() {
    let failure = check_json(
        &contract(),
        "GET",
        &format!("/public/dpp/{ID}"),
        404,
        "application/problem+json",
        &json!({ "title": "no type, no status" }),
    )
    .expect_err("a problem without its required members");

    assert!(failure.contains("is a required property"), "{failure}");
}
