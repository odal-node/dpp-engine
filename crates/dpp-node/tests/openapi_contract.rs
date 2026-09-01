//! The OpenAPI description is checked against the code that implements it.
//!
//! `api/` is hand-authored. Before this test the only gate on it was
//! `just openapi-check`, which bundles the tree and runs Redocly's linter —
//! both of which read *only* the spec. Nothing opened a `.rs` file, so a field
//! added to a struct, a variant added to an enum, or a route added to a router
//! never made the spec fail. Drift was not a risk being managed; it was
//! guaranteed, and it accumulated (see `docs/` for the audit that found it).
//!
//! Five things are checked, and every one of them fails loudly rather than
//! skipping:
//!
//! 1. **Object schemas** — the property set of each schema equals the key set
//!    `serde` actually emits for a maximally-populated instance of the type
//!    behind it. A field the server sends and the spec omits is a defect; so is
//!    a property the spec promises and the server never sends. Both directions
//!    fail.
//! 2. **Enum schemas** — the `enum` list equals the wire strings the Rust enum
//!    serialises to. A status the server can return and the spec does not list
//!    breaks every generated client that models it as a closed enum.
//! 3. **Query parameters** — the documented parameter names for each operation
//!    equal the names the struct that deserialises them actually reads. Both
//!    directions fail: a documented parameter no handler reads is silently
//!    ignored, and one the handler reads and the spec omits is undiscoverable.
//! 4. **Reachability** — every published shape has a name the checks above can
//!    look up. A shape written inline — in a schema's properties, in a JSON
//!    response, or in a JSON request body — is not skipped, it is invisible, so
//!    each of those three is failed rather than tolerated.
//! 5. **Route coverage** — the paths in the spec equal the routes actually
//!    registered by every deployable `openapi.yaml` names in `servers`: the
//!    assembled node, the standalone resolver, and the standalone identity
//!    service's mTLS signing surface. No exception list — see
//!    `identity_standalone_surface` for why one would be the wrong shape.
//!
//! ## Why maximal instances built from exhaustive struct literals
//!
//! Ground truth here is what `serde` emits, not what a parser thinks the source
//! says: `#[serde(flatten)]`, `rename`, `skip_serializing_if` and custom
//! `Serialize` impls all mean the wire shape is not readable off the field list.
//! Serialising a real value is the only honest answer.
//!
//! The fixtures below deliberately use **exhaustive struct literals** — no
//! `..Default::default()` on any type whose schema is checked. That is what makes
//! this gate self-maintaining: adding a field to such a struct fails to compile
//! here until the fixture sets it, and once the fixture sets it the schema check
//! fails until the spec documents it. A fixture that could silently omit a new
//! field would leave exactly the hole this test exists to close.
//!
//! Every `Option` is `Some` and every collection is non-empty for the same
//! reason — under `skip_serializing_if` a default-ish instance simply does not
//! emit the field, and the test would pass by not looking.
//!
//! ## Why the JSON bundle
//!
//! This reads `api/openapi.bundled.json`, generated beside the YAML bundle by
//! `just openapi-bundle` and committed with it. `serde_json` is already a
//! dependency; the alternative was adding a YAML parser, and the only
//! established one (`serde_yaml`) is unmaintained — a supply-chain cost to this
//! workspace's `cargo audit` gate paid purely so a test could read a file the
//! build already knows how to emit in a format it can read.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, NaiveDate, TimeZone, Utc};
use serde_json::{Value, json};
use uuid::Uuid;

// ── Spec access ────────────────────────────────────────────────────────────

/// The committed bundle, embedded at compile time so a missing or moved spec is
/// a build failure rather than a test that silently reads nothing.
const SPEC_JSON: &str = include_str!("../../../api/openapi.bundled.json");

fn spec() -> Value {
    serde_json::from_str(SPEC_JSON).expect("api/openapi.bundled.json is not valid JSON")
}

fn schemas(spec: &Value) -> &serde_json::Map<String, Value> {
    spec["components"]["schemas"]
        .as_object()
        .expect("components.schemas is not an object")
}

/// Follow a local `$ref` (`#/components/schemas/Name`) to the schema it names.
///
/// Only local refs occur: the bundle is a single self-contained document by
/// construction, so an external ref would mean the bundling step changed and is
/// worth failing on rather than silently resolving to nothing.
fn resolve<'a>(spec: &'a Value, schema: &'a Value) -> &'a Value {
    match schema.get("$ref").and_then(Value::as_str) {
        None => schema,
        Some(pointer) => {
            let name = pointer
                .strip_prefix("#/components/schemas/")
                .unwrap_or_else(|| panic!("unexpected non-local $ref in the bundle: {pointer}"));
            schemas(spec)
                .get(name)
                .unwrap_or_else(|| panic!("$ref points at a schema that does not exist: {pointer}"))
        }
    }
}

/// Walk a schema and every branch it composes with, applying `visit` to each.
///
/// `allOf` is composition, not decoration: a schema written as
/// `allOf: [$ref Base, {properties: {extra}}]` declares `Base`'s properties plus
/// `extra`, and reading only the top-level `properties` of such a schema finds
/// nothing at all. Without this the gate would report every field of a composed
/// response as undocumented — a false failure that invites someone to "fix" it
/// by flattening a schema that was right.
fn walk_composed(spec: &Value, schema: &Value, visit: &mut impl FnMut(&Value)) {
    let schema = resolve(spec, schema);
    visit(schema);
    if let Some(branches) = schema.get("allOf").and_then(Value::as_array) {
        for branch in branches {
            walk_composed(spec, branch, visit);
        }
    }
}

/// Property names a schema declares, including through `allOf` composition.
fn spec_properties(spec: &Value, schema: &Value) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    walk_composed(spec, schema, &mut |s| {
        if let Some(props) = s.get("properties").and_then(Value::as_object) {
            out.extend(props.keys().cloned());
        }
    });
    out
}

/// Every property a schema declares, mapped to its own sub-schema, including
/// through `allOf` composition. Later branches do not override earlier ones —
/// a name declared twice in a composition is a spec bug, not a merge.
fn schema_property_map(spec: &Value, schema: &Value) -> BTreeMap<String, Value> {
    let mut out = BTreeMap::new();
    walk_composed(spec, schema, &mut |s| {
        if let Some(props) = s.get("properties").and_then(Value::as_object) {
            for (k, v) in props {
                out.entry(k.clone()).or_insert_with(|| v.clone());
            }
        }
    });
    out
}

/// Names a schema marks required, including through `allOf` composition.
fn spec_required(spec: &Value, schema: &Value) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    walk_composed(spec, schema, &mut |s| {
        if let Some(req) = s.get("required").and_then(Value::as_array) {
            out.extend(req.iter().filter_map(Value::as_str).map(str::to_owned));
        }
    });
    out
}

/// Top-level keys a serialised instance actually carries.
fn wire_keys(value: &Value) -> BTreeSet<String> {
    value
        .as_object()
        .expect("fixture did not serialise to a JSON object")
        .keys()
        .cloned()
        .collect()
}

fn joined(set: &BTreeSet<String>) -> String {
    set.iter().cloned().collect::<Vec<_>>().join(", ")
}

/// Query parameter names an operation declares, in spec order.
///
/// Path parameters are excluded: they are part of the path template, which
/// `every_route_is_documented_and_every_documented_path_exists` already checks,
/// and they never appear in the query struct.
fn spec_query_params(spec: &Value, method: &str, path: &str) -> Option<BTreeSet<String>> {
    let operation = spec["paths"].get(path)?.get(method)?;
    Some(
        operation
            .get("parameters")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter(|p| p.get("in").and_then(Value::as_str) == Some("query"))
            .filter_map(|p| p.get("name").and_then(Value::as_str))
            .map(str::to_owned)
            .collect(),
    )
}

/// Every `(method, path)` in the spec that declares at least one query
/// parameter.
fn operations_with_query_params(spec: &Value) -> BTreeSet<(String, String)> {
    let mut out = BTreeSet::new();
    for (path, item) in spec["paths"].as_object().expect("paths is not an object") {
        for (method, operation) in item.as_object().expect("path item is not an object") {
            let declares_query = operation
                .get("parameters")
                .and_then(Value::as_array)
                .is_some_and(|ps| {
                    ps.iter()
                        .any(|p| p.get("in").and_then(Value::as_str) == Some("query"))
                });
            if declares_query {
                out.insert((method.clone(), path.clone()));
            }
        }
    }
    out
}

// ── Timestamps ─────────────────────────────────────────────────────────────
//
// Fixed rather than `Utc::now()` so a failure message is stable and diffable.

fn ts() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 1, 2, 3, 4, 5).unwrap()
}

fn date() -> NaiveDate {
    NaiveDate::from_ymd_opt(2026, 1, 2).unwrap()
}

fn uuid() -> Uuid {
    Uuid::nil()
}

// ── Registry ───────────────────────────────────────────────────────────────

/// A schema whose shape is checked against a serialised instance.
struct ObjectCase {
    /// Schema name in `components/schemas`.
    name: &'static str,
    /// A maximally-populated instance, serialised.
    value: Value,
}

/// A documented operation's query parameters, checked against the struct that
/// deserialises them.
struct QueryCase {
    /// Lowercase HTTP method, as the spec spells it.
    method: &'static str,
    /// Path template, as the spec spells it.
    path: &'static str,
    /// A maximally-populated instance of the handler's query struct,
    /// serialised. Same ground truth as `ObjectCase`: what serde emits, not
    /// what the field list looks like.
    value: Value,
}

/// A schema whose `enum` list is checked against the wire strings the Rust type
/// serialises to.
struct EnumCase {
    name: &'static str,
    /// Every variant, serialised. Built by serialising the actual values, so a
    /// renamed variant fails here rather than being transcribed wrongly twice.
    variants: Vec<String>,
}

/// Schemas deliberately not shape-checked, each with the reason. Anything not in
/// this list and not in a case above fails `every_schema_is_covered` — there is
/// no silent skip.
const UNCHECKED: &[(&str, &str)] = &[
    (
        "DppId",
        "a bare `type: string, format: uuid`, not an object with properties",
    ),
    (
        "DidDocument",
        "a W3C DID document passed through as opaque JSON; the node does not \
         model it as a struct and must not, since it round-trips documents it \
         did not author",
    ),
    (
        "QualifiedSealMember",
        "the dossier holds this member as untyped JSON (`serde_json::Value`), so \
         no Rust type declares `seal`/`signedOverJws`/`payloadHash` and there is \
         nothing to compare the property list against. Naming the schema at \
         least makes that gap visible instead of hiding it inside \
         `EvidenceDossier`; giving the dossier a real type for the member is \
         the only thing that would actually close it",
    ),
    (
        "ProductGroupData",
        "deliberately open (`additionalProperties: true`, discriminated by \
         `productGroup`). The per-product-group payloads are described by the versioned JSON \
         Schemas served from `/integrator/api/v1/schemas/{productGroup}`, which is the \
         authoritative description; duplicating them into OpenAPI would create a \
         second copy to drift",
    ),
];

fn object_cases() -> Vec<ObjectCase> {
    let mut cases = Vec::new();

    macro_rules! case {
        ($name:literal, $value:expr) => {
            cases.push(ObjectCase {
                name: $name,
                value: serde_json::to_value(&$value).expect(concat!(
                    "fixture for ",
                    $name,
                    " failed to serialise"
                )),
            });
        };
    }

    // ── the API's own response shape, and the core parts it embeds ───────
    //
    // `PassportResponse` is this service's type, not the core aggregate. It was
    // the aggregate until the API model was cut, which meant this gate proved
    // the spec matched a *library's internal shape* — so a rename inside core
    // rewrote the published API with no step where anyone agreed to it.
    case!(
        "PassportResponse",
        dpp_vault::api::PassportResponse::from(&fixtures::passport())
    );
    case!("InstrumentRef", fixtures::instrument_ref());
    case!("ManufacturerInfo", fixtures::manufacturer());
    case!("MaterialEntry", fixtures::material());
    case!("PassportRef", fixtures::passport_ref());
    case!("DerogationRef", fixtures::derogation_ref());
    case!("FacilitySnapshot", fixtures::facility_snapshot());
    case!("CarbonFootprint", fixtures::carbon_footprint());
    case!("RepairabilityScore", fixtures::repairability_score());
    case!("RepairCriterion", fixtures::repair_criterion());
    case!("ComplianceResult", fixtures::compliance_result());
    case!("ComplianceFinding", fixtures::compliance_finding());
    case!("LintResult", fixtures::lint_result());

    // The obligation endpoint. Served as declared types rather than assembled
    // JSON, so this gate has something to check the published shape against.
    //
    // Every nested shape is registered too, not just the two outer ones. This
    // gate compares the top-level keys of a *named* schema; a shape written
    // inline inside another has no name to look up and is checked by nothing.
    // Declaring the Rust types while inlining their schemas bought exactly
    // nothing — the three below were unverified until they were given names.
    case!(
        "ProductGroupObligation",
        fixtures::product_group_obligation()
    );
    case!(
        "ProductGroupObligationList",
        fixtures::product_group_obligation_list()
    );
    case!("PassportObligation", fixtures::passport_obligation());
    case!("ObligationDate", fixtures::obligation_date());
    case!("RetentionPeriod", fixtures::retention_period());
    case!("ReachingInstrument", fixtures::reaching_instrument());
    case!("JobProgress", fixtures::job_progress());
    case!("LintFinding", fixtures::lint_finding());
    case!("SealedEnvelope", fixtures::sealed_envelope());
    case!("ResponsibleOperator", fixtures::responsible_operator());
    case!("TransferRecord", fixtures::transfer_record());

    // ── dpp-types: platform records ───────────────────────────────────────
    case!("ApiKey", fixtures::api_key());
    case!("CreatedApiKeyResponse", fixtures::new_api_key());
    case!("CreateApiKeyRequest", fixtures::create_api_key_request());
    case!("PassportAuditEntry", fixtures::audit_entry());
    case!("Facility", fixtures::facility());
    case!("CreateFacilityRequest", fixtures::create_facility_request());
    case!("OperatorIdentifier", fixtures::operator_identifier());
    case!(
        "CreateOperatorIdentifierRequest",
        fixtures::create_operator_identifier_request()
    );
    case!(
        "RegistryIdentityAuditEntry",
        fixtures::registry_identity_audit()
    );
    case!("OperatorConfig", fixtures::operator_config());
    case!("UpdateOperatorConfig", fixtures::update_operator_config());

    // ── dpp-types: the evidence dossier ───────────────────────────────────
    case!("SignedLayer", fixtures::signed_layer());
    case!("DossierManifest", fixtures::dossier_manifest());
    case!("EvidenceDossier", fixtures::dossier());
    case!("EvidenceDossierRecord", fixtures::dossier_record());
    case!("EvidenceDossierSummary", fixtures::dossier_summary());
    case!("CheckResult", fixtures::check_result());
    case!("VerificationReport", fixtures::verification_report());

    // ── dpp-common ────────────────────────────────────────────────────────
    case!("Problem", fixtures::problem());
    case!("ProblemFieldError", fixtures::problem_field_error());
    case!("ScanBatch", fixtures::scan_batch());
    case!("ScanBatchEntry", fixtures::scan_count());
    case!("QrRenderBatchEntry", fixtures::qr_render_count());

    // ── dpp-vault: request and response bodies ────────────────────────────
    case!("CreatePassportRequest", fixtures::create_request());
    case!("ValidateResponse", fixtures::validate_response());
    case!("PassportListResponse", fixtures::passport_list_response());
    case!("WhoamiResponse", fixtures::whoami_response());
    case!("PassportScanStats", fixtures::passport_scan_stats());
    case!("OperatorScanStats", fixtures::operator_scan_stats());
    case!("DailyScanCount", fixtures::daily_scan_count());
    case!("SealResponse", fixtures::seal_response());
    case!("SealDeclarer", fixtures::seal_declarer());
    case!("SealSummaryResponse", fixtures::seal_summary_response());
    case!("InstalledPlugin", fixtures::installed_plugin());
    case!("RulesetReload", fixtures::ruleset_reload());
    case!("WebhookSubscription", fixtures::webhook_subscription());
    case!("CreateWebhookRequest", fixtures::new_webhook_subscription());
    case!(
        "CreatedWebhookResponse",
        fixtures::created_webhook_response()
    );
    case!("EolRequest", fixtures::eol_request());
    case!("SuspendRequest", fixtures::suspend_request());
    case!("NodeState", fixtures::node_state());
    case!("VaultInfo", fixtures::vault_info());
    case!(
        "TransferInitiateRequest",
        fixtures::transfer_initiate_request()
    );
    case!("TreeReport", fixtures::tree_report());
    case!("TreeNodeReport", fixtures::tree_node_report());
    case!("RegistrationView", fixtures::registration_view());
    case!("TransferNotificationView", fixtures::transfer_view());
    case!("CurrentOperatorView", fixtures::current_operator_view());
    case!("PassportRegistryView", fixtures::passport_registry_view());
    case!("RegistryVerificationView", fixtures::verification_view());
    case!("RegistrationCounts", fixtures::registration_counts());
    case!("TransferNotificationCounts", fixtures::transfer_counts());
    case!("RegistryRollupView", fixtures::registry_rollup_view());

    // ── dpp-identity: the internal signing surface ────────────────────────
    case!("InternalSignRequest", fixtures::sign_request());
    case!("InternalSignResponse", fixtures::sign_response());
    case!("InternalVerifyRequest", fixtures::verify_request());
    case!("InternalVerifyResponse", fixtures::verify_response());
    case!("InternalRotateKeyRequest", fixtures::rotate_request());
    case!("InternalRotateKeyResponse", fixtures::rotate_response());

    // ── dpp-integrator: bulk import ───────────────────────────────────────
    case!("ImportSyncResponse", fixtures::import_sync_response());
    case!("ImportAsyncResponse", fixtures::import_async_response());
    case!("ImportCreatedEntry", fixtures::import_created_entry());
    case!("ImportUpdatedEntry", fixtures::import_updated_entry());
    case!("ImportErrorEntry", fixtures::import_error_entry());
    case!("JobStatusResponse", fixtures::job_status_response());

    cases
}

fn enum_cases() -> Vec<EnumCase> {
    fn wire<T: serde::Serialize>(values: &[T]) -> Vec<String> {
        values
            .iter()
            .map(|v| {
                serde_json::to_value(v)
                    .expect("enum variant failed to serialise")
                    .as_str()
                    .expect("enum variant did not serialise to a string")
                    .to_owned()
            })
            .collect()
    }

    vec![
        EnumCase {
            name: "PassportStatus",
            variants: wire(&fixtures::all_passport_statuses()),
        },
        EnumCase {
            name: "OperatorRole",
            variants: wire(&fixtures::all_operator_roles()),
        },
        EnumCase {
            name: "TransferReason",
            variants: wire(&fixtures::all_transfer_reasons()),
        },
        EnumCase {
            name: "ScanVariant",
            variants: wire(&fixtures::all_scan_variants()),
        },
        EnumCase {
            name: "ApiKeyScope",
            variants: wire(&fixtures::all_api_key_scopes()),
        },
        EnumCase {
            name: "ComplianceStatus",
            variants: wire(&fixtures::all_compliance_statuses()),
        },
        EnumCase {
            name: "LintSeverity",
            variants: wire(&fixtures::all_lint_severities()),
        },
        EnumCase {
            name: "SealFormat",
            variants: wire(&fixtures::all_seal_formats()),
        },
        EnumCase {
            name: "SealCoverage",
            variants: wire(&fixtures::all_coverages()),
        },
        // `DateBasis` and `RetentionBasis` match variant for variant today and
        // are checked separately on purpose. They are two enumerations in core
        // answering two questions; one spec schema for both would let either
        // drift silently behind the other, and the drift would be invisible
        // precisely because they currently agree.
        EnumCase {
            name: "DateBasis",
            variants: wire(&fixtures::all_date_bases()),
        },
        EnumCase {
            name: "RetentionBasis",
            variants: wire(&fixtures::all_retention_bases()),
        },
        // Both were written out inline twice — once on the passport, once on the
        // obligation — and so were checked nowhere: an `enum` list only reachable
        // through a property is not a schema this gate can name. One shared
        // schema each, and now a core variant that neither copy knew about fails
        // here instead of shipping.
        EnumCase {
            name: "Granularity",
            variants: wire(&fixtures::all_granularities()),
        },
        EnumCase {
            name: "RecordedBasis",
            variants: wire(&fixtures::all_recorded_bases()),
        },
        // The two statuses that qualify a served passport obligation. A variant
        // core adds here changes what the endpoint can say about how firm a
        // requirement is, so it must not reach the wire undocumented.
        EnumCase {
            name: "InstrumentStatus",
            variants: wire(&fixtures::all_instrument_statuses()),
        },
        EnumCase {
            name: "RegulatoryStatus",
            variants: wire(&fixtures::all_regulatory_statuses()),
        },
    ]
}

/// Every documented operation that takes query parameters, paired with the
/// struct the handler deserialises them into.
///
/// Several operations share one struct — `days` is `StatsQuery` on both stats
/// routes, `linkType` is `ByGtinQuery` on all four Digital Link routes — so each
/// route is registered separately rather than the struct being registered once.
/// A parameter documented on one route and not its sibling is exactly the kind
/// of drift this is for, and registering per struct would hide it.
fn query_cases() -> Vec<QueryCase> {
    let mut cases = Vec::new();

    macro_rules! case {
        ($method:literal, $path:literal, $value:expr) => {
            cases.push(QueryCase {
                method: $method,
                path: $path,
                value: serde_json::to_value(&$value).expect(concat!(
                    "query fixture for ",
                    $method,
                    " ",
                    $path,
                    " failed to serialise"
                )),
            });
        };
    }

    case!("get", "/vault/api/v1/dpps", fixtures::list_query());
    case!(
        "get",
        "/vault/api/v1/dpp/by-identity",
        fixtures::identity_query()
    );
    case!(
        "get",
        "/vault/api/v1/dpp/{dppId}/stats",
        fixtures::stats_query()
    );
    case!("get", "/vault/api/v1/stats", fixtures::stats_query());
    case!(
        "get",
        "/vault/public/dpp/{dppId}",
        fixtures::public_read_query()
    );
    case!(
        "get",
        "/vault/public/dpp/by-gtin/{gtin}",
        fixtures::public_read_query()
    );
    case!(
        "get",
        "/integrator/api/v1/templates/{productGroup}",
        fixtures::template_query()
    );
    case!("get", "/01/{gtin}", fixtures::by_gtin_query());
    case!("get", "/01/{gtin}/21/{serial}", fixtures::by_gtin_query());
    case!("get", "/01/{gtin}/10/{batch}", fixtures::by_gtin_query());
    case!(
        "get",
        "/01/{gtin}/10/{batch}/21/{serial}",
        fixtures::by_gtin_query()
    );

    cases
}

/// `DeactivationReason` is an internally-tagged enum whose spec is a `oneOf` of
/// per-`kind` objects, so neither the object nor the enum check fits it. Its
/// discriminator values are checked instead.
fn deactivation_reason_kinds() -> Vec<String> {
    fixtures::all_deactivation_reasons()
        .iter()
        .map(|r| {
            serde_json::to_value(r).expect("DeactivationReason failed to serialise")["kind"]
                .as_str()
                .expect("DeactivationReason has no `kind` discriminator")
                .to_owned()
        })
        .collect()
}

// ── The dpp-core repin tripwire ────────────────────────────────────────────

/// The `dpp-core` version this contract was last verified against **by hand**.
///
/// Bump only after re-checking the enums listed below against the released
/// crate. Bumping it to make a red build green is the one thing that breaks
/// this gate.
const CORE_VERSION_VERIFIED: &str = "0.19.0";

/// Enums whose variants this test cannot enumerate, and so cannot gate.
///
/// Listed here so the failure message can name them, rather than leaving the
/// reader to work out what "re-check the enums" means.
const UNENUMERABLE_CORE_ENUMS: &[&str] = &[
    "PassportStatus",
    "OperatorRole",
    "TransferReason",
    "DeactivationReason",
    "ComplianceStatus",
    "LifecycleStage",
    "SystemBoundary",
    "DateBasis",
    "RetentionBasis",
    "Granularity",
    "RecordedBasis",
    "InstrumentStatus",
    "RegulatoryStatus",
];

/// A `dpp-core` repin must not pass silently.
///
/// Everything else in this file survives a repin on its own: a field added to a
/// core struct fails the fixture's compile, a renamed wire key fails the schema
/// check, a changed field type fails the type check. **Enum variants do not.**
///
/// Every enum in `dpp-domain` is `#[non_exhaustive]`, which is correct for a
/// published crate but means a consumer cannot enumerate one from outside. The
/// variant lists in `fixtures` are therefore written by hand, and a hand-written
/// list does not stop compiling when core grows a variant — it compiles, the
/// enum check passes, and the new value ships undocumented. That is precisely
/// how `PassportStatus` came to omit `superseded` and `deactivated`, two states
/// the server returns and the description called impossible.
///
/// So the repin itself is the trigger. Changing the pin fails this test, and
/// clearing it means going and looking.
///
/// **This is a stopgap.** The real fix belongs in `dpp-core`: a
/// `pub const ALL: &'static [Self]` on each enum, exactly as `SealFormat::ALL`
/// already does for the same stated reason. Once those land and the engine
/// repins, the fixtures read `ALL` directly, the hand-written lists go, and this
/// tripwire can go with them.
#[test]
fn a_dpp_core_repin_forces_the_enums_to_be_rechecked() {
    assert_eq!(
        dpp_domain::VERSION,
        CORE_VERSION_VERIFIED,
        "\n\ndpp-core moved from {CORE_VERSION_VERIFIED} to {}, and this contract was verified \
         against {CORE_VERSION_VERIFIED}.\n\n\
         Struct changes are already covered — a new field on a core struct fails to compile in \
         `fixtures`, and a renamed or retyped one fails the schema checks. This test exists for \
         the one thing that is NOT covered: enum variants.\n\n\
         `dpp-domain`'s enums are `#[non_exhaustive]`, so this crate cannot enumerate them. The \
         variant lists in `fixtures` are hand-written and will keep compiling — and keep passing \
         — after core adds a variant, shipping it undocumented.\n\n\
         Re-check each of these against the new release, add any new variant to its fixture list \
         AND to its schema under api/components/schemas/, then bump CORE_VERSION_VERIFIED:\n  {}\n\n\
         Do not bump it first.\n",
        dpp_domain::VERSION,
        UNENUMERABLE_CORE_ENUMS.join("\n  ")
    );
}

// ── Declared type vs emitted type ──────────────────────────────────────────

/// The JSON type a value actually has, in OpenAPI's vocabulary.
///
/// `integer` is reported for a whole number because OpenAPI distinguishes it
/// from `number` even though JSON does not — a float documented as `integer` is
/// a real mismatch for a generated client that types the field as an int.
fn json_type_of(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
        Value::Number(n) => {
            if n.is_i64() || n.is_u64() {
                "integer"
            } else {
                "number"
            }
        }
    }
}

/// The set of types a property schema declares, following `$ref`, `allOf` and
/// `anyOf` so a `$ref`-ed scalar (an enum, a formatted string) is still typed.
///
/// `None` means the schema declares no type this can read — a bare composition
/// with no typed branch — and the property is skipped rather than guessed at.
fn declared_types(spec: &Value, prop: &Value) -> Option<BTreeSet<String>> {
    let mut out = BTreeSet::new();

    fn collect(spec: &Value, node: &Value, out: &mut BTreeSet<String>) {
        let node = resolve(spec, node);
        match node.get("type") {
            Some(Value::String(t)) => {
                out.insert(t.clone());
            }
            Some(Value::Array(ts)) => {
                out.extend(ts.iter().filter_map(Value::as_str).map(str::to_owned));
            }
            _ => {}
        }
        for key in ["allOf", "anyOf", "oneOf"] {
            if let Some(branches) = node.get(key).and_then(Value::as_array) {
                for branch in branches {
                    collect(spec, branch, out);
                }
            }
        }
    }

    collect(spec, prop, &mut out);
    if out.is_empty() { None } else { Some(out) }
}

/// Whether an emitted value satisfies a declared type set.
///
/// `number` admits a whole number: JSON has one numeric type, and a field
/// documented `number` whose fixture value happens to be `7` is not a defect.
/// The reverse is not true — `integer` does not admit a fractional value.
fn type_matches(declared: &BTreeSet<String>, actual: &str) -> bool {
    if declared.contains(actual) {
        return true;
    }
    actual == "integer" && declared.contains("number")
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[test]
fn object_schemas_match_the_types_behind_them() {
    let spec = spec();
    let schemas = schemas(&spec);
    let mut failures: Vec<String> = Vec::new();

    for case in object_cases() {
        let Some(schema) = schemas.get(case.name) else {
            failures.push(format!(
                "{}: registered in this test but absent from the spec",
                case.name
            ));
            continue;
        };

        let documented = spec_properties(&spec, schema);
        let emitted = wire_keys(&case.value);

        let undocumented: BTreeSet<String> = emitted.difference(&documented).cloned().collect();
        let phantom: BTreeSet<String> = documented.difference(&emitted).cloned().collect();

        if !undocumented.is_empty() {
            failures.push(format!(
                "{}: the server emits fields the spec does not document: {}",
                case.name,
                joined(&undocumented)
            ));
        }
        if !phantom.is_empty() {
            failures.push(format!(
                "{}: the spec documents fields the server never emits: {}",
                case.name,
                joined(&phantom)
            ));
        }

        // A `required` property the server cannot emit is worse than an
        // undocumented one: a conforming client is entitled to reject the
        // response outright.
        let impossible: BTreeSet<String> = spec_required(&spec, schema)
            .difference(&emitted)
            .cloned()
            .collect();
        if !impossible.is_empty() {
            failures.push(format!(
                "{}: the spec marks fields REQUIRED that the server never emits: {}",
                case.name,
                joined(&impossible)
            ));
        }

        // Matching names are not a matching contract. `co2ePerUnit` and
        // `repairabilityScore` were both documented as bare numbers long after
        // they became objects, and a name-only check passes that happily — a
        // generated client would type them as `f64` and fail to parse every
        // response. Compare the declared type against the type the fixture
        // actually serialises to.
        let props = schema_property_map(&spec, schema);
        let emitted_obj = case
            .value
            .as_object()
            .expect("fixture did not serialise to a JSON object");
        for (name, prop_schema) in &props {
            let Some(actual_value) = emitted_obj.get(name) else {
                continue; // absence is already reported above
            };
            let Some(declared) = declared_types(&spec, prop_schema) else {
                continue; // untyped composition — nothing to compare
            };
            let actual = json_type_of(actual_value);
            if !type_matches(&declared, actual) {
                failures.push(format!(
                    "{}.{name}: the spec says `{}`, the server sends `{actual}`",
                    case.name,
                    declared.iter().cloned().collect::<Vec<_>>().join(" | ")
                ));
            }
        }
    }

    assert!(
        failures.is_empty(),
        "OpenAPI object schemas disagree with the types that implement them:\n  {}\n\n\
         Fix the spec under api/components/schemas/ (then `just openapi-bundle`), \
         or fix the type. Do not edit the fixtures to match a wrong spec.",
        failures.join("\n  ")
    );
}

#[test]
fn enum_schemas_list_every_variant_the_server_can_emit() {
    let spec = spec();
    let schemas = schemas(&spec);
    let mut failures: Vec<String> = Vec::new();

    let mut check = |name: &str, emitted: Vec<String>| {
        let Some(schema) = schemas.get(name) else {
            failures.push(format!(
                "{name}: registered in this test but absent from the spec"
            ));
            return;
        };
        let documented: BTreeSet<String> = schema
            .get("enum")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default();
        let emitted: BTreeSet<String> = emitted.into_iter().collect();

        let undocumented: BTreeSet<String> = emitted.difference(&documented).cloned().collect();
        let phantom: BTreeSet<String> = documented.difference(&emitted).cloned().collect();

        if !undocumented.is_empty() {
            failures.push(format!(
                "{name}: the server can emit values the spec does not list: {} \
                 (a client modelling this as a closed enum fails on them)",
                joined(&undocumented)
            ));
        }
        if !phantom.is_empty() {
            failures.push(format!(
                "{name}: the spec lists values the server never emits: {}",
                joined(&phantom)
            ));
        }
    };

    for case in enum_cases() {
        check(case.name, case.variants);
    }

    assert!(
        failures.is_empty(),
        "OpenAPI enum schemas disagree with the Rust enums behind them:\n  {}",
        failures.join("\n  ")
    );
}

#[test]
fn deactivation_reason_documents_every_kind() {
    let spec = spec();
    let schema = &schemas(&spec)["DeactivationReason"];
    let documented: BTreeSet<String> = schema["oneOf"]
        .as_array()
        .expect("DeactivationReason is not a oneOf")
        .iter()
        .filter_map(|v| v["properties"]["kind"]["enum"][0].as_str())
        .map(str::to_owned)
        .collect();
    let emitted: BTreeSet<String> = deactivation_reason_kinds().into_iter().collect();

    assert_eq!(
        documented,
        emitted,
        "DeactivationReason `kind` discriminators disagree.\n  spec: {}\n  code: {}",
        joined(&documented),
        joined(&emitted)
    );
}

#[test]
fn every_schema_is_covered() {
    let spec = spec();
    let declared: BTreeSet<String> = schemas(&spec).keys().cloned().collect();

    let mut covered: BTreeSet<String> = object_cases()
        .into_iter()
        .map(|c| c.name.to_owned())
        .collect();
    covered.extend(enum_cases().into_iter().map(|c| c.name.to_owned()));
    covered.insert("DeactivationReason".to_owned());
    covered.extend(UNCHECKED.iter().map(|(n, _)| (*n).to_owned()));

    let unchecked: BTreeSet<String> = declared.difference(&covered).cloned().collect();
    assert!(
        unchecked.is_empty(),
        "these schemas are in the spec but nothing checks them against code: {}\n\n\
         Add a case to `object_cases`/`enum_cases`, or an entry to `UNCHECKED` \
         with the reason it cannot be checked. A schema no test covers is a \
         schema free to drift.",
        joined(&unchecked)
    );

    let stale: BTreeSet<String> = covered.difference(&declared).cloned().collect();
    assert!(
        stale.is_empty(),
        "these names are registered here but no longer exist in the spec: {}",
        joined(&stale)
    );
}

// ── Documented bounds vs enforced bounds ───────────────────────────────────

/// A documented numeric bound is a promise about what the server accepts, and
/// nothing was checking it.
///
/// `CreatePassportRequest.repairabilityScore` was documented `minimum: 0, maximum: 100`
/// with a description saying "0–100", while the validator enforced `0..=10` and
/// rejected anything above with a 422. Every check up to this point passed: the
/// property existed, was named right, and was typed right. A client trusting
/// the description would send 55 and be refused.
///
/// This does not restate the bound — restating it is how the two got out of
/// step. It reads `minimum`/`maximum` from the spec and drives the **real**
/// validator at those exact values, so the spec is only green when the code
/// agrees with it at the boundary.
#[test]
fn documented_numeric_bounds_are_the_bounds_actually_enforced() {
    use dpp_vault::handlers::create::validate_create_request;

    let spec = spec();
    let schema = &schemas(&spec)["CreatePassportRequest"];
    let props = schema_property_map(&spec, schema);

    // Each numeric field of CreatePassportRequest, with a way to set it on a body that
    // is otherwise valid. Adding a bounded field without adding it here is
    // caught below.
    type Setter = fn(&mut dpp_vault::handlers::create::CreatePassportRequest, f64);
    let numeric: &[(&str, Setter)] = &[
        ("co2ePerUnit", |b, v| b.co2e_per_unit = Some(v)),
        ("repairabilityScore", |b, v| b.repairability_score = Some(v)),
    ];

    let accepts = |set: Setter, v: f64| -> bool {
        let mut body = fixtures::minimal_create_request();
        set(&mut body, v);
        validate_create_request(&body).is_none()
    };

    let mut failures = Vec::new();
    let mut checked = BTreeSet::new();

    for (name, set) in numeric {
        let Some(prop) = props.get(*name) else {
            failures.push(format!(
                "CreatePassportRequest.{name}: no longer in the spec"
            ));
            continue;
        };
        let min = prop.get("minimum").and_then(Value::as_f64);
        let max = prop.get("maximum").and_then(Value::as_f64);
        if min.is_none() && max.is_none() {
            continue;
        }
        checked.insert((*name).to_owned());

        // Step just outside by a hair relative to the bound's own magnitude, so
        // this works for a bound of 10 and a bound of 730 alike.
        let nudge = |v: f64| v.abs().max(1.0) * 1e-6;

        if let Some(min) = min {
            if !accepts(*set, min) {
                failures.push(format!(
                    "CreatePassportRequest.{name}: spec says minimum {min}, but the validator rejects it"
                ));
            }
            if accepts(*set, min - nudge(min)) {
                failures.push(format!(
                    "CreatePassportRequest.{name}: spec says minimum {min}, but the validator accepts \
                     values below it"
                ));
            }
        }
        if let Some(max) = max {
            if !accepts(*set, max) {
                failures.push(format!(
                    "CreatePassportRequest.{name}: spec says maximum {max}, but the validator REJECTS it \
                     — the documented range is wider than the enforced one"
                ));
            }
            if accepts(*set, max + nudge(max)) {
                failures.push(format!(
                    "CreatePassportRequest.{name}: spec says maximum {max}, but the validator accepts \
                     values above it — the documented range is narrower than the enforced one"
                ));
            }
        }
    }

    // A bounded property nothing drives is a bound nobody is checking.
    let bounded: BTreeSet<String> = props
        .iter()
        .filter(|(_, p)| p.get("minimum").is_some() || p.get("maximum").is_some())
        .map(|(k, _)| k.clone())
        .collect();
    let undriven: BTreeSet<String> = bounded.difference(&checked).cloned().collect();
    if !undriven.is_empty() {
        failures.push(format!(
            "CreatePassportRequest declares bounds on properties this test does not drive: {} — add them \
             to `numeric` above",
            joined(&undriven)
        ));
    }

    assert!(
        failures.is_empty(),
        "documented bounds disagree with the validator:\n  {}",
        failures.join("\n  ")
    );
}

// ── Response-body coverage ─────────────────────────────────────────────────

/// `application/json` success responses that legitimately describe no Rust type
/// of ours, with the reason. Everything else must name a schema.
const INLINE_JSON_RESPONSE_ALLOWED: &[(&str, &str)] = &[
    (
        "/integrator/api/v1/schemas",
        "returns the product_group schema registry's own listing of JSON Schema \
         documents — data about schemas, not a serialised domain type",
    ),
    (
        "/integrator/api/v1/schemas/{productGroup}",
        "returns a JSON Schema document verbatim. Describing a meta-schema's \
         shape in OpenAPI would restate JSON Schema itself",
    ),
    (
        "/integrator/api/v1/schemas/{productGroup}/{version}",
        "as above, pinned to a version",
    ),
];

/// Every JSON success body must be a named schema, because only a named schema
/// is checked against a Rust type.
///
/// This is what closes the gap the other tests leave: they prove every *named*
/// schema matches its type and every route is documented, but an endpoint whose
/// response is written as an anonymous inline object satisfies both while its
/// body is described by nothing and verified by nothing. Ten endpoints were in
/// that state — including the passport list, the seal status, and `whoami` —
/// and their inline shapes had no mechanism keeping them true.
///
/// Non-JSON bodies are out of scope by construction: `text/html`, `image/png`,
/// `text/csv`, and the external-standard payloads (`application/aas+json`,
/// `application/linkset+json`) are not serialised from a type this workspace
/// owns.
#[test]
fn every_json_success_response_names_a_schema() {
    let spec = spec();
    let allowed: BTreeSet<&str> = INLINE_JSON_RESPONSE_ALLOWED
        .iter()
        .map(|(p, _)| *p)
        .collect();

    let mut failures = Vec::new();
    let mut allowlist_used: BTreeSet<&str> = BTreeSet::new();

    let paths = spec["paths"].as_object().expect("paths is not an object");
    for (path, item) in paths {
        let Some(ops) = item.as_object() else {
            continue;
        };
        for (method, op) in ops {
            let Some(responses) = op.get("responses").and_then(Value::as_object) else {
                continue;
            };
            for (code, response) in responses {
                if !code.starts_with('2') {
                    continue;
                }
                let Some(json_body) = response
                    .get("content")
                    .and_then(Value::as_object)
                    .and_then(|c| c.get("application/json"))
                else {
                    continue;
                };
                let Some(schema) = json_body.get("schema") else {
                    continue;
                };

                // A named schema, an array of one, or a composition over one.
                let named = schema.get("$ref").is_some()
                    || schema.get("items").is_some_and(|i| i.get("$ref").is_some())
                    || schema
                        .get("allOf")
                        .and_then(Value::as_array)
                        .is_some_and(|b| b.iter().any(|x| x.get("$ref").is_some()));

                if named {
                    continue;
                }
                if allowed.contains(path.as_str()) {
                    allowlist_used.insert(path.as_str());
                    continue;
                }
                failures.push(format!(
                    "{} {path} [{code}] describes its JSON body inline — nothing checks that \
                     shape against the code",
                    method.to_uppercase()
                ));
            }
        }
    }

    // An allowlist entry for a response that no longer exists (or is now named)
    // is a stale excuse; it should be deleted rather than left to cover
    // something else later.
    let stale: BTreeSet<&str> = allowed.difference(&allowlist_used).copied().collect();
    if !stale.is_empty() {
        failures.push(format!(
            "INLINE_JSON_RESPONSE_ALLOWED names paths that no longer have an inline JSON \
             response: {}",
            stale.into_iter().collect::<Vec<_>>().join(", ")
        ));
    }

    assert!(
        failures.is_empty(),
        "JSON success responses that name no schema:\n  {}\n\n\
         Give the handler a named response type, add a schema for it under \
         api/components/schemas/, `$ref` it here, and register it in `object_cases` \
         — that is what puts the body under the contract test.",
        failures.join("\n  ")
    );
}

// ── Request-body coverage ──────────────────────────────────────────────────

/// `application/json` request bodies that legitimately name no schema, with the
/// reason. Keyed by `(method, path)`, because one path can take a body on more
/// than one method and only one of them may be exempt.
const INLINE_JSON_REQUEST_ALLOWED: &[(&str, &str, &str)] = &[(
    "put",
    "/vault/api/v1/dpp/{dppId}",
    "a free-form merge-patch: the caller supplies only the fields being changed, \
     so the body is an open bag of passport fields rather than a fixed shape. \
     There is no Rust struct behind it to compare a property list against — the \
     handler takes the object and applies it field by field. Naming it would \
     require enumerating every patchable field, which is `PassportResponse`'s \
     job and would be a second copy to drift",
)];

/// Every `application/json` request body names a schema.
///
/// The sibling of `every_json_success_response_names_a_schema`, and the half
/// that was missing. `every_published_object_shape_has_a_name` walks the
/// properties of *named schemas*, and the response check walks responses — so a
/// body shape written inline under `requestBody` fell between them and was
/// checked by nothing at all.
///
/// That was not hypothetical either: the suspend endpoint declared its
/// `{ reason }` body inline while a real `SuspendRequest` struct sat behind it,
/// so renaming that field would have changed what the server accepts and failed
/// nothing. A request body is the side of the contract a *client* has to get
/// right, which makes an unverified one the more expensive of the two.
///
/// Non-JSON bodies are out of scope by construction: `multipart/form-data`
/// uploads describe file parts, not a serialised Rust type, and there is no
/// struct whose serde output could be compared to them.
#[test]
fn every_json_request_body_names_a_schema() {
    let spec = spec();
    let allowed: BTreeSet<(&str, &str)> = INLINE_JSON_REQUEST_ALLOWED
        .iter()
        .map(|(m, p, _)| (*m, *p))
        .collect();

    let mut failures = Vec::new();
    let mut allowlist_used: BTreeSet<(&str, &str)> = BTreeSet::new();

    let paths = spec["paths"].as_object().expect("paths is not an object");
    for (path, item) in paths {
        let Some(ops) = item.as_object() else {
            continue;
        };
        for (method, op) in ops {
            let Some(schema) = op
                .get("requestBody")
                .and_then(|b| b.get("content"))
                .and_then(|c| c.get("application/json"))
                .and_then(|j| j.get("schema"))
            else {
                continue;
            };

            // A named schema, an array of one, or a composition over one — the
            // same three shapes the response check accepts.
            let named = schema.get("$ref").is_some()
                || schema.get("items").is_some_and(|i| i.get("$ref").is_some())
                || schema
                    .get("allOf")
                    .and_then(Value::as_array)
                    .is_some_and(|b| b.iter().any(|x| x.get("$ref").is_some()));

            if named {
                continue;
            }

            let key = (method.as_str(), path.as_str());
            if allowed.contains(&key) {
                allowlist_used.insert(key);
                continue;
            }
            failures.push(format!(
                "{} {path} describes its JSON request body inline — nothing checks that \
                 shape against the code",
                method.to_uppercase()
            ));
        }
    }

    // A stale excuse covers whatever drifts into its place next; delete it
    // rather than leaving it to do that.
    let stale: Vec<String> = allowed
        .difference(&allowlist_used)
        .map(|(m, p)| format!("{} {p}", m.to_uppercase()))
        .collect();
    if !stale.is_empty() {
        failures.push(format!(
            "INLINE_JSON_REQUEST_ALLOWED names operations that no longer have an inline \
             JSON request body: {}",
            stale.join(", ")
        ));
    }

    assert!(
        failures.is_empty(),
        "JSON request bodies that name no schema:\n  {}\n\n\
         Give the handler's body a named type, add a schema for it under \
         api/components/schemas/, `$ref` it here, and register it in `object_cases` \
         — that is what puts the body under the contract test.",
        failures.join("\n  ")
    );
}

// ── No unnamed shapes ──────────────────────────────────────────────────────

/// Whether a property node declares an object shape inline rather than naming
/// one, looking through arrays and composition but **not** through `$ref`.
///
/// A `$ref` is the whole point: it resolves to a named schema, which is what
/// makes the shape reachable by every other check in this file.
fn declares_inline_object(node: &Value) -> bool {
    if node.get("$ref").is_some() {
        return false;
    }
    if node.get("properties").is_some() {
        return true;
    }
    if let Some(items) = node.get("items")
        && declares_inline_object(items)
    {
        return true;
    }
    ["allOf", "anyOf", "oneOf"].iter().any(|key| {
        node.get(key)
            .and_then(Value::as_array)
            .is_some_and(|branches| branches.iter().any(declares_inline_object))
    })
}

/// Every published object shape has a name of its own.
///
/// This closes the hole the rest of this file was built around but could not
/// see. `every_schema_is_covered` guarantees that no *named* schema goes
/// unchecked — but a shape written inline inside another schema never becomes a
/// named schema, so it is not skipped, it is invisible. Nothing compares it to
/// code, and nothing ever reports that as a gap.
///
/// That is not theoretical. The product-group obligation endpoint declared four
/// Rust types **specifically so this gate could check them**, then wrote all
/// four inline — so renaming a field in any of them failed nothing at all. The
/// stated reason for declaring them was not being delivered, and no test said
/// so.
///
/// There is no exception list on purpose. An allowlist here would refill with
/// exactly the shapes this exists to prevent, one justified entry at a time.
///
/// Scoped to *properties*. A named schema that is itself a `oneOf` of object
/// variants — `DeactivationReason` — is a tagged union, is named, and has its
/// own check.
#[test]
fn every_published_object_shape_has_a_name() {
    let spec = spec();
    let mut unnamed: Vec<String> = Vec::new();

    for (name, schema) in schemas(&spec) {
        let Some(properties) = schema.get("properties").and_then(Value::as_object) else {
            continue;
        };
        for (property, node) in properties {
            if declares_inline_object(node) {
                unnamed.push(format!("{name}.{property}"));
            }
        }
    }

    unnamed.sort();
    assert!(
        unnamed.is_empty(),
        "these properties hold an object shape written inline, so no test can \
         reach it:\n  {}\n\n\
         Give each one its own file under api/components/schemas/, `$ref` it \
         here, and register it in `object_cases` (or in `UNCHECKED` with the \
         reason it cannot be checked). An inline shape is not covered by \
         `every_schema_is_covered` — it never becomes a schema at all.",
        unnamed.join("\n  ")
    );
}

// ── Query parameters ───────────────────────────────────────────────────────

/// Documented query parameter names equal the names the handler's struct
/// actually reads.
///
/// This gate shipped a parameter no client could send. Until the product group
/// rename, `/vault/api/v1/dpp/by-identity` documented a parameter named
/// `product group` — a space, in an identifier position, the residue of a
/// find-and-replace that ran over a `name:` field. The handler reads
/// `productGroup`; an integration test was sending `product_group`. Three
/// spellings of one parameter, and every existing check passed: the schemas
/// matched, the bounds matched, the route was documented.
///
/// It survived because the old name was a single word, spelled identically in
/// snake_case and camelCase, so the description, the test and the handler had
/// agreed **by coincidence** rather than because anything compared them.
/// Renaming to two words broke the coincidence in all three places at once.
///
/// Both directions fail. A documented parameter the handler never reads is
/// dead — a client that sends it is silently ignored. A parameter the handler
/// reads and the spec omits is undiscoverable.
#[test]
fn documented_query_parameters_are_the_ones_the_handler_reads() {
    let spec = spec();
    let mut failures: Vec<String> = Vec::new();

    for case in query_cases() {
        let Some(documented) = spec_query_params(&spec, case.method, case.path) else {
            failures.push(format!(
                "{} {}: registered here but absent from the spec",
                case.method.to_uppercase(),
                case.path
            ));
            continue;
        };

        let read = wire_keys(&case.value);

        let undocumented: BTreeSet<String> = read.difference(&documented).cloned().collect();
        let dead: BTreeSet<String> = documented.difference(&read).cloned().collect();

        if !undocumented.is_empty() {
            failures.push(format!(
                "{} {}: the handler reads parameters the spec does not document: {}",
                case.method.to_uppercase(),
                case.path,
                joined(&undocumented)
            ));
        }
        if !dead.is_empty() {
            failures.push(format!(
                "{} {}: the spec documents parameters the handler never reads: {} \
                 (a client sending them is silently ignored)",
                case.method.to_uppercase(),
                case.path,
                joined(&dead)
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "OpenAPI query parameters disagree with the structs that read them:\n  {}\n\n\
         Fix the `name:` under api/paths/ (then `just openapi-bundle`), or fix the \
         handler's query struct. The wire name is the field name after the struct's \
         serde rename rule — not the Rust field name.",
        failures.join("\n  ")
    );
}

/// No operation takes query parameters without something checking them.
///
/// Without this, the check above is only as good as whoever remembered to
/// register a case, and a new route with a new parameter is exactly when nobody
/// does.
#[test]
fn every_operation_with_query_parameters_is_covered() {
    let spec = spec();

    let documented = operations_with_query_params(&spec);
    let registered: BTreeSet<(String, String)> = query_cases()
        .into_iter()
        .map(|c| (c.method.to_owned(), c.path.to_owned()))
        .collect();

    let uncovered: Vec<String> = documented
        .difference(&registered)
        .map(|(m, p)| format!("{} {p}", m.to_uppercase()))
        .collect();
    assert!(
        uncovered.is_empty(),
        "these operations declare query parameters but nothing checks them against \
         a handler struct: {}\n\n\
         Add a case to `query_cases`.",
        uncovered.join(", ")
    );

    let stale: Vec<String> = registered
        .difference(&documented)
        .map(|(m, p)| format!("{} {p}", m.to_uppercase()))
        .collect();
    assert!(
        stale.is_empty(),
        "these operations are registered in `query_cases` but no longer declare query \
         parameters in the spec: {}",
        stale.join(", ")
    );
}

// ── Route coverage ─────────────────────────────────────────────────────────

/// Router sources, embedded at compile time so they cannot go stale relative to
/// the code that is actually built.
mod routers {
    pub const VAULT: &str = include_str!("../../dpp-vault/src/router.rs");
    pub const IDENTITY: &str = include_str!("../../dpp-identity/src/router.rs");
    pub const INTEGRATOR: &str = include_str!("../../dpp-integrator/src/router.rs");
    pub const RESOLVER: &str = include_str!("../../dpp-resolver/src/router.rs");
    pub const NODE: &str = include_str!("../src/router.rs");
}

/// Everything before the file's `#[cfg(test)]` module.
///
/// Router files mount throwaway routes inside their own unit tests (the CORS
/// test in `dpp-vault` registers `/credential/dpp/{id}`), and those are not part
/// of the served surface. Scanning them would report a documented route as
/// undocumented because a test spelled its path parameter differently.
fn without_tests(src: &str) -> &str {
    match src.find("#[cfg(test)]") {
        Some(at) => &src[..at],
        None => src,
    }
}

/// Extract the path literal of every `.route("…"` in `src`.
///
/// Route registration is a fixed, single-form construct — `.route("` followed
/// by a string literal — so scanning for it is exact, unlike reading field
/// shapes off a struct. Multi-line `.route(\n    "…"` is handled by matching the
/// literal after the token rather than requiring it on the same line.
fn routes_in(src: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut rest = without_tests(src);
    while let Some(at) = rest.find(".route(") {
        rest = &rest[at + ".route(".len()..];
        let Some(open) = rest.find('"') else { break };
        // Only whitespace may separate the paren from the literal; anything else
        // means this was not a literal route registration.
        if !rest[..open].trim().is_empty() {
            continue;
        }
        let after = &rest[open + 1..];
        let Some(close) = after.find('"') else { break };
        out.insert(after[..close].to_owned());
        rest = &after[close..];
    }
    out
}

/// The section of `dpp-vault`'s router between two markers, so each group of
/// routes can be given the prefix it is actually nested under.
fn section<'a>(src: &'a str, from: &str, to: Option<&str>) -> &'a str {
    let start = src
        .find(from)
        .unwrap_or_else(|| panic!("marker {from:?} not found in router"));
    let rest = &src[start..];
    match to {
        Some(end) => {
            &rest[..rest
                .find(end)
                .unwrap_or_else(|| panic!("marker {end:?} not found"))]
        }
        None => rest,
    }
}

fn prefixed(prefix: &str, routes: BTreeSet<String>) -> BTreeSet<String> {
    routes
        .into_iter()
        .map(|r| {
            if prefix.is_empty() {
                r
            } else {
                format!("{prefix}{r}")
            }
        })
        .collect()
}

/// Every path the assembled node serves.
///
/// The node mounts `dpp_identity_service::router::build_public` — deliberately
/// not `build` — so the `/internal/*` signing routes are not part of this
/// surface. The vault signs in-process; there is no network-reachable signing
/// endpoint on a node.
fn node_surface() -> BTreeSet<String> {
    let vault_authenticated = section(
        routers::VAULT,
        "let authenticated =",
        Some("let internal ="),
    );
    let vault_internal = section(routers::VAULT, "let internal =", Some("let cors_layer ="));
    let vault_public = section(routers::VAULT, "let cors_layer =", None);

    let identity_public = section(routers::IDENTITY, "pub fn build_public", None);

    let mut paths = BTreeSet::new();
    paths.extend(prefixed("/vault/api/v1", routes_in(vault_authenticated)));
    paths.extend(prefixed("/vault/internal", routes_in(vault_internal)));
    paths.extend(prefixed("/vault", routes_in(vault_public)));
    paths.extend(prefixed("/identity", routes_in(identity_public)));
    paths.extend(prefixed("/integrator", routes_in(routers::INTEGRATOR)));
    // The node's own root routes, minus the `.nest` calls (which carry no
    // `.route(` literal and so are already excluded).
    paths.extend(routes_in(routers::NODE));
    paths
}

/// The resolver is a separate deployable, mounted at the root of its own host.
fn resolver_surface() -> BTreeSet<String> {
    routes_in(routers::RESOLVER)
}

/// The mTLS internal signing surface, served only when `dpp-identity` runs as
/// its own process (`servers[1]`, port 8002).
///
/// These three routes live in `build()` and not in `build_public()`, which is
/// why the node does not serve them — it signs in-process instead. They are
/// still part of the described API, because `openapi.yaml` declares standalone
/// identity as one of its three servers.
///
/// Modelled as a real surface rather than an exception list on purpose. An
/// exception list is where "missing" hides: every entry is a route nothing
/// checks, justified once by a comment that no longer has to stay true. Reading
/// them out of `build()` means adding a fourth internal route fails this test
/// the same as any other undocumented route.
fn identity_standalone_surface() -> BTreeSet<String> {
    // `build()` registers only the internal routes directly; it composes the
    // public ones via `build_public(state).merge(internal)`, which carries no
    // `.route(` literal. Slicing to `build_public` therefore yields exactly the
    // routes the node does not mount.
    let internal_only = section(
        routers::IDENTITY,
        "pub fn build",
        Some("pub fn build_public"),
    );
    routes_in(internal_only)
}

#[test]
fn every_route_is_documented_and_every_documented_path_exists() {
    let spec = spec();
    let documented: BTreeSet<String> = spec["paths"]
        .as_object()
        .expect("paths is not an object")
        .keys()
        .cloned()
        .collect();

    // The union of every deployable `openapi.yaml` names in `servers`.
    let mut served = node_surface();
    served.extend(resolver_surface());
    served.extend(identity_standalone_surface());

    let undocumented: BTreeSet<String> = served.difference(&documented).cloned().collect();
    let phantom: BTreeSet<String> = documented.difference(&served).cloned().collect();

    let mut failures = Vec::new();
    if !undocumented.is_empty() {
        failures.push(format!(
            "routes the code serves that the spec does not document: {}",
            joined(&undocumented)
        ));
    }
    if !phantom.is_empty() {
        failures.push(format!(
            "paths the spec documents that nothing serves: {}",
            joined(&phantom)
        ));
    }

    assert!(
        failures.is_empty(),
        "the OpenAPI paths and the registered routes disagree:\n  {}",
        failures.join("\n  ")
    );
}

// ── Documented error codes ─────────────────────────────────────────────────
//
// Handler sources, embedded like the routers above so they cannot go stale
// against the code that is actually built.
//
// Listing files by hand would normally be a hole — a new handler module nobody
// adds here would simply not be scanned, and the gate would pass by not
// looking. `every_registered_handler_is_readable` closes it: a handler a router
// registers and this list cannot reach fails the build by name.
mod handler_sources {
    pub const VAULT: &[&str] = &[
        include_str!("../../dpp-vault/src/handlers/api_keys.rs"),
        include_str!("../../dpp-vault/src/handlers/archive.rs"),
        include_str!("../../dpp-vault/src/handlers/audience_read.rs"),
        include_str!("../../dpp-vault/src/handlers/create.rs"),
        include_str!("../../dpp-vault/src/handlers/eol.rs"),
        include_str!("../../dpp-vault/src/handlers/evidence.rs"),
        include_str!("../../dpp-vault/src/handlers/find_by_identity.rs"),
        include_str!("../../dpp-vault/src/handlers/health.rs"),
        include_str!("../../dpp-vault/src/handlers/history.rs"),
        include_str!("../../dpp-vault/src/handlers/info.rs"),
        include_str!("../../dpp-vault/src/handlers/lint.rs"),
        include_str!("../../dpp-vault/src/handlers/list.rs"),
        include_str!("../../dpp-vault/src/handlers/node_state.rs"),
        include_str!("../../dpp-vault/src/handlers/operator.rs"),
        include_str!("../../dpp-vault/src/handlers/plugins.rs"),
        include_str!("../../dpp-vault/src/handlers/public_read.rs"),
        include_str!("../../dpp-vault/src/handlers/public_read_by_gtin.rs"),
        include_str!("../../dpp-vault/src/handlers/publish.rs"),
        include_str!("../../dpp-vault/src/handlers/read.rs"),
        include_str!("../../dpp-vault/src/handlers/registry_identity.rs"),
        include_str!("../../dpp-vault/src/handlers/registry_status.rs"),
        include_str!("../../dpp-vault/src/handlers/ruleset.rs"),
        include_str!("../../dpp-vault/src/handlers/scan_ingest.rs"),
        include_str!("../../dpp-vault/src/handlers/seal.rs"),
        include_str!("../../dpp-vault/src/handlers/stats.rs"),
        include_str!("../../dpp-vault/src/handlers/suspend.rs"),
        include_str!("../../dpp-vault/src/handlers/transfer.rs"),
        include_str!("../../dpp-vault/src/handlers/update.rs"),
        include_str!("../../dpp-vault/src/handlers/validate.rs"),
        include_str!("../../dpp-vault/src/handlers/verify_tree.rs"),
        include_str!("../../dpp-vault/src/handlers/webhooks.rs"),
        include_str!("../../dpp-vault/src/handlers/whoami.rs"),
    ];
    pub const INTEGRATOR: &[&str] = &[
        include_str!("../../dpp-integrator/src/handlers/health.rs"),
        include_str!("../../dpp-integrator/src/handlers/import.rs"),
        include_str!("../../dpp-integrator/src/handlers/job_status.rs"),
        include_str!("../../dpp-integrator/src/handlers/product_groups.rs"),
        include_str!("../../dpp-integrator/src/handlers/schemas.rs"),
        include_str!("../../dpp-integrator/src/handlers/templates.rs"),
    ];
    pub const IDENTITY: &[&str] = &[
        include_str!("../../dpp-identity/src/handlers/did_document.rs"),
        include_str!("../../dpp-identity/src/handlers/health.rs"),
        include_str!("../../dpp-identity/src/handlers/rotate_key.rs"),
        include_str!("../../dpp-identity/src/handlers/sign.rs"),
        include_str!("../../dpp-identity/src/handlers/verify.rs"),
    ];
    pub const RESOLVER: &[&str] = &[
        include_str!("../../dpp-resolver/src/handlers/resolve_aas.rs"),
        include_str!("../../dpp-resolver/src/handlers/resolve_by_gtin.rs"),
        include_str!("../../dpp-resolver/src/handlers/resolve_json.rs"),
        include_str!("../../dpp-resolver/src/handlers/resolve_qr.rs"),
        include_str!("../../dpp-resolver/src/handlers/health.rs"),
    ];
}

/// Every way a handler in this workspace names a status code, and the code it
/// means.
///
/// Two vocabularies, because the crates genuinely differ: `dpp-vault` routes
/// almost everything through the named helpers in `handlers/error.rs`, while the
/// resolver and integrator construct `StatusCode` directly. Both are exact
/// tokens, so reading them is not a heuristic — a handler body containing
/// `conflict_error(` can return `409`, and one that does not, cannot.
const CODE_TOKENS: &[(&str, u64)] = &[
    // dpp-vault's named helpers — crates/dpp-vault/src/handlers/error.rs.
    ("not_found_error(", 404),
    ("conflict_error(", 409),
    ("validation_error(", 422),
    ("require_write(", 403),
    ("require_admin(", 403),
    ("parse_passport_id(", 400),
    // `dpp-common::http_problem`, the RFC 7807 constructors the integrator and
    // resolver reach for directly.
    ("http_problem::not_found(", 404),
    ("http_problem::bad_request(", 400),
    ("http_problem::unprocessable(", 422),
    // Direct construction.
    ("StatusCode::BAD_REQUEST", 400),
    ("StatusCode::FORBIDDEN", 403),
    ("StatusCode::NOT_FOUND", 404),
    ("StatusCode::NOT_ACCEPTABLE", 406),
    ("StatusCode::CONFLICT", 409),
    ("StatusCode::GONE", 410),
    ("StatusCode::UNPROCESSABLE_ENTITY", 422),
    ("StatusCode::NOT_IMPLEMENTED", 501),
    ("StatusCode::BAD_GATEWAY", 502),
    ("StatusCode::SERVICE_UNAVAILABLE", 503),
];

/// Codes deliberately outside this gate, each because the handler body is not
/// where they are decided.
///
/// - **401** is `auth_middleware`'s, applied to a whole route group. No handler
///   body mentions it, so requiring one to would fail every authenticated route,
///   and requiring the spec to omit it would be worse — it is the truest thing
///   documented on those 54 operations.
/// - **500** is the `Err(e) => internal_error(e)` arm nearly every handler ends
///   with. Documenting it everywhere would add noise to 60-odd operations to say
///   the same thing; leaving it undocumented is the existing convention.
const CODES_NOT_GATED: &[u64] = &[401, 500];

/// `(method, path, handler)` for every `.route("…", method(handler))` in `src`.
///
/// Extends `routes_in`'s exactness to the rest of the registration: between one
/// `.route(` and the next, the only `get(`/`post(`/… calls are that route's own
/// method handlers. Matching the HTTP method names specifically rather than any
/// `ident(` keeps `.layer(DefaultBodyLimit::max(…))` from reading as one.
fn route_handlers_in(src: &str) -> BTreeSet<(String, String, String)> {
    const METHODS: &[&str] = &["get", "post", "put", "delete", "patch"];
    let mut out = BTreeSet::new();
    let body = without_tests(src);

    for (start, _) in body.match_indices(".route(") {
        let after_paren = &body[start + ".route(".len()..];

        let Some(open) = after_paren.find('"') else {
            continue;
        };
        if !after_paren[..open].trim().is_empty() {
            continue;
        }
        let after = &after_paren[open + 1..];
        let Some(close) = after.find('"') else {
            continue;
        };
        let path = after[..close].to_owned();

        // Bound the window at the `.route(` call's own closing paren. Taking
        // everything up to the next `.route(` instead made the *last* route in a
        // file swallow the rest of it, which picked up an `axum::` path from an
        // unrelated line and reported it as a handler.
        let tail = &after[close + 1..];
        let mut depth = 1usize;
        let mut end = tail.len();
        for (i, c) in tail.char_indices() {
            match c {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        end = i;
                        break;
                    }
                }
                _ => {}
            }
        }
        let window = &tail[..end];

        for method in METHODS {
            let token = format!("{method}(");
            let mut rest = window;
            let mut consumed = 0usize;
            while let Some(at) = rest.find(&token) {
                // A method call, not the tail of a longer identifier — and not a
                // path segment like `routing::get(`.
                let before = window[..consumed + at].chars().next_back();
                let preceded_by_ident =
                    before.is_some_and(|c| c.is_alphanumeric() || c == '_' || c == ':');
                let arg = &rest[at + token.len()..];
                consumed += at + token.len();
                rest = arg;
                if preceded_by_ident {
                    continue;
                }
                // `get(crate::handlers::audience_read::audience_read_handler)`
                // names a path, not a bare identifier. The handler is its last
                // segment; taking the first reported the *module* as the
                // handler and made it unfindable.
                let path_expr: String = arg
                    .chars()
                    .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == ':')
                    .collect();
                if let Some(ident) = path_expr.rsplit("::").next()
                    && !ident.is_empty()
                {
                    out.insert(((*method).to_owned(), path.clone(), ident.to_owned()));
                }
            }
        }
    }
    out
}

/// The body of `pub async fn <name>`, and nothing after it.
///
/// The end marker is the closing brace in **column 0**, which `rustfmt`
/// guarantees for a top-level item and never emits inside one. Cheaper than
/// brace matching, which would have to understand braces in string literals and
/// comments to be correct.
///
/// Getting this boundary wrong is not a small error. Scanning to the next
/// `pub`/`async` item instead let `api_keys_delete_handler` — the last item in
/// its file — run to EOF and swallow the `#[cfg(test)]` module below it, whose
/// `assert_eq!(resp.status(), StatusCode::CONFLICT)` was then reported as the
/// handler returning `409`. Test sources are stripped as well, belt and braces.
fn handler_body<'a>(sources: &[&'a str], name: &str) -> Option<&'a str> {
    // `async fn` as well as `pub async fn`: the resolver defines
    // `content_negotiation_handler` privately inside its own router, so
    // requiring `pub` reported a registered handler as unreadable.
    for needle in [format!("pub async fn {name}("), format!("async fn {name}(")] {
        for src in sources {
            let src = without_tests(src);
            let Some(at) = src.find(&needle) else {
                continue;
            };
            let rest = &src[at..];
            let end = rest.find("\n}").map_or(rest.len(), |e| e + 2);
            return Some(&rest[..end]);
        }
    }
    None
}

/// The status codes a handler body can actually produce.
fn codes_emitted_by(body: &str) -> BTreeSet<u64> {
    CODE_TOKENS
        .iter()
        .filter(|(token, _)| body.contains(token))
        .map(|(_, code)| *code)
        .filter(|c| !CODES_NOT_GATED.contains(c))
        .collect()
}

/// The 4xx/5xx codes an operation documents.
fn documented_error_codes(spec: &Value, method: &str, path: &str) -> BTreeSet<u64> {
    spec["paths"][path][method]["responses"]
        .as_object()
        .map(|r| {
            r.keys()
                .filter_map(|c| c.parse::<u64>().ok())
                .filter(|c| (400..600).contains(c))
                .filter(|c| !CODES_NOT_GATED.contains(c))
                .collect()
        })
        .unwrap_or_default()
}

/// Every `(method, path, handler)` the described deployables serve.
///
/// Mirrors `node_surface`/`resolver_surface`/`identity_standalone_surface`
/// exactly, so the two views of the router cannot disagree about what is served.
fn surface_handlers() -> BTreeSet<(String, String, String, &'static str)> {
    fn tag(
        prefix: &str,
        src: &str,
        which: &'static str,
        out: &mut BTreeSet<(String, String, String, &'static str)>,
    ) {
        for (method, path, handler) in route_handlers_in(src) {
            out.insert((method, format!("{prefix}{path}"), handler, which));
        }
    }

    let mut out = BTreeSet::new();
    tag(
        "/vault/api/v1",
        section(
            routers::VAULT,
            "let authenticated =",
            Some("let internal ="),
        ),
        "vault",
        &mut out,
    );
    tag(
        "/vault/internal",
        section(routers::VAULT, "let internal =", Some("let cors_layer =")),
        "vault",
        &mut out,
    );
    tag(
        "/vault",
        section(routers::VAULT, "let cors_layer =", None),
        "vault",
        &mut out,
    );
    tag(
        "/identity",
        section(routers::IDENTITY, "pub fn build_public", None),
        "identity",
        &mut out,
    );
    tag(
        "",
        section(
            routers::IDENTITY,
            "pub fn build",
            Some("pub fn build_public"),
        ),
        "identity",
        &mut out,
    );
    tag("/integrator", routers::INTEGRATOR, "integrator", &mut out);
    tag("", routers::RESOLVER, "resolver", &mut out);
    tag("", routers::NODE, "node", &mut out);
    out
}

/// A crate's handler modules **and** its router, because a router may define a
/// handler inline — `dpp-resolver`'s content-negotiation entry point is a
/// private `async fn` in `router.rs`.
fn sources_for(which: &str) -> Vec<&'static str> {
    let (handlers, router) = match which {
        "vault" => (handler_sources::VAULT, routers::VAULT),
        "integrator" => (handler_sources::INTEGRATOR, routers::INTEGRATOR),
        "identity" => (handler_sources::IDENTITY, routers::IDENTITY),
        "resolver" => (handler_sources::RESOLVER, routers::RESOLVER),
        _ => return Vec::new(),
    };
    let mut out = handlers.to_vec();
    out.push(router);
    out
}

/// Every handler a router registers can be read by this gate.
///
/// Without this, `handler_sources` would be an allowlist by omission: forget to
/// add a new module and its routes are silently unchecked, which is the exact
/// shape of hole `every_published_object_shape_has_a_name` exists to prevent one
/// level up.
#[test]
fn every_registered_handler_is_readable() {
    let mut unreadable: Vec<String> = Vec::new();
    for (method, path, handler, which) in surface_handlers() {
        // The node's own router re-mounts sub-routers; its handlers live in the
        // crates already covered, and its two local ones are health checks.
        if which == "node" {
            continue;
        }
        if handler_body(&sources_for(which), &handler).is_none() {
            unreadable.push(format!(
                "{} {path} → {handler}() [{which}]",
                method.to_uppercase()
            ));
        }
    }
    unreadable.sort();
    assert!(
        unreadable.is_empty(),
        "these handlers are registered by a router but their source is not reachable \
         from `handler_sources`:\n  {}\n\n\
         Add the module holding each one to `handler_sources`. Until then nothing \
         checks the status codes those routes document.",
        unreadable.join("\n  ")
    );
}

/// The error codes an operation documents are the ones its handler can return.
///
/// # Why this is a separate check from everything above
///
/// The other gates compare the spec to what `serde` emits, which is ground truth
/// a machine can derive. A status code has no such source: it is chosen by a
/// `match` arm in the handler. This reads those arms.
///
/// # What it does and does not catch
///
/// It catches a code a handler demonstrably produces that the spec never
/// mentions. That direction is sound: the token `conflict_error(` in a body
/// means `409` is reachable, full stop.
///
/// It deliberately does **not** check the reverse — a documented code no handler
/// appears to produce. That reading requires proving absence, and a handler can
/// delegate: the resolver's content-negotiation entry point dispatches to three
/// others, and `validate_handler` returns whatever the create path returns.
/// Scanning one body cannot see through a call, so the reverse direction
/// reported four resolver routes and `POST /dpp/validate` as documenting codes
/// they in fact return. A gate that cries wolf gets deleted, and following calls
/// to fix it would mean writing a call-graph analysis this test has no business
/// containing.
///
/// It does **not** catch a code documented with the wrong *meaning*, which is a
/// different defect and the one that actually shipped: three transfer routes
/// documented `404` as "no pending transfer", while that condition returns `422`
/// and `404` means "no transfer chain at all". The code was right; the sentence
/// beside it described the other branch. Nothing mechanical can check prose
/// against behaviour — only a test that constructs the condition and asserts the
/// status, which is what the smoke tests now do for the routes where the
/// distinction carries weight.
///
/// So this closes the adjacent class, and the convention in CLAUDE.md covers the
/// one it cannot reach. Neither alone is enough.
#[test]
fn documented_error_codes_are_the_ones_handlers_return() {
    let spec = spec();
    let mut failures: Vec<String> = Vec::new();

    for (method, path, handler, which) in surface_handlers() {
        if which == "node" {
            continue;
        }
        // Only operations the description actually carries; route coverage is
        // `every_route_is_documented_and_every_documented_path_exists`'s job.
        if spec["paths"][&path][&method].is_null() {
            continue;
        }
        let Some(body) = handler_body(&sources_for(which), &handler) else {
            continue; // reported by `every_registered_handler_is_readable`
        };

        let emitted = codes_emitted_by(body);
        let documented = documented_error_codes(&spec, &method, &path);
        let op = format!("{} {path}", method.to_uppercase());

        let undocumented: Vec<String> = emitted
            .difference(&documented)
            .map(u64::to_string)
            .collect();

        if !undocumented.is_empty() {
            failures.push(format!(
                "{op}: {handler}() returns {}, which the spec does not document",
                undocumented.join(", ")
            ));
        }
    }

    failures.sort();
    assert!(
        failures.is_empty(),
        "documented error codes disagree with the handlers that serve them:\n  {}\n\n\
         Fix the `responses:` block under api/paths/ (then `just openapi-bundle`), or \
         the handler. `401` and `500` are deliberately not gated — see \
         `CODES_NOT_GATED`.",
        failures.join("\n  ")
    );
}

// ── Fixtures ───────────────────────────────────────────────────────────────
//
// Every struct literal here is exhaustive on purpose — see the module docs. Do
// not reach for `..Default::default()`: it would let a new field slip past this
// gate without a compile error, which is the whole failure mode being closed.

mod fixtures {
    use super::*;

    use dpp_common::{
        http_problem::{Problem, ProblemFieldError},
        plugin_admin::InstalledPlugin,
        ruleset_admin::RulesetReload,
        scan::{QrRenderBatchEntry, ScanBatch, ScanBatchEntry, ScanVariant},
    };
    use dpp_domain::{
        compliance::{ComplianceFinding, ComplianceResult, ComplianceStatus},
        eol::{DeactivationReason, DerogationRef},
        identifier::commodity_code::CommodityCode,
        lint::{LintFinding, LintResult, LintSeverity},
        passport::{
            FacilitySnapshot, ManufacturerInfo, MaterialEntry, Passport, PassportId, PassportRef,
        },
        product_group::{
            CarbonFootprint, CarbonFootprintClass, LifecycleStage, ProductGroup, RepairCriterion,
            RepairabilityScore, SystemBoundary,
        },
        seal::{SealFormat, SealedEnvelope},
        status::PassportStatus,
        transfer::{
            OperatorRole, ResponsibleOperator, TransferChain, TransferReason, TransferRecord,
        },
    };
    use dpp_integrator::handlers::product_groups::{
        InstrumentRefView, ObligationDateView, PassportObligationView, ProductGroupObligation,
        ProductGroupObligationList, RetentionView,
    };
    use dpp_types::{
        api_key::{ApiKey, ApiKeyScope, CreateApiKeyRequest, CreatedApiKeyResponse},
        audit::PassportAuditEntry,
        evidence::{
            CheckResult, CheckStatus, DossierManifest, DossierV1, EvidenceDossierRecord,
            EvidenceDossierSummary, SignedLayer, VerificationReport,
        },
        operator::{OperatorConfig, UpdateOperatorConfig},
        registry_identity::{
            CreateFacilityRequest, CreateOperatorIdentifierRequest, Facility, OperatorIdentifier,
            RegistryIdentityAuditEntry,
        },
        scan::{DailyScanCount, OperatorScanStats, PassportScanStats},
        trust::{NodeProfile, NodeTrustReport, TrustMode, TrustPort},
        webhook::{CreateWebhookRequest, WebhookSubscription},
    };

    use dpp_identity_service::handlers::{
        rotate_key::{InternalRotateKeyRequest, InternalRotateKeyResponse},
        sign::{InternalSignRequest, InternalSignResponse},
        verify::{InternalVerifyRequest, InternalVerifyResponse},
    };
    use dpp_integrator::handlers::{
        import::{AsyncImportResponse, CreatedEntry, ErrorEntry, SyncImportResponse, UpdatedEntry},
        job_status::{JobProgress, JobStatusResponse},
    };
    use dpp_vault::{
        domain::verify::{NodeReport, RefUnverifiable, TreeReport},
        handlers::{
            create::CreatePassportRequest,
            eol::EolRequest,
            info::VaultInfo,
            list::PassportListResponse,
            node_state::NodeState,
            registry_status::{
                CurrentOperatorView, PassportRegistryView, RegistrationCounts, RegistrationView,
                RegistryRollupView, RegistryVerificationView, TransferNotificationCounts,
                TransferNotificationView,
            },
            seal::{SealCoverage, SealDeclarer, SealResponse, SealSummaryResponse},
            suspend::SuspendRequest,
            transfer::TransferInitiateRequest,
            validate::ValidateResponse,
            webhooks::CreatedWebhookResponse,
            whoami::WhoamiResponse,
        },
    };

    // ── dpp-core ──────────────────────────────────────────────────────────

    pub fn manufacturer() -> ManufacturerInfo {
        ManufacturerInfo {
            name: "Nordwerk GmbH".into(),
            address: "Hauptstrasse 1, 10115 Berlin, DE".into(),
            did_web_url: Some("did:web:nordwerk.example".into()),
        }
    }

    pub fn material() -> MaterialEntry {
        MaterialEntry {
            name: "Lithium carbonate".into(),
            weight_kg: 12.5,
            recycled_pct: Some(35.0),
            country_of_origin: Some("DE".into()),
        }
    }

    pub fn passport_ref() -> PassportRef {
        PassportRef {
            uri: "https://id.example/dpp/019723f4-1a2b-7c3d-8e4f-5a6b7c8d9e0f".into(),
            public_jws_hash: "b1946ac92492d2347c6235b4d2611184".into(),
        }
    }

    pub fn facility_snapshot() -> FacilitySnapshot {
        FacilitySnapshot {
            scheme: "gln".into(),
            value: "4012345000009".into(),
            name: "Werk Nord".into(),
            country: "DE".into(),
            address: Some("Werkstrasse 4, 21079 Hamburg, DE".into()),
        }
    }

    pub fn derogation_ref() -> DerogationRef {
        DerogationRef {
            category: "safety".into(),
            act_citation: Some("Regulation (EU) 2024/1781, Art. 25(3)".into()),
        }
    }

    pub fn all_deactivation_reasons() -> Vec<DeactivationReason> {
        vec![
            DeactivationReason::Recycled,
            DeactivationReason::Destroyed {
                derogation: derogation_ref(),
            },
            DeactivationReason::Exported,
            DeactivationReason::Lost,
        ]
    }

    pub fn responsible_operator() -> ResponsibleOperator {
        ResponsibleOperator {
            did: "did:web:nordwerk.example".into(),
            name: "Nordwerk GmbH".into(),
            role: OperatorRole::Manufacturer,
            eu_operator_id: Some("DE123456789".into()),
            eu_operator_id_scheme: Some("eori".into()),
            country: "DE".into(),
        }
    }

    pub fn transfer_record() -> TransferRecord {
        TransferRecord {
            transfer_id: uuid(),
            passport_id: PassportId::new(),
            from_operator: responsible_operator(),
            to_operator: responsible_operator(),
            reason: TransferReason::Sale,
            from_signature: Some("eyJhbGciOiJFZERTQSJ9..aaa".into()),
            node_acceptance_attestation: Some("eyJhbGciOiJFZERTQSJ9..bbb".into()),
            initiated_at: ts(),
            completed_at: Some(ts()),
            rejected_at: Some(ts()),
            cancelled_at: Some(ts()),
            notes: Some("Sold to distributor".into()),
        }
    }

    pub fn all_passport_statuses() -> Vec<PassportStatus> {
        vec![
            PassportStatus::Draft,
            PassportStatus::Published,
            PassportStatus::Suspended,
            PassportStatus::Archived,
            PassportStatus::Superseded,
            PassportStatus::Deactivated,
        ]
    }

    pub fn all_operator_roles() -> Vec<OperatorRole> {
        vec![
            OperatorRole::Manufacturer,
            OperatorRole::Importer,
            OperatorRole::Distributor,
            OperatorRole::AuthorisedRepresentative,
            OperatorRole::Remanufacturer,
            OperatorRole::Repurposer,
            OperatorRole::PreparerForReuse,
            OperatorRole::Repairer,
            OperatorRole::Recycler,
        ]
    }

    pub fn all_transfer_reasons() -> Vec<TransferReason> {
        vec![
            TransferReason::Sale,
            TransferReason::Return,
            TransferReason::Remanufacturing,
            TransferReason::Repurposing,
            TransferReason::PreparationForReuse,
            TransferReason::Import,
            TransferReason::InsolvencySuccession,
        ]
    }

    pub fn carbon_footprint() -> CarbonFootprint {
        CarbonFootprint {
            value_kg: 45.2,
            lifecycle_stage: Some(LifecycleStage::CradleToGate),
            system_boundary: Some(SystemBoundary::En15804),
            methodology_ref: Some("EN 15804:2012+A2:2019".into()),
            performance_class: Some(CarbonFootprintClass::new("B").expect("valid class label")),
        }
    }

    pub fn repair_criterion() -> RepairCriterion {
        RepairCriterion {
            name: "disassembly_depth".into(),
            score: 8.0,
            weight: 0.4,
        }
    }

    pub fn repairability_score() -> RepairabilityScore {
        RepairabilityScore {
            overall: 7.5,
            criteria: vec![repair_criterion()],
        }
    }

    pub fn compliance_finding() -> ComplianceFinding {
        ComplianceFinding::new(
            "battery.recycled_content.cobalt_below_2031",
            "/recycledContentCobaltPct",
            "below the 2031 threshold",
        )
    }

    pub fn lint_finding() -> LintFinding {
        LintFinding {
            code: "mass.balance".into(),
            field: "/materials".into(),
            severity: LintSeverity::Warning,
            message: "material mass exceeds product mass".into(),
        }
    }

    pub fn all_api_key_scopes() -> Vec<ApiKeyScope> {
        vec![ApiKeyScope::Read, ApiKeyScope::Write, ApiKeyScope::Admin]
    }

    pub fn all_compliance_statuses() -> Vec<ComplianceStatus> {
        vec![
            ComplianceStatus::PassthroughNoValidation,
            ComplianceStatus::Compliant,
            ComplianceStatus::NonCompliant,
            ComplianceStatus::NotAssessed,
            ComplianceStatus::NotImplemented,
        ]
    }

    pub fn all_lint_severities() -> Vec<LintSeverity> {
        vec![LintSeverity::Warning, LintSeverity::Notice]
    }

    pub fn all_seal_formats() -> Vec<SealFormat> {
        SealFormat::ALL.to_vec()
    }

    pub fn compliance_result() -> ComplianceResult {
        ComplianceResult {
            co2e_score: Some(45.2),
            repairability_index: Some(7.5),
            recycled_content_pct: Some(35.0),
            compliance_status: ComplianceStatus::PassthroughNoValidation,
            violations: vec![compliance_finding()],
            warnings: vec![compliance_finding()],
            ruleset_version: Some("2026.1.0".into()),
            assessed_at: Some(ts()),
            receipt: Some(json!({ "inputHash": "abc" })),
        }
    }

    pub fn lint_result() -> LintResult {
        LintResult {
            pack_version: "1.0.0".into(),
            findings: vec![lint_finding()],
            assessed_at: ts(),
        }
    }

    pub fn sealed_envelope() -> SealedEnvelope {
        SealedEnvelope {
            format: SealFormat::Cades,
            seal_value: "MIIB...".into(),
            signing_cert_ref: Some("urn:cert:1".into()),
            sealed_at: ts(),
            placeholder: false,
        }
    }

    /// A `Passport` with every optional field populated, so the serialised form
    /// carries every key the type is capable of emitting.
    pub fn passport() -> Passport {
        let mut disclosure_signatures = BTreeMap::new();
        disclosure_signatures.insert(
            "public+restricted".to_owned(),
            "eyJhbGciOiJFZERTQSJ9..ccc".to_owned(),
        );

        Passport {
            id: PassportId::new(),
            batch_id: Some("LOT-2026-001".into()),
            product_name: "EcoCell Pro 48V".into(),
            product_group: ProductGroup::Textile,
            // Both must be *populated*, not defaulted: each is
            // `skip_serializing_if`, so an empty vec or a `None` emits nothing,
            // the fixture stops exercising the field, and the spec is never
            // asked to document it. A field that serialises away is a field this
            // gate cannot see.
            applicable_instruments: vec![dpp_domain::InstrumentRef::from_catalog("espr")],
            granularity: Some(dpp_domain::Granularity::Item),
            manufacturer: manufacturer(),
            materials: vec![material()],
            co2e_per_unit: Some(CarbonFootprint::from_kg(45.2)),
            repairability_score: Some(RepairabilityScore::from_scalar(7.5)),
            compliance_result: Some(compliance_result()),
            lint_result: Some(lint_result()),
            product_group_data: None,
            status: PassportStatus::Published,
            qr_code_url: Some("https://id.example/01/09506000134352/21/ABC".into()),
            jws_signature: Some("eyJhbGciOiJFZERTQSJ9..ddd".into()),
            public_jws_signature: Some("eyJhbGciOiJFZERTQSJ9..eee".into()),
            disclosure_signatures,
            created_at: ts(),
            updated_at: ts(),
            published_at: Some(ts()),
            placed_on_market_date: Some(date()),
            schema_version: "1.0.0".into(),
            retention_locked: true,
            version: 2,
            supersedes_id: Some(PassportId::new()),
            parent_passport_ref: Some(passport_ref()),
            component_refs: vec![passport_ref()],
            retention_until: Some(ts()),
            product_id: Some(uuid()),
            commodity_code: Some(CommodityCode::parse("85076000").expect("valid CN-8")),
            operator_identifier: Some("DE123456789".into()),
            facility: Some(facility_snapshot()),
            seal: Some(sealed_envelope()),
        }
    }

    // ── dpp-types ─────────────────────────────────────────────────────────

    pub fn api_key() -> ApiKey {
        ApiKey {
            id: uuid(),
            name: "CI pipeline".into(),
            key_prefix: "odal_sk_abc1".into(),
            is_active: true,
            scope: ApiKeyScope::Admin,
            created_at: ts(),
            last_used_at: Some(ts()),
            expires_at: Some(ts()),
        }
    }

    pub fn new_api_key() -> CreatedApiKeyResponse {
        CreatedApiKeyResponse {
            key: api_key(),
            secret: "odal_sk_abc123def456".into(),
        }
    }

    pub fn create_api_key_request() -> CreateApiKeyRequest {
        CreateApiKeyRequest {
            name: "CI pipeline".into(),
            expires_at: Some(ts()),
            scope: Some(ApiKeyScope::Admin),
        }
    }

    pub fn audit_entry() -> PassportAuditEntry {
        PassportAuditEntry {
            id: uuid(),
            passport_id: "019723f4-1a2b-7c3d-8e4f-5a6b7c8d9e0f".into(),
            actor: "admin@example.com".into(),
            action: "published".into(),
            previous_status: Some("draft".into()),
            new_status: Some("active".into()),
            metadata: Some(json!({ "note": "first publish" })),
            timestamp: ts(),
            prev_hash: Some("0".repeat(64)),
            entry_hash: Some("1".repeat(64)),
        }
    }

    pub fn facility() -> Facility {
        Facility {
            id: uuid(),
            name: "Werk Nord".into(),
            identifier_scheme: "gln".into(),
            identifier_value: "4012345000009".into(),
            country: "DE".into(),
            address: Some("Werkstrasse 4, 21079 Hamburg, DE".into()),
            is_default: true,
            created_at: ts(),
        }
    }

    pub fn create_facility_request() -> CreateFacilityRequest {
        CreateFacilityRequest {
            name: "Werk Nord".into(),
            identifier_scheme: "gln".into(),
            identifier_value: "4012345000009".into(),
            country: "DE".into(),
            address: Some("Werkstrasse 4, 21079 Hamburg, DE".into()),
            is_default: true,
        }
    }

    pub fn operator_identifier() -> OperatorIdentifier {
        OperatorIdentifier {
            id: uuid(),
            scheme: "eori".into(),
            value: "DE123456789".into(),
            label: Some("Primary EORI".into()),
            is_primary: true,
            created_at: ts(),
        }
    }

    pub fn create_operator_identifier_request() -> CreateOperatorIdentifierRequest {
        CreateOperatorIdentifierRequest {
            scheme: "eori".into(),
            value: "DE123456789".into(),
            label: Some("Primary EORI".into()),
            is_primary: true,
        }
    }

    pub fn registry_identity_audit() -> RegistryIdentityAuditEntry {
        RegistryIdentityAuditEntry {
            id: uuid(),
            operator_id: "standalone".into(),
            entity_type: "facility".into(),
            entity_id: uuid(),
            action: "created".into(),
            actor: "admin@example.com".into(),
            snapshot: Some(json!({ "name": "Werk Nord" })),
            ts: ts(),
        }
    }

    pub fn operator_config() -> OperatorConfig {
        OperatorConfig {
            operator_id: "standalone".into(),
            legal_name: "Nordwerk GmbH".into(),
            trade_name: Some("Nordwerk".into()),
            address: "Hauptstrasse 1, 10115 Berlin, DE".into(),
            country: "DE".into(),
            contact_email: "compliance@nordwerk.example".into(),
            did_web_url: Some("did:web:nordwerk.example".into()),
            product_categories: Some(vec!["battery".into()]),
            brand_primary: Some("#0A5".into()),
            brand_secondary: Some("#083".into()),
            brand_logo_url: Some("https://nordwerk.example/logo.svg".into()),
            custom_domain: Some("dpp.nordwerk.example".into()),
            data_residency: "eu".into(),
            retention_policy_days: 3650,
            feature_flags: Some(json!({ "passthroughCompliance": true })),
            registry_verified_at: Some(ts()),
            created_at: Some(ts()),
            updated_at: Some(ts()),
        }
    }

    pub fn update_operator_config() -> UpdateOperatorConfig {
        UpdateOperatorConfig {
            legal_name: Some("Nordwerk GmbH".into()),
            trade_name: Some("Nordwerk".into()),
            address: Some("Hauptstrasse 1, 10115 Berlin, DE".into()),
            country: Some("DE".into()),
            contact_email: Some("compliance@nordwerk.example".into()),
            did_web_url: Some("did:web:nordwerk.example".into()),
            product_categories: Some(vec!["battery".into()]),
            brand_primary: Some("#0A5".into()),
            brand_secondary: Some("#083".into()),
            brand_logo_url: Some("https://nordwerk.example/logo.svg".into()),
            custom_domain: Some("dpp.nordwerk.example".into()),
            data_residency: Some("eu".into()),
            retention_policy_days: Some(3650),
            feature_flags: Some(json!({ "passthroughCompliance": true })),
            registry_verified_at: Some(ts()),
        }
    }

    // ── Evidence dossier ──────────────────────────────────────────────────

    pub fn signed_layer() -> SignedLayer {
        SignedLayer {
            payload: json!({ "id": "019723f4-1a2b-7c3d-8e4f-5a6b7c8d9e0f" }),
            jws: "eyJhbGciOiJFZERTQSJ9..fff".into(),
        }
    }

    pub fn dossier_manifest() -> DossierManifest {
        let mut content_hashes = BTreeMap::new();
        content_hashes.insert("fullView".to_owned(), "2".repeat(64));
        DossierManifest {
            format_version: "1".into(),
            passport_id: "019723f4-1a2b-7c3d-8e4f-5a6b7c8d9e0f".into(),
            issuer_did: "did:web:node.example".into(),
            created_at: ts(),
            node_version: "0.12.0".into(),
            core_version: "0.18.0".into(),
            ruleset_version: Some("2026.1.0".into()),
            content_hashes,
        }
    }

    pub fn dossier() -> DossierV1 {
        let mut did_documents = BTreeMap::new();
        did_documents.insert(
            "did:web:node.example".to_owned(),
            json!({ "id": "did:web:node.example" }),
        );
        DossierV1 {
            manifest: dossier_manifest(),
            manifest_jws: "eyJhbGciOiJFZERTQSJ9..ggg".into(),
            full_view: signed_layer(),
            public_view: signed_layer(),
            did_documents,
            audit_entries: vec![audit_entry()],
            transfer_chain: Some(TransferChain {
                passport_id: PassportId::new(),
                original_operator: responsible_operator(),
                transfers: vec![transfer_record()],
            }),
            eol_event: Some(json!({ "kind": "recycled" })),
            checkpoint: Some(json!({})),
            calc_receipts: vec![json!({})],
            component_graph: Some(json!({})),
            qualified_seal: Some(json!({})),
        }
    }

    pub fn check_result() -> CheckResult {
        CheckResult {
            name: "audit_chain".into(),
            status: CheckStatus::Fail("hash mismatch at entry 3".into()),
        }
    }

    pub fn verification_report() -> VerificationReport {
        VerificationReport {
            trust_anchor_note: "verified against did:web:node.example".into(),
            checks: vec![check_result()],
        }
    }

    // ── dpp-common ────────────────────────────────────────────────────────

    pub fn problem() -> Problem {
        Problem {
            problem_type: "https://problems.example/validation-error".into(),
            title: "Validation failed".into(),
            status: 422,
            detail: Some("productName must not be empty".into()),
            instance: Some("/vault/api/v1/dpp".into()),
            // Two, not one: the member exists because a validation failure is
            // usually plural, and a single-element fixture would let a spec
            // that typed it as an object rather than an array pass.
            errors: Some(vec![
                problem_field_error(),
                ProblemFieldError {
                    field: "/productGroupData/gtin".into(),
                    message: "check digit is wrong".into(),
                },
            ]),
        }
    }

    pub fn problem_field_error() -> ProblemFieldError {
        ProblemFieldError {
            field: "/productName".into(),
            message: "productName must not be empty".into(),
        }
    }

    pub fn scan_count() -> ScanBatchEntry {
        ScanBatchEntry {
            dpp_id: "019723f4-1a2b-7c3d-8e4f-5a6b7c8d9e0f".into(),
            day: date(),
            variant: ScanVariant::Html,
            count: 42,
        }
    }

    pub fn qr_render_count() -> QrRenderBatchEntry {
        QrRenderBatchEntry {
            dpp_id: "019723f4-1a2b-7c3d-8e4f-5a6b7c8d9e0f".into(),
            day: date(),
            count: 7,
        }
    }

    pub fn scan_batch() -> ScanBatch {
        ScanBatch {
            scans: vec![scan_count()],
            qr_renders: vec![qr_render_count()],
        }
    }

    pub fn all_scan_variants() -> Vec<ScanVariant> {
        vec![ScanVariant::Html, ScanVariant::Json]
    }

    pub fn dossier_record() -> EvidenceDossierRecord {
        EvidenceDossierRecord {
            id: uuid(),
            passport_id: PassportId::new(),
            actor: "admin@example.com".into(),
            created_at: ts(),
            doc_hash: "3".repeat(64),
            dossier: dossier(),
        }
    }

    pub fn dossier_summary() -> EvidenceDossierSummary {
        EvidenceDossierSummary {
            id: uuid(),
            passport_id: PassportId::new(),
            actor: "admin@example.com".into(),
            created_at: ts(),
            doc_hash: "3".repeat(64),
        }
    }

    // ── dpp-vault: request and response bodies ────────────────────────────

    pub fn create_request() -> CreatePassportRequest {
        CreatePassportRequest {
            product_name: "EcoCell Pro 48V".into(),
            product_group: Some(ProductGroup::Textile),
            manufacturer: manufacturer(),
            materials: Some(vec![material()]),
            co2e_per_unit: Some(45.2),
            repairability_score: Some(7.5),
            product_group_data: None,
            batch_id: Some("LOT-2026-001".into()),
            placed_on_market_date: Some(date()),
            schema_version: Some("1.0.0".into()),
            commodity_code: Some("85076000".into()),
            parent_passport_ref: Some(passport_ref()),
            component_refs: vec![passport_ref()],
        }
    }

    pub fn eol_request() -> EolRequest {
        EolRequest {
            reason: DeactivationReason::Recycled,
            declared_by: Some("admin@example.com".into()),
            material_recovery: Some(json!({ "cobaltKg": 1.2 })),
            notes: Some("Sent to certified recycler".into()),
        }
    }

    /// `trust` is a flattened `serde_json::Value` on the response type, but the
    /// value is produced by `NodeTrustReport::posture_json` — so it is built
    /// here through that, not hand-written. A hand-written literal is only ever
    /// a second guess at the shape: this fixture originally carried
    /// `"trustMode": "full"`, a string, while the real posture emits an object
    /// keyed by port. The type check caught it.
    pub fn node_state() -> NodeState {
        let report = NodeTrustReport::new(
            NodeProfile::Production,
            vec![
                TrustPort {
                    port: "seal",
                    mode: TrustMode::Ghost,
                    required: true,
                },
                TrustPort {
                    port: "registry_sync",
                    mode: TrustMode::Sandbox,
                    required: false,
                },
            ],
        );
        NodeState {
            bootstrapped: true,
            operator_complete: true,
            trust: Some(report.posture_json()),
            ruleset_version: Some("2026.1.0".into()),
        }
    }

    pub fn vault_info() -> VaultInfo {
        VaultInfo::current()
    }

    /// `reason` is the only field, and it is `Some` here for the reason every
    /// fixture is maximal: an `Option` left `None` emits nothing and the schema
    /// check would pass by not looking.
    pub fn suspend_request() -> SuspendRequest {
        SuspendRequest {
            reason: Some("Product recall — safety investigation pending".into()),
        }
    }

    pub fn transfer_initiate_request() -> TransferInitiateRequest {
        TransferInitiateRequest {
            from_operator: responsible_operator(),
            to_operator: responsible_operator(),
            reason: TransferReason::Sale,
            notes: Some("Sold to distributor".into()),
        }
    }

    pub fn tree_node_report() -> NodeReport {
        NodeReport {
            path: vec!["root".into(), "cell".into()],
            verified: false,
            reason: Some(RefUnverifiable::HashMismatch),
        }
    }

    pub fn tree_report() -> TreeReport {
        TreeReport {
            verified: false,
            nodes: vec![tree_node_report()],
        }
    }

    // ── dpp-identity ──────────────────────────────────────────────────────

    pub fn sign_request() -> InternalSignRequest {
        InternalSignRequest {
            operator_id: "standalone".into(),
            passport_id: "019723f4-1a2b-7c3d-8e4f-5a6b7c8d9e0f".into(),
            payload: "eyJpZCI6IngifQ==".into(),
        }
    }

    pub fn sign_response() -> InternalSignResponse {
        InternalSignResponse {
            jws_signature: "eyJhbGciOiJFZERTQSJ9..hhh".into(),
        }
    }

    pub fn verify_request() -> InternalVerifyRequest {
        InternalVerifyRequest {
            operator_id: "standalone".into(),
            jws: "eyJhbGciOiJFZERTQSJ9..hhh".into(),
            payload: json!({ "id": "x" }),
        }
    }

    pub fn verify_response() -> InternalVerifyResponse {
        InternalVerifyResponse { valid: true }
    }

    pub fn rotate_request() -> InternalRotateKeyRequest {
        InternalRotateKeyRequest {
            operator_id: "standalone".into(),
        }
    }

    pub fn rotate_response() -> InternalRotateKeyResponse {
        InternalRotateKeyResponse {
            operator_id: "standalone".into(),
            new_key_id: "did:web:node.example#key-1".into(),
            fingerprint: "4".repeat(64),
            rotated: true,
            did_document: json!({ "id": "did:web:node.example" }),
        }
    }

    // ── dpp-integrator ────────────────────────────────────────────────────

    // ── dpp-vault: read and telemetry responses ───────────────────────────

    /// The smallest body `validate_create_request` accepts — only the two
    /// genuinely required fields. Used to probe one constraint at a time
    /// without another field's rule deciding the outcome.
    ///
    /// Deliberately *not* the maximal `create_request()` fixture: that one sets
    /// every field, so a rejection could come from any of them and the probe
    /// would be measuring the wrong rule.
    pub fn minimal_create_request() -> CreatePassportRequest {
        CreatePassportRequest {
            product_name: "EcoCell Pro 48V".into(),
            product_group: None,
            manufacturer: manufacturer(),
            materials: None,
            co2e_per_unit: None,
            repairability_score: None,
            product_group_data: None,
            batch_id: None,
            placed_on_market_date: None,
            schema_version: None,
            commodity_code: None,
            parent_passport_ref: None,
            component_refs: Vec::new(),
        }
    }

    pub fn validate_response() -> ValidateResponse {
        ValidateResponse {
            create_valid: true,
            product_group_data_valid: false,
            detail: Some("no registered JSON Schema for product_group 'furniture'".into()),
        }
    }

    pub fn passport_list_response() -> PassportListResponse {
        PassportListResponse {
            dpps: vec![dpp_vault::api::PassportResponse::from(&passport())],
            total: 42,
            limit: 20,
            skip: 0,
        }
    }

    pub fn whoami_response() -> WhoamiResponse {
        WhoamiResponse {
            user_id: "ci-pipeline".into(),
            scope: ApiKeyScope::Admin,
            key_id: Some(uuid()),
        }
    }

    pub fn daily_scan_count() -> DailyScanCount {
        DailyScanCount {
            day: date(),
            count: 12,
        }
    }

    pub fn passport_scan_stats() -> PassportScanStats {
        PassportScanStats {
            window_days: 30,
            total_scans: 128,
            scans_html: 96,
            scans_json: 32,
            daily: vec![daily_scan_count()],
            qr_renders: 4,
        }
    }

    pub fn operator_scan_stats() -> OperatorScanStats {
        OperatorScanStats {
            window_days: 30,
            total_scans: 1024,
            total_qr_renders: 64,
            distinct_passports_scanned: 12,
        }
    }

    pub fn seal_declarer() -> SealDeclarer {
        SealDeclarer {
            manufacturer: "TestCorp GmbH".into(),
            operator_identifier: Some("LEI:529900T8BM49AURSDO55".into()),
            responsibility_may_have_transferred: true,
            // A `&'static str` constant on the type, like `verification` below;
            // the fixture needs a value of the right shape for the key set.
            note: "the seal attests to the sender, not the author",
        }
    }

    pub fn seal_response() -> SealResponse {
        SealResponse {
            declared_by: seal_declarer(),
            format: "CADES".into(),
            seal_value: "MIIB...".into(),
            sealed_at: ts(),
            signing_cert_ref: Some("5".repeat(64)),
            placeholder: false,
            current_jws: "eyJhbGciOiJFZERTQSJ9..iii".into(),
            current_payload_hash: "6".repeat(64),
            sealed_payload_hash: Some("6".repeat(64)),
            coverage: SealCoverage::Current,
            // A `&'static str` constant on the response type; the fixture only
            // needs a value of the right shape for the key set.
            verification: "not validated by this node",
        }
    }

    pub fn seal_summary_response() -> SealSummaryResponse {
        SealSummaryResponse {
            unsealed_published: 0,
            pending: 2,
            sealed: 40,
            exhausted: 0,
            sealing_configured: true,
        }
    }

    pub fn all_coverages() -> Vec<SealCoverage> {
        vec![
            SealCoverage::Current,
            SealCoverage::Superseded,
            SealCoverage::Unknown,
        ]
    }

    pub fn all_date_bases() -> Vec<dpp_domain::instrument::DateBasis> {
        use dpp_domain::instrument::DateBasis;
        vec![DateBasis::Sourced, DateBasis::Assumed]
    }

    pub fn all_retention_bases() -> Vec<dpp_domain::catalog::RetentionBasis> {
        use dpp_domain::catalog::RetentionBasis;
        vec![RetentionBasis::Sourced, RetentionBasis::Assumed]
    }

    pub fn all_granularities() -> Vec<dpp_domain::catalog::Granularity> {
        use dpp_domain::catalog::Granularity;
        vec![Granularity::Model, Granularity::Batch, Granularity::Item]
    }

    pub fn all_recorded_bases() -> Vec<dpp_domain::instrument::RecordedBasis> {
        use dpp_domain::instrument::RecordedBasis;
        vec![RecordedBasis::Catalog, RecordedBasis::Operator]
    }

    // ── Query structs ──────────────────────────────────────────────────────
    //
    // Every `Option` is `Some` for the same reason the object fixtures populate
    // theirs: a `None` under `skip_serializing_if` emits no key, and the check
    // would pass by not looking. None of these carry that attribute today, so a
    // new field appears in the wire keys either way — but that is a property of
    // the structs as they happen to be written, not a guarantee, and these
    // literals are exhaustive so a new field fails to compile here first.

    pub fn list_query() -> dpp_vault::handlers::list::ListQuery {
        use dpp_domain::PassportStatus;
        dpp_vault::handlers::list::ListQuery {
            status: Some(PassportStatus::Published),
            q: Some("kettle".into()),
            facility_id: Some("4012345000009".into()),
            limit: Some(20),
            skip: Some(0),
        }
    }

    pub fn identity_query() -> dpp_vault::handlers::find_by_identity::IdentityQuery {
        use dpp_domain::product_group::ProductGroup;
        dpp_vault::handlers::find_by_identity::IdentityQuery {
            product_group: ProductGroup::Battery,
            gtin: "04012345000009".into(),
            batch_id: Some("BATCH-2026-04-001".into()),
        }
    }

    pub fn stats_query() -> dpp_vault::handlers::stats::StatsQuery {
        dpp_vault::handlers::stats::StatsQuery { days: Some(30) }
    }

    pub fn public_read_query() -> dpp_vault::handlers::public_read::PublicReadQuery {
        dpp_vault::handlers::public_read::PublicReadQuery {
            schema_view: Some("battery".into()),
        }
    }

    pub fn template_query() -> dpp_integrator::handlers::templates::TemplateQuery {
        dpp_integrator::handlers::templates::TemplateQuery {
            format: Some("csv".into()),
        }
    }

    pub fn by_gtin_query() -> dpp_resolver::handlers::resolve_by_gtin::ByGtinQuery {
        dpp_resolver::handlers::resolve_by_gtin::ByGtinQuery {
            link_type: Some("linkset".into()),
        }
    }

    pub fn all_instrument_statuses() -> Vec<dpp_domain::instrument::InstrumentStatus> {
        use dpp_domain::instrument::InstrumentStatus;
        vec![
            InstrumentStatus::Adopted,
            InstrumentStatus::Proposed,
            InstrumentStatus::Anticipated,
        ]
    }

    pub fn all_regulatory_statuses() -> Vec<dpp_domain::catalog::RegulatoryStatus> {
        use dpp_domain::catalog::RegulatoryStatus;
        vec![
            RegulatoryStatus::InForce,
            RegulatoryStatus::Provisional,
            RegulatoryStatus::Watch,
        ]
    }

    /// A fully populated obligation — every optional field present, so the
    /// contract gate sees the whole key set. A fixture that left `from`,
    /// `granularity` or `retention` as `None` would still serialise the keys
    /// (they are not `skip_serializing_if`), but populating them keeps the
    /// fixture honest about what the endpoint can return.
    pub fn instrument_ref() -> dpp_domain::instrument::InstrumentRef {
        use dpp_domain::instrument::{InstrumentRef, RecordedBasis};
        InstrumentRef {
            instrument: "battery-reg-2023-1542".into(),
            recorded: RecordedBasis::Catalog,
        }
    }

    pub fn job_progress() -> dpp_integrator::handlers::job_status::JobProgress {
        dpp_integrator::handlers::job_status::JobProgress {
            processed: 120,
            total: 500,
        }
    }

    pub fn obligation_date() -> ObligationDateView {
        use dpp_domain::instrument::DateBasis;
        ObligationDateView {
            date: "2030-08-01".into(),
            basis: DateBasis::Sourced,
        }
    }

    pub fn passport_obligation() -> PassportObligationView {
        PassportObligationView {
            required: true,
            from: Some(obligation_date()),
        }
    }

    pub fn retention_period() -> RetentionView {
        use dpp_domain::catalog::RetentionBasis;
        RetentionView {
            years: 10,
            basis: RetentionBasis::Sourced,
        }
    }

    pub fn reaching_instrument() -> InstrumentRefView {
        use dpp_domain::catalog::RegulatoryStatus;
        use dpp_domain::instrument::{InstrumentStatus, RecordedBasis};
        InstrumentRefView {
            instrument: "toy-safety-2025-2509".into(),
            recorded: RecordedBasis::Catalog,
            instrument_status: InstrumentStatus::Adopted,
            binding_status: RegulatoryStatus::Provisional,
        }
    }

    pub fn product_group_obligation() -> ProductGroupObligation {
        use dpp_domain::catalog::Granularity;

        ProductGroupObligation {
            product_group: "toy".into(),
            title: Some("Toys".into()),
            passport: passport_obligation(),
            determinable: false,
            granularity: Some(Granularity::Model),
            retention: Some(retention_period()),
            instruments: vec![reaching_instrument()],
        }
    }

    pub fn product_group_obligation_list() -> ProductGroupObligationList {
        ProductGroupObligationList {
            product_groups: vec![product_group_obligation()],
        }
    }

    pub fn installed_plugin() -> InstalledPlugin {
        InstalledPlugin {
            product_group: "battery".into(),
            abi_version: "1.0".into(),
        }
    }

    pub fn ruleset_reload() -> RulesetReload {
        RulesetReload {
            ruleset_version: "2026-Q3.2".into(),
            changed: true,
        }
    }

    pub fn webhook_subscription() -> WebhookSubscription {
        WebhookSubscription {
            id: uuid(),
            url: "https://hooks.example.com/odal".into(),
            events: vec!["dpp.passport.published".into()],
            active: true,
            description: Some("Production receiver".into()),
            created_at: ts(),
            updated_at: ts(),
        }
    }

    pub fn new_webhook_subscription() -> CreateWebhookRequest {
        CreateWebhookRequest {
            url: "https://hooks.example.com/odal".into(),
            events: vec!["dpp.passport.published".into()],
            description: Some("Production receiver".into()),
        }
    }

    pub fn created_webhook_response() -> CreatedWebhookResponse {
        CreatedWebhookResponse {
            subscription: webhook_subscription(),
            secret: "whsec_abc123".into(),
        }
    }

    // ── dpp-vault: EU-registry state ──────────────────────────────────────

    pub fn registration_view() -> RegistrationView {
        RegistrationView {
            status: "submitted",
            registry_id: Some("EUDPP-2026-0001".into()),
            message: Some("accepted for processing".into()),
            attempts: 2,
            stalled: false,
            status_intent: Some("deactivated"),
        }
    }

    pub fn transfer_view() -> TransferNotificationView {
        TransferNotificationView {
            transfer_id: uuid(),
            status: "notified",
            registry_id: Some("EUDPP-T-0001".into()),
            message: Some("acknowledged".into()),
            attempts: 1,
            stalled: false,
        }
    }

    pub fn current_operator_view() -> CurrentOperatorView {
        CurrentOperatorView {
            did: "did:web:nordwerk.example".into(),
            name: "Nordwerk GmbH".into(),
            country: "DE".into(),
            transfer_count: 1,
        }
    }

    pub fn passport_registry_view() -> PassportRegistryView {
        PassportRegistryView {
            passport_id: "019723f4-1a2b-7c3d-8e4f-5a6b7c8d9e0f".into(),
            configured: true,
            registration: Some(registration_view()),
            transfers: vec![transfer_view()],
            current_operator: Some(current_operator_view()),
        }
    }

    pub fn verification_view() -> RegistryVerificationView {
        RegistryVerificationView {
            current: true,
            verified_at: Some(ts()),
            expires_at: Some(ts()),
            days_remaining: Some(365),
        }
    }

    pub fn registration_counts() -> RegistrationCounts {
        RegistrationCounts {
            pending: 1,
            submitted: 2,
            registered: 3,
            rejected: 0,
            deactivated: 0,
            status_intents: 1,
            stalled: 0,
            unregistered_published: 0,
        }
    }

    pub fn transfer_counts() -> TransferNotificationCounts {
        TransferNotificationCounts {
            pending: 1,
            notified: 2,
            rejected: 0,
            stalled: 0,
        }
    }

    pub fn registry_rollup_view() -> RegistryRollupView {
        RegistryRollupView {
            configured: true,
            verification: verification_view(),
            registrations: Some(registration_counts()),
            transfers: Some(transfer_counts()),
        }
    }

    pub fn import_updated_entry() -> UpdatedEntry {
        UpdatedEntry {
            row: 4,
            passport_id: "019723f4-1a2b-7c3d-8e4f-5a6b7c8d9e0f".into(),
        }
    }

    pub fn import_created_entry() -> CreatedEntry {
        CreatedEntry {
            row: 2,
            passport_id: "019723f4-1a2b-7c3d-8e4f-5a6b7c8d9e0f".into(),
            status: "draft".into(),
        }
    }

    pub fn import_error_entry() -> ErrorEntry {
        ErrorEntry {
            row: 3,
            field: "productName".into(),
            message: "must not be empty".into(),
        }
    }

    pub fn import_sync_response() -> SyncImportResponse {
        SyncImportResponse {
            job_id: uuid().to_string(),
            total_rows: 3,
            success_count: 2,
            error_count: 1,
            created: vec![import_created_entry()],
            updated: vec![import_updated_entry()],
            errors: vec![import_error_entry()],
        }
    }

    pub fn import_async_response() -> AsyncImportResponse {
        AsyncImportResponse {
            job_id: uuid().to_string(),
            status: "queued".into(),
            total_rows: 500,
        }
    }

    pub fn job_status_response() -> JobStatusResponse {
        JobStatusResponse {
            job_id: uuid(),
            status: "completed".into(),
            progress: JobProgress {
                processed: 3,
                total: 3,
            },
            result: json!({ "created": [] }),
            report: json!({ "rows": [] }),
        }
    }
}
