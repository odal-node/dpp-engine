//! The OpenAPI description is checked against the code that implements it.
//!
//! `api/` is hand-authored. Before this test the only gate on it was
//! `just openapi-check`, which bundles the tree and runs Redocly's linter —
//! both of which read *only* the spec. Nothing opened a `.rs` file, so a field
//! added to a struct, a variant added to an enum, or a route added to a router
//! never made the spec fail. Drift was not a risk being managed; it was
//! guaranteed, and it accumulated (see `docs/` for the audit that found it).
//!
//! Three things are checked, and every one of them fails loudly rather than
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
//! 3. **Route coverage** — the paths in the spec equal the routes actually
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
        "ProductGroupData",
        "deliberately open (`additionalProperties: true`, discriminated by \
         `product_group`). The per-product-group payloads are described by the versioned JSON \
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
    case!(
        "ProductGroupObligation",
        fixtures::product_group_obligation()
    );
    case!(
        "ProductGroupObligationList",
        fixtures::product_group_obligation_list()
    );
    case!("LintFinding", fixtures::lint_finding());
    case!("SealedEnvelope", fixtures::sealed_envelope());
    case!("ResponsibleOperator", fixtures::responsible_operator());
    case!("TransferRecord", fixtures::transfer_record());

    // ── dpp-types: platform records ───────────────────────────────────────
    case!("ApiKey", fixtures::api_key());
    case!("NewApiKey", fixtures::new_api_key());
    case!("CreateApiKeyRequest", fixtures::create_api_key_request());
    case!("AuditEntry", fixtures::audit_entry());
    case!("Facility", fixtures::facility());
    case!("CreateFacilityRequest", fixtures::create_facility_request());
    case!("OperatorIdentifier", fixtures::operator_identifier());
    case!(
        "CreateOperatorIdentifierRequest",
        fixtures::create_operator_identifier_request()
    );
    case!("RegistryIdentityAudit", fixtures::registry_identity_audit());
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
    case!("ScanBatch", fixtures::scan_batch());
    case!("ScanCount", fixtures::scan_count());
    case!("QrRenderCount", fixtures::qr_render_count());

    // ── dpp-vault: request and response bodies ────────────────────────────
    case!("CreateRequest", fixtures::create_request());
    case!("ValidateResponse", fixtures::validate_response());
    case!("PassportListResponse", fixtures::passport_list_response());
    case!("WhoamiResponse", fixtures::whoami_response());
    case!("PassportScanStats", fixtures::passport_scan_stats());
    case!("OperatorScanStats", fixtures::operator_scan_stats());
    case!("DailyScanCount", fixtures::daily_scan_count());
    case!("SealResponse", fixtures::seal_response());
    case!("SealSummaryResponse", fixtures::seal_summary_response());
    case!("InstalledPlugin", fixtures::installed_plugin());
    case!("WebhookSubscription", fixtures::webhook_subscription());
    case!(
        "NewWebhookSubscription",
        fixtures::new_webhook_subscription()
    );
    case!(
        "CreatedWebhookResponse",
        fixtures::created_webhook_response()
    );
    case!("EolRequest", fixtures::eol_request());
    case!("NodeState", fixtures::node_state());
    case!("VaultInfo", fixtures::vault_info());
    case!(
        "TransferInitiateRequest",
        fixtures::transfer_initiate_request()
    );
    case!("TreeReport", fixtures::tree_report());
    case!("TreeNodeReport", fixtures::tree_node_report());
    case!("RegistrationView", fixtures::registration_view());
    case!("TransferView", fixtures::transfer_view());
    case!("CurrentOperatorView", fixtures::current_operator_view());
    case!("PassportRegistryView", fixtures::passport_registry_view());
    case!("VerificationView", fixtures::verification_view());
    case!("RegistrationCounts", fixtures::registration_counts());
    case!("TransferCounts", fixtures::transfer_counts());
    case!("RegistryRollupView", fixtures::registry_rollup_view());

    // ── dpp-identity: the internal signing surface ────────────────────────
    case!("SignRequest", fixtures::sign_request());
    case!("SignResponse", fixtures::sign_response());
    case!("VerifyRequest", fixtures::verify_request());
    case!("VerifyResponse", fixtures::verify_response());
    case!("RotateRequest", fixtures::rotate_request());
    case!("RotateResponse", fixtures::rotate_response());

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
            name: "Coverage",
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
/// `CreateRequest.repairabilityScore` was documented `minimum: 0, maximum: 100`
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
    let schema = &schemas(&spec)["CreateRequest"];
    let props = schema_property_map(&spec, schema);

    // Each numeric field of CreateRequest, with a way to set it on a body that
    // is otherwise valid. Adding a bounded field without adding it here is
    // caught below.
    type Setter = fn(&mut dpp_vault::handlers::create::CreateRequest, f64);
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
            failures.push(format!("CreateRequest.{name}: no longer in the spec"));
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
                    "CreateRequest.{name}: spec says minimum {min}, but the validator rejects it"
                ));
            }
            if accepts(*set, min - nudge(min)) {
                failures.push(format!(
                    "CreateRequest.{name}: spec says minimum {min}, but the validator accepts \
                     values below it"
                ));
            }
        }
        if let Some(max) = max {
            if !accepts(*set, max) {
                failures.push(format!(
                    "CreateRequest.{name}: spec says maximum {max}, but the validator REJECTS it \
                     — the documented range is wider than the enforced one"
                ));
            }
            if accepts(*set, max + nudge(max)) {
                failures.push(format!(
                    "CreateRequest.{name}: spec says maximum {max}, but the validator accepts \
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
            "CreateRequest declares bounds on properties this test does not drive: {} — add them \
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

// ── Fixtures ───────────────────────────────────────────────────────────────
//
// Every struct literal here is exhaustive on purpose — see the module docs. Do
// not reach for `..Default::default()`: it would let a new field slip past this
// gate without a compile error, which is the whole failure mode being closed.

mod fixtures {
    use super::*;

    use dpp_common::{
        http_problem::Problem,
        plugin_admin::InstalledPlugin,
        scan::{QrRenderCount, ScanBatch, ScanCount, ScanVariant},
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
        api_key::{ApiKey, ApiKeyScope, CreateApiKeyRequest, NewApiKey},
        audit::AuditEntry,
        evidence::{
            CheckResult, CheckStatus, DossierManifest, DossierV1, EvidenceDossierRecord,
            EvidenceDossierSummary, SignedLayer, VerificationReport,
        },
        operator::{OperatorConfig, UpdateOperatorConfig},
        registry_identity::{
            CreateFacilityRequest, CreateOperatorIdentifierRequest, Facility, OperatorIdentifier,
            RegistryIdentityAudit,
        },
        scan::{DailyScanCount, OperatorScanStats, PassportScanStats},
        trust::{NodeProfile, NodeTrustReport, TrustMode, TrustPort},
        webhook::{NewWebhookSubscription, WebhookSubscription},
    };

    use dpp_identity_service::handlers::{
        rotate_key::{RotateRequest, RotateResponse},
        sign::{SignRequest, SignResponse},
        verify::{VerifyRequest, VerifyResponse},
    };
    use dpp_integrator::handlers::{
        import::{AsyncImportResponse, CreatedEntry, ErrorEntry, SyncImportResponse, UpdatedEntry},
        job_status::{JobProgress, JobStatusResponse},
    };
    use dpp_vault::{
        domain::verify::{NodeReport, RefUnverifiable, TreeReport},
        handlers::{
            create::CreateRequest,
            eol::EolRequest,
            info::VaultInfo,
            list::PassportListResponse,
            node_state::NodeState,
            registry_status::{
                CurrentOperatorView, PassportRegistryView, RegistrationCounts, RegistrationView,
                RegistryRollupView, TransferCounts, TransferView, VerificationView,
            },
            seal::{Coverage, SealResponse, SealSummaryResponse},
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

    pub fn new_api_key() -> NewApiKey {
        NewApiKey {
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

    pub fn audit_entry() -> AuditEntry {
        AuditEntry {
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

    pub fn registry_identity_audit() -> RegistryIdentityAudit {
        RegistryIdentityAudit {
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
        }
    }

    pub fn scan_count() -> ScanCount {
        ScanCount {
            dpp_id: "019723f4-1a2b-7c3d-8e4f-5a6b7c8d9e0f".into(),
            day: date(),
            variant: ScanVariant::Html,
            count: 42,
        }
    }

    pub fn qr_render_count() -> QrRenderCount {
        QrRenderCount {
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

    pub fn create_request() -> CreateRequest {
        CreateRequest {
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

    pub fn sign_request() -> SignRequest {
        SignRequest {
            operator_id: "standalone".into(),
            passport_id: "019723f4-1a2b-7c3d-8e4f-5a6b7c8d9e0f".into(),
            payload: "eyJpZCI6IngifQ==".into(),
        }
    }

    pub fn sign_response() -> SignResponse {
        SignResponse {
            jws_signature: "eyJhbGciOiJFZERTQSJ9..hhh".into(),
        }
    }

    pub fn verify_request() -> VerifyRequest {
        VerifyRequest {
            operator_id: "standalone".into(),
            jws: "eyJhbGciOiJFZERTQSJ9..hhh".into(),
            payload: json!({ "id": "x" }),
        }
    }

    pub fn verify_response() -> VerifyResponse {
        VerifyResponse { valid: true }
    }

    pub fn rotate_request() -> RotateRequest {
        RotateRequest {
            operator_id: "standalone".into(),
        }
    }

    pub fn rotate_response() -> RotateResponse {
        RotateResponse {
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
    pub fn minimal_create_request() -> CreateRequest {
        CreateRequest {
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

    pub fn seal_response() -> SealResponse {
        SealResponse {
            format: "CADES".into(),
            seal_value: "MIIB...".into(),
            sealed_at: ts(),
            signing_cert_ref: Some("5".repeat(64)),
            placeholder: false,
            current_jws: "eyJhbGciOiJFZERTQSJ9..iii".into(),
            current_payload_hash: "6".repeat(64),
            sealed_payload_hash: Some("6".repeat(64)),
            coverage: Coverage::Current,
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

    pub fn all_coverages() -> Vec<Coverage> {
        vec![Coverage::Current, Coverage::Superseded, Coverage::Unknown]
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
    pub fn product_group_obligation() -> ProductGroupObligation {
        use dpp_domain::catalog::{Granularity, RegulatoryStatus, RetentionBasis};
        use dpp_domain::instrument::{DateBasis, InstrumentStatus, RecordedBasis};

        ProductGroupObligation {
            product_group: "toy".into(),
            title: Some("Toys".into()),
            passport: PassportObligationView {
                required: true,
                from: Some(ObligationDateView {
                    date: "2030-08-01".into(),
                    basis: DateBasis::Sourced,
                }),
            },
            determinable: false,
            granularity: Some(Granularity::Model),
            retention: Some(RetentionView {
                years: 10,
                basis: RetentionBasis::Sourced,
            }),
            instruments: vec![InstrumentRefView {
                instrument: "toy-safety-2025-2509".into(),
                recorded: RecordedBasis::Catalog,
                instrument_status: InstrumentStatus::Adopted,
                binding_status: RegulatoryStatus::Provisional,
            }],
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

    pub fn new_webhook_subscription() -> NewWebhookSubscription {
        NewWebhookSubscription {
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

    pub fn transfer_view() -> TransferView {
        TransferView {
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

    pub fn verification_view() -> VerificationView {
        VerificationView {
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

    pub fn transfer_counts() -> TransferCounts {
        TransferCounts {
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
