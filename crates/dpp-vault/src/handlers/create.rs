//! `POST /api/v1/dpp` — create a new passport in `Draft` status.

use axum::{extract::State, http::StatusCode, response::IntoResponse};

use chrono::Utc;
use dpp_common::url_guard::validate_public_https_url;
use dpp_domain::{
    ProductGroupCatalog,
    passport::{Passport, PassportId, PassportRef},
    product_group::{CarbonFootprint, ProductGroup, ProductGroupData, RepairabilityScore},
    schemas::VersionedSchemaRegistry,
    status::PassportStatus,
    validation::validate_product_group_data,
};
use std::sync::OnceLock;
use uuid::Uuid;

use crate::{middleware::scope::RequireWrite, state::AppState};

use super::error::{api_error, internal_error};
use crate::extract::Json;

/// Request body for passport creation.
///
/// Re-exported rather than declared: the bulk importer builds the same body, and
/// the two used to be separate structs kept in step by a comment. See the type
/// for what that cost.
pub use dpp_types::CreatePassportRequest;

/// `POST /api/v1/dpp` — validate fields and create a new passport in `Draft` status.
///
/// Rejects blank required fields, unsafe Unicode characters (null bytes, bidi
/// overrides), out-of-range numeric values and invalid product group data before
/// touching the database.
///
/// A malformed GTIN never reaches here: every typed payload declares
/// `gtin: Gtin`, whose `Deserialize` validates the GS1 check digit, so the body
/// fails to parse. See the `gtin_boundary` tests.
pub async fn create_handler(
    State(state): State<AppState>,
    // The gate is an extractor, and it precedes `Json` deliberately: axum runs
    // body-less extractors first, so a wrong-scope caller is refused before the
    // body is buffered or parsed. See `middleware::scope`.
    RequireWrite(auth): RequireWrite,
    Json(body): Json<CreatePassportRequest>,
) -> impl IntoResponse {
    // Every check below is shared with `POST /api/v1/dpp/validate`, which runs
    // it without persisting. One implementation, so a dry-run verdict and the
    // real create can never disagree.
    if let Some(resp) = validate_create_request(&body) {
        return resp;
    }

    // ProductGroup is the dispatch key: explicit if supplied, else derived from the
    // typed product group data, else Other.
    let product_group = body
        .product_group
        .or_else(|| body.product_group_data.as_ref().map(|d| d.product_group()))
        .unwrap_or_else(|| ProductGroup::Other("other".to_owned()));

    // A new passport is written at the product group's current schema version, and only
    // that one. Never silently down-version to a hardcoded "1.0.0".
    //
    // `PassportService::create` already overwrites this from the catalog on
    // persist, so a caller-supplied value never reached the database — it was
    // computed here and discarded. Two reasons that is not good enough to leave
    // alone. It is dishonest: the request was accepted, so the caller has no way
    // to learn its declaration was ignored. And the service's one assignment is
    // now the only thing standing between a caller and the disclosure table its
    // passport is served under — the stored version selects that table, and an
    // older one classifies fewer fields while defaulting the rest to `Public`
    // (battery v1.0.0 annotates 11 against v2.6.0's 68). Refusing a mismatch
    // here means two independent things must go wrong, not one.
    //
    // The body is validated against the *current* schema regardless — see
    // `validate_against_schema` — so a differing declaration is not a variant the
    // server could honour anyway; it is a claim about the body that is already
    // false.
    let schema_version = catalog()
        .resolve_schema_version(product_group.catalog_key(), None)
        .unwrap_or_else(|| "1.0.0".into());

    // If co2e_per_unit not supplied at the top level, derive it from the
    // typed product group data so callers don't have to duplicate the value.
    let co2e_per_unit = body
        .co2e_per_unit
        .or_else(|| {
            body.product_group_data.as_ref().and_then(|sd| match sd {
                ProductGroupData::Battery(b) => Some(b.co2e_per_unit_kg),
                ProductGroupData::Textile(t) => t.carbon_footprint_kg_co2e,
                _ => None,
            })
        })
        .map(CarbonFootprint::from_kg);

    // Refuse a malformed tariff code at the edge rather than at registration:
    // a draft that cannot be registered should say so when it is created, not
    // months later when it is published.
    let commodity_code = match body.commodity_code.as_deref().map(str::trim) {
        Some(raw) if !raw.is_empty() => match dpp_domain::CommodityCode::parse(raw) {
            Ok(code) => Some(code),
            Err(e) => {
                return api_error(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "VALIDATION_ERROR",
                    &e.to_string(),
                );
            }
        },
        _ => None,
    };

    let passport = Passport {
        id: PassportId(Uuid::now_v7()),
        product_name: body.product_name,
        // Recorded once, here, from the acts the catalog knows reach this
        // product group — and never recomputed afterwards. The law that governs
        // a product is the law at placing on the market, and the set is not
        // derivable from the product group alone, so a later refresh could only
        // narrow it.
        applicable_instruments: dpp_domain::InstrumentCatalog::new()
            .instrument_refs_for(product_group.catalog_key()),
        // Set by the applicable delegated act, and no adopted act fixes one for
        // any product group yet.
        granularity: None,
        product_group,
        manufacturer: body.manufacturer,
        materials: body.materials.unwrap_or_default(),
        co2e_per_unit,
        repairability_score: body
            .repairability_score
            .map(RepairabilityScore::from_scalar),
        // Populated by the service's `apply_compliance`/`apply_lint` after creation.
        compliance_result: None,
        lint_result: None,
        product_group_data: body.product_group_data,
        status: PassportStatus::Draft,
        qr_code_url: None,
        jws_signature: None,
        public_jws_signature: None,
        disclosure_signatures: Default::default(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        published_at: None,
        placed_on_market_date: body.placed_on_market_date,
        schema_version,
        batch_id: body.batch_id,
        retention_locked: false,
        version: 1,
        supersedes_id: body.supersedes_id,
        parent_passport_ref: body.parent_passport_ref,
        component_refs: body.component_refs,
        retention_until: None,
        product_id: None,
        commodity_code,
        operator_identifier: None,
        facility: None,
        seal: None,
    };

    match state.service.create(passport, &auth).await {
        Ok(p) => (
            StatusCode::CREATED,
            Json(crate::api::PassportResponse::from(&p)),
        )
            .into_response(),
        Err(e) => internal_error(e),
    }
}

/// Versioned JSON-Schema registry (embedded schemas), built once.
fn schema_registry() -> &'static VersionedSchemaRegistry {
    static REGISTRY: OnceLock<VersionedSchemaRegistry> = OnceLock::new();
    REGISTRY.get_or_init(VersionedSchemaRegistry::new)
}

/// ProductGroup catalog — single source of truth for the current schema version, built once.
fn catalog() -> &'static ProductGroupCatalog {
    static CATALOG: OnceLock<ProductGroupCatalog> = OnceLock::new();
    CATALOG.get_or_init(ProductGroupCatalog::new)
}

/// Validate typed product group data against its versioned JSON schema. New passports
/// validate against the product group's current schema version (matching what the
/// service persists); product groups with no embedded schema are skipped. Returns the
/// human-readable error string on failure.
fn validate_against_schema(sd: &ProductGroupData) -> Result<(), String> {
    let product_group = sd.product_group();
    let key = product_group.catalog_key();
    let Some(version) = catalog().resolve_schema_version(key, None) else {
        return Ok(());
    };
    let mut json = serde_json::to_value(sd).map_err(|e| e.to_string())?;
    // `ProductGroupData` is internally tagged (`#[serde(tag = "product group")]`); the schemas
    // validate the inner object with `additionalProperties: false`, so strip the tag.
    if let Some(obj) = json.as_object_mut() {
        obj.remove("productGroup");
    }
    schema_registry()
        .validate_strict(key, &version, &json)
        .map_err(|errs| errs.to_display())
}

/// True if `s` contains characters that must never appear in DPP free text:
/// the null byte, other C0/C1 control characters (tab/newline/CR excepted), or
/// Unicode bidirectional override/isolate characters (a display-spoofing vector).
fn has_unsafe_text(s: &str) -> bool {
    s.chars().any(|c| {
        c == '\0'
            || (c.is_control() && c != '\t' && c != '\n' && c != '\r')
            || ('\u{202A}'..='\u{202E}').contains(&c) // LRE, RLE, PDF, LRO, RLO
            || ('\u{2066}'..='\u{2069}').contains(&c) // LRI, RLI, FSI, PDI
    })
}

/// A `parentPassportRef.publicJwsHash` must be a lowercase hex SHA-256 digest —
/// 64 hex chars, no uppercase — so it compares byte-for-byte against the
/// recomputed hash of the fetched parent at verify time.
fn is_lowercase_hex_sha256(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Shape-validate a cross-operator passport reference: `https` + the SSRF guard
/// on the URI, and a lowercase-hex SHA-256 pin. Returns a field-qualified
/// message on failure (`field` names the offending JSON field).
fn validate_passport_ref(r: &PassportRef, field: &str) -> Result<(), String> {
    validate_public_https_url(&r.uri).map_err(|e| format!("{field}.uri: {e}"))?;
    if !is_lowercase_hex_sha256(&r.public_jws_hash) {
        return Err(format!(
            "{field}.publicJwsHash must be a lowercase hex SHA-256 digest"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod parent_ref_hash {
    use super::is_lowercase_hex_sha256;

    #[test]
    fn accepts_only_64_lowercase_hex() {
        assert!(is_lowercase_hex_sha256(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        ));
        assert!(!is_lowercase_hex_sha256(&"A".repeat(64))); // uppercase
        assert!(!is_lowercase_hex_sha256(&"a".repeat(63))); // too short
        assert!(!is_lowercase_hex_sha256(&"a".repeat(65))); // too long
        assert!(!is_lowercase_hex_sha256(&"g".repeat(64))); // non-hex
    }
}

#[cfg(test)]
mod security_regression {
    //! Free-text DPP fields must reject these before they reach the DB:
    //! - **F8** (null bytes / C0-C1 control chars stored verbatim)
    //! - **F12** (Unicode bidi override/isolate → display-spoofing/phishing)
    use super::has_unsafe_text;

    #[test]
    fn rejects_null_byte() {
        assert!(has_unsafe_text("ACME\0Corp")); // F8
    }

    #[test]
    fn rejects_bidi_override_and_isolate() {
        assert!(has_unsafe_text("invoice\u{202E}gpj.exe")); // F12: RLO
        assert!(has_unsafe_text("a\u{2066}b")); // F12: LRI
    }

    #[test]
    fn rejects_other_control_chars() {
        assert!(has_unsafe_text("bell\u{0007}")); // BEL (C0)
    }

    #[test]
    fn allows_normal_text_and_whitespace() {
        assert!(!has_unsafe_text(
            "Eco Jacket — 70% cotton, 30% recycled polyester"
        ));
        assert!(!has_unsafe_text("line1\nline2\tcol\r")); // tab/newline/CR are allowed
        assert!(!has_unsafe_text("Café Müller 30°C")); // accented/degree chars are fine
    }
}

#[cfg(test)]
mod schema_validation {
    //! M-1: typed product group data is also validated against its versioned JSON schema
    //! on the write path, catching schema-only constraints the Rust types miss.
    use super::*;
    use dpp_domain::Gtin;
    use dpp_domain::product_group::{BatteryChemistry, BatteryData, BatteryType};

    fn valid_battery() -> ProductGroupData {
        ProductGroupData::Battery(Box::new(BatteryData {
            gtin: Gtin::parse("09506000134352").unwrap(),
            battery_chemistry: BatteryChemistry::Lfp,
            nominal_voltage_v: 3.2,
            nominal_capacity_ah: 100.0,
            expected_lifetime_cycles: Some(3000),
            co2e_per_unit_kg: 85.4,
            recycled_content_cobalt_pct: None,
            recycled_content_lithium_pct: Some(12.5),
            recycled_content_nickel_pct: None,
            state_of_health_pct: None,
            rated_capacity_kwh: Some(32.0),
            carbon_footprint_class: None,
            due_diligence_url: None,
            cathode_material: None,
            anode_material: None,
            electrolyte_material: None,
            critical_raw_materials: None,
            disassembly_instructions_url: None,
            soh_methodology: None,
            operating_temp_min_c: None,
            operating_temp_max_c: None,
            rated_energy_wh: None,
            recycled_content_lead_pct: None,
            battery_weight_kg: None,
            battery_type: BatteryType::Industrial,
            round_trip_efficiency_pct: None,
            internal_resistance_mohm: None,
            manufacturing_date: None,
            manufacturing_place: None,
            battery_model_id: None,
            battery_passport_number: None,
            placed_on_market_date: None,
            carbon_footprint_class_ruleset_id: None,
            carbon_footprint_class_ruleset_version: None,
            recycled_content_reporting_year: None,
            state_of_health: None,
            expected_lifetime: None,
            // Annex VI Part A / Annex XIII points 1-3, added in dpp-core 0.17.0.
            // All optional and none of them load-bearing for what these tests
            // assert, so all `None`.
            battery_status: None,
            capacity_threshold_for_exhaustion_pct: None,
            commercial_warranty_period_months: None,
            component_part_numbers: None,
            cycle_life_test_c_rate: None,
            dynamic_performance: None,
            eu_declaration_of_conformity: None,
            expected_lifetime_reference_test: None,
            hazard_symbol: None,
            hazardous_substances: None,
            initial_round_trip_efficiency_pct: None,
            internal_cell_resistance_mohm: None,
            internal_pack_resistance_mohm: None,
            marking_information: None,
            maximum_voltage_v: None,
            minimal_voltage_v: None,
            not_in_use_temperature_range: None,
            not_in_use_temperature_reference_test: None,
            original_power_capability_w: None,
            power_limit_max_w: None,
            power_limit_min_w: None,
            power_temperature_range: None,
            renewable_content_pct: None,
            round_trip_efficiency_at_half_cycle_life_pct: None,
            safety_measures: None,
            spare_parts_contacts: None,
            test_report_results: None,
            usable_extinguishing_agent: None,
            usage_history: None,
            voltage_temperature_range: None,
            waste_battery_information: None,
        }))
    }

    #[test]
    fn product_group_data_carries_internal_tag() {
        // Documents the assumption that `validate_against_schema` strips: the
        // internally-tagged enum emits a `product_group` field the schema forbids.
        let json = serde_json::to_value(valid_battery()).unwrap();
        assert_eq!(json["productGroup"], "battery");
    }

    #[test]
    fn valid_battery_passes_versioned_schema() {
        // Resolves to battery v2.0.0; passes only because the `product_group` tag is
        // stripped (the schema uses additionalProperties: false).
        assert!(validate_against_schema(&valid_battery()).is_ok());
    }

    #[test]
    fn schema_rejects_pattern_violation_the_types_allow() {
        // A GTIN of the wrong length is rejected by the schema's `^[0-9]{14}$`
        // pattern — a constraint the Rust types don't carry on the wire shape.
        let mut json = serde_json::to_value(valid_battery()).unwrap();
        json.as_object_mut().unwrap().remove("productGroup");
        json["gtin"] = serde_json::json!("123"); // too short for ^[0-9]{14}$
        assert!(
            schema_registry()
                .validate_if_present("battery", "2.0.0", &json)
                .is_err(),
            "schema must reject a GTIN that violates its pattern"
        );
    }
}

#[cfg(test)]
mod gtin_boundary {
    //! Where a malformed GTIN is actually refused.
    //!
    //! Every typed payload declares `gtin: Gtin`, and `Gtin`'s `Deserialize`
    //! calls `Gtin::parse`. So a bad check digit is rejected while the request
    //! body is being parsed, for every product group at once, before any handler
    //! validation runs. These tests pin that, because the handler's own GTIN
    //! check reads as if it were the thing enforcing it.
    use super::*;

    fn tyre_body(gtin: &str) -> serde_json::Value {
        serde_json::json!({
            "productName": "All-season 205/55R16",
            "manufacturer": { "name": "M", "address": "A" },
            "productGroupData": {
                "productGroup": "tyre",
                "gtin": gtin,
                "tyreClass": "C1",
                "fuelEfficiencyClass": "A",
                "wetGripClass": "A",
                "externalRollingNoiseDb": 70.0
            }
        })
    }

    #[test]
    fn a_bad_check_digit_is_refused_while_the_body_is_parsed() {
        // Valid 14-digit shape, wrong GS1 mod-10 check digit.
        let err = serde_json::from_value::<CreatePassportRequest>(tyre_body("09506000134353"))
            .expect_err("a bad check digit must not deserialize");
        assert!(
            err.to_string().to_lowercase().contains("check digit"),
            "the rejection should name the check digit, got: {err}"
        );
    }

    #[test]
    fn a_valid_gtin_parses_and_the_request_is_accepted() {
        let body = serde_json::from_value::<CreatePassportRequest>(tyre_body("09506000134352"))
            .expect("a valid GTIN must deserialize");
        assert!(
            validate_create_request(&body).is_none(),
            "a well-formed tyre body must pass every create validation"
        );
    }

    #[test]
    fn the_handler_reads_the_gtin_generically_not_battery_only() {
        // The handler asks the payload rather than matching on the variant. If
        // this ever returns `None` for a product group that declares a `gtin`,
        // the check silently stops covering it — which is how it came to cover
        // battery alone.
        let body =
            serde_json::from_value::<CreatePassportRequest>(tyre_body("09506000134352")).unwrap();
        let data = body.product_group_data.expect("payload present");
        assert_eq!(data.gtin(), Some("09506000134352"));
    }
}

/// Every validation `POST /api/v1/dpp` applies to a request body, with no side
/// effects. Returns the rejection response, or `None` when the body would be
/// accepted.
///
/// Extracted so the dry-run endpoint runs *this* rather than a second copy — a
/// preview that disagreed with the real thing would be worse than none, because
/// the direction it disagrees is the direction bad data gets through.
pub fn validate_create_request(body: &CreatePassportRequest) -> Option<axum::response::Response> {
    // Shadows the module-level helper so every check below keeps the exact
    // form it had inside `create_handler` — the extraction is a move, not a
    // rewrite, and the compiler enforces that.
    fn api_error(status: StatusCode, code: &str, detail: &str) -> Option<axum::response::Response> {
        Some(super::error::api_error(status, code, detail))
    }
    if body.product_name.trim().is_empty() {
        return api_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "VALIDATION_ERROR",
            "productName is required",
        );
    }
    if body.manufacturer.name.trim().is_empty() || body.manufacturer.address.trim().is_empty() {
        return api_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "VALIDATION_ERROR",
            "manufacturer.name and manufacturer.address are required",
        );
    }

    // Reject control / bidirectional-override characters in free text — they have
    // no place in DPP data and enable display spoofing and downstream injection.
    let text_fields = [
        body.product_name.as_str(),
        body.manufacturer.name.as_str(),
        body.manufacturer.address.as_str(),
        body.batch_id.as_deref().unwrap_or(""),
    ];
    if text_fields.iter().any(|s| has_unsafe_text(s)) {
        return api_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "VALIDATION_ERROR",
            "text fields must not contain control or bidirectional characters",
        );
    }

    // Numeric sanity: footprints/scores must be finite and in range.
    if let Some(co2e) = body.co2e_per_unit
        && (!co2e.is_finite() || co2e < 0.0)
    {
        return api_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "VALIDATION_ERROR",
            "co2ePerUnit must be a finite, non-negative number",
        );
    }
    if let Some(score) = body.repairability_score
        && (!score.is_finite() || !(0.0..=10.0).contains(&score))
    {
        return api_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "VALIDATION_ERROR",
            "repairabilityScore must be between 0 and 10",
        );
    }

    if let Some(ref sd) = body.product_group_data {
        if let Err(errs) = validate_product_group_data(sd) {
            return api_error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "VALIDATION_ERROR",
                &errs.to_display(),
            );
        }

        // No GTIN check here, deliberately. Every typed payload declares
        // `gtin: Gtin`, and `Gtin`'s `Deserialize` calls `Gtin::parse`, so a bad
        // check digit is refused while this body is being parsed — for all
        // eleven product groups that carry one, before this function is
        // reached. `Gtin`'s inner field is private and `parse` is the only
        // constructor, so a `Gtin` that has not been validated cannot exist.
        //
        // What stood here re-validated `ProductGroupData::Battery`'s already-parsed
        // GTIN and could not fail. It read as the thing enforcing GTIN validity
        // for battery and no other product group, which is the opposite of what
        // was true. See the `gtin_boundary` tests.

        // JSON-Schema validation against the product group's current versioned schema —
        // catches schema-only constraints (string patterns, enum sets, numeric
        // ranges) that the Rust types don't express.
        if let Err(msg) = validate_against_schema(sd) {
            return api_error(StatusCode::UNPROCESSABLE_ENTITY, "VALIDATION_ERROR", &msg);
        }
    }

    // Lineage/BOM refs are fetched cross-operator at verify time, so hold each
    // URI to the same SSRF guard as webhooks (https, no internal hosts) and
    // require the pin to be a lowercase hex SHA-256. Local cycles among
    // `componentRefs` are refused later by the service (it has the repo).
    if let Some(ref parent) = body.parent_passport_ref
        && let Err(e) = validate_passport_ref(parent, "parentPassportRef")
    {
        return api_error(StatusCode::UNPROCESSABLE_ENTITY, "VALIDATION_ERROR", &e);
    }
    for (i, r) in body.component_refs.iter().enumerate() {
        if let Err(e) = validate_passport_ref(r, &format!("componentRefs[{i}]")) {
            return api_error(StatusCode::UNPROCESSABLE_ENTITY, "VALIDATION_ERROR", &e);
        }
    }

    // ProductGroup is the dispatch key: explicit if supplied, else derived from the
    // typed product group data, else Other. Derived again here rather than passed in —
    // it is pure, and computing it locally keeps this function callable on a
    // bare request body with nothing else in hand.
    let product_group = body
        .product_group
        .clone()
        .or_else(|| body.product_group_data.as_ref().map(|d| d.product_group()))
        .unwrap_or_else(|| ProductGroup::Other("other".to_owned()));
    let schema_version = catalog()
        .resolve_schema_version(product_group.catalog_key(), None)
        .unwrap_or_else(|| "1.0.0".into());

    if let Some(requested) = body.schema_version.as_deref()
        && requested != schema_version
    {
        return api_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "VALIDATION_ERROR",
            &format!(
                "schemaVersion must be `{schema_version}` for product_group `{}` (or omitted); \
                 `{requested}` was requested. A new passport is always written at the \
                 product_group's current schema version — the stored version selects the \
                 disclosure table its public view is signed under, so it is not the \
                 caller's to choose.",
                product_group.catalog_key()
            ),
        );
    }
    None
}
