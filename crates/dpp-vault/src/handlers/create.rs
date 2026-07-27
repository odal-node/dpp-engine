//! `POST /api/v1/dpp` — create a new passport in `Draft` status.

use axum::{
    extract::{Extension, Json, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::Deserialize;

use chrono::Utc;
use dpp_common::url_guard::validate_public_https_url;
use dpp_digital_link::validate_gtin;
use dpp_domain::{
    SectorCatalog,
    domain::passport::{ManufacturerInfo, MaterialEntry, Passport, PassportId, PassportRef},
    domain::sector::{CarbonFootprint, RepairabilityScore, Sector, SectorData},
    domain::status::PassportStatus,
    domain::validation::validate_sector_data,
    schemas::VersionedSchemaRegistry,
};
use std::sync::OnceLock;
use uuid::Uuid;

use crate::{middleware::auth::AuthContext, state::AppState};

use super::error::{api_error, internal_error, require_write};

/// Request body for passport creation.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateRequest {
    pub product_name: String,
    /// EU ESPR sector (dispatch key). Optional — derived from `sectorData` when omitted.
    pub sector: Option<Sector>,
    pub manufacturer: ManufacturerInfo,
    pub materials: Option<Vec<MaterialEntry>>,
    pub co2e_per_unit: Option<f64>,
    pub repairability_score: Option<f64>,
    pub sector_data: Option<SectorData>,
    pub batch_id: Option<String>,
    pub schema_version: Option<String>,
    /// Cross-operator predecessor this passport derives from (second-life
    /// successor linkage). Shape-validated here; the hash is checked against the
    /// fetched parent at verify time.
    pub parent_passport_ref: Option<PassportRef>,
    /// Cross-operator references to this product's constituent passports (its
    /// bill of materials). Shape-validated here; local cycles/over-depth are
    /// refused by the service.
    #[serde(default)]
    pub component_refs: Vec<PassportRef>,
}

/// `POST /api/v1/dpp` — validate fields and create a new passport in `Draft` status.
///
/// Rejects blank required fields, unsafe Unicode characters (null bytes, bidi
/// overrides), out-of-range numeric values, invalid sector data, and malformed
/// GTINs before touching the database.
pub async fn create_handler(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Json(body): Json<CreateRequest>,
) -> impl IntoResponse {
    if let Some(resp) = require_write(&auth, "Creating a passport") {
        return resp;
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

    if let Some(ref sd) = body.sector_data {
        if let Err(errs) = validate_sector_data(sd) {
            return api_error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "VALIDATION_ERROR",
                &errs.to_display(),
            );
        }

        // GS1 GTIN check-digit validation for Battery passports.
        if let SectorData::Battery(battery) = sd
            && let Err(e) = validate_gtin(battery.gtin.as_str())
        {
            return api_error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "VALIDATION_ERROR",
                &format!("sectorData.gtin: {e}"),
            );
        }

        // JSON-Schema validation against the sector's current versioned schema —
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

    // Sector is the dispatch key: explicit if supplied, else derived from the
    // typed sector data, else Other.
    let sector = body
        .sector
        .or_else(|| body.sector_data.as_ref().map(|d| d.sector()))
        .unwrap_or(Sector::Other);

    // Resolve the sector's current schema version (the service re-normalises this
    // on persist); never silently down-version to a hardcoded "1.0.0".
    let schema_version = catalog()
        .resolve_schema_version(sector.catalog_key(), body.schema_version.as_deref())
        .unwrap_or_else(|| "1.0.0".into());

    // If co2e_per_unit not supplied at the top level, derive it from the
    // typed sector data so callers don't have to duplicate the value.
    let co2e_per_unit = body
        .co2e_per_unit
        .or_else(|| {
            body.sector_data.as_ref().and_then(|sd| match sd {
                SectorData::Battery(b) => Some(b.co2e_per_unit_kg),
                SectorData::Textile(t) => t.carbon_footprint_kg_co2e,
                _ => None,
            })
        })
        .map(CarbonFootprint::from_kg);

    let passport = Passport {
        id: PassportId(Uuid::now_v7()),
        product_name: body.product_name,
        sector,
        product_category: None,
        manufacturer: body.manufacturer,
        materials: body.materials.unwrap_or_default(),
        co2e_per_unit,
        repairability_score: body
            .repairability_score
            .map(RepairabilityScore::from_scalar),
        // Populated by the service's `apply_compliance`/`apply_lint` after creation.
        compliance_result: None,
        lint_result: None,
        sector_data: body.sector_data,
        status: PassportStatus::Draft,
        qr_code_url: None,
        jws_signature: None,
        public_jws_signature: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
        published_at: None,
        schema_version,
        batch_id: body.batch_id,
        retention_locked: false,
        version: 1,
        supersedes_id: None,
        parent_passport_ref: body.parent_passport_ref,
        component_refs: body.component_refs,
        retention_until: None,
        product_id: None,
        operator_identifier: None,
        facility: None,
        seal: None,
    };

    match state.service.create(passport, &auth).await {
        Ok(p) => (StatusCode::CREATED, Json(p)).into_response(),
        Err(e) => internal_error(e),
    }
}

/// Versioned JSON-Schema registry (embedded schemas), built once.
fn schema_registry() -> &'static VersionedSchemaRegistry {
    static REGISTRY: OnceLock<VersionedSchemaRegistry> = OnceLock::new();
    REGISTRY.get_or_init(VersionedSchemaRegistry::new)
}

/// Sector catalog — single source of truth for the current schema version, built once.
fn catalog() -> &'static SectorCatalog {
    static CATALOG: OnceLock<SectorCatalog> = OnceLock::new();
    CATALOG.get_or_init(SectorCatalog::new)
}

/// Validate typed sector data against its versioned JSON schema. New passports
/// validate against the sector's current schema version (matching what the
/// service persists); sectors with no embedded schema are skipped. Returns the
/// human-readable error string on failure.
fn validate_against_schema(sd: &SectorData) -> Result<(), String> {
    let key = sd.sector().catalog_key();
    let Some(version) = catalog().resolve_schema_version(key, None) else {
        return Ok(());
    };
    let mut json = serde_json::to_value(sd).map_err(|e| e.to_string())?;
    // `SectorData` is internally tagged (`#[serde(tag = "sector")]`); the schemas
    // validate the inner object with `additionalProperties: false`, so strip the tag.
    if let Some(obj) = json.as_object_mut() {
        obj.remove("sector");
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
    //! M-1: typed sector data is also validated against its versioned JSON schema
    //! on the write path, catching schema-only constraints the Rust types miss.
    use super::*;
    use dpp_domain::Gtin;
    use dpp_domain::domain::sector::{BatteryChemistry, BatteryData};

    fn valid_battery() -> SectorData {
        SectorData::Battery(BatteryData {
            gtin: Gtin::parse("09506000134352").unwrap(),
            battery_chemistry: BatteryChemistry::Lfp,
            nominal_voltage_v: 3.2,
            nominal_capacity_ah: 100.0,
            expected_lifetime_cycles: 3000,
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
            battery_type: None,
            round_trip_efficiency_pct: None,
            internal_resistance_mohm: None,
            manufacturing_date: None,
            manufacturing_place: None,
            battery_model_id: None,
            battery_passport_number: None,
        })
    }

    #[test]
    fn sector_data_carries_internal_tag() {
        // Documents the assumption that `validate_against_schema` strips: the
        // internally-tagged enum emits a `sector` field the schema forbids.
        let json = serde_json::to_value(valid_battery()).unwrap();
        assert_eq!(json["sector"], "battery");
    }

    #[test]
    fn valid_battery_passes_versioned_schema() {
        // Resolves to battery v2.0.0; passes only because the `sector` tag is
        // stripped (the schema uses additionalProperties: false).
        assert!(validate_against_schema(&valid_battery()).is_ok());
    }

    #[test]
    fn schema_rejects_pattern_violation_the_types_allow() {
        // A GTIN of the wrong length is rejected by the schema's `^[0-9]{14}$`
        // pattern — a constraint the Rust types don't carry on the wire shape.
        let mut json = serde_json::to_value(valid_battery()).unwrap();
        json.as_object_mut().unwrap().remove("sector");
        json["gtin"] = serde_json::json!("123"); // too short for ^[0-9]{14}$
        assert!(
            schema_registry()
                .validate_if_present("battery", "2.0.0", &json)
                .is_err(),
            "schema must reject a GTIN that violates its pattern"
        );
    }
}
