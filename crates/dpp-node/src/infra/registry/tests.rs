use std::time::{Duration, Instant};

use chrono::Utc;
use dpp_domain::domain::passport::PassportId;
use dpp_registry::{EuRegistryResponse, registry::RegistryStatusCode};
use uuid::Uuid;

use dpp_domain::ports::registry_sync::{RegistrationRequest, RegistryStatus};

use super::client::EuRegistrySync;
use super::config::EuRegistrySyncConfig;
use super::mapping::{extract_gtin_from_gs1_dl, facility_identifier_for};
use super::token::CachedToken;
use dpp_registry::StatusResponse;

#[test]
fn sandbox_config_has_correct_defaults() {
    let config = EuRegistrySyncConfig::sandbox("id".into(), "secret".into());
    assert_eq!(config.max_retries, 3);
    assert!(config.endpoint.base_url.contains("sandbox"));
}

#[test]
fn production_config_requires_mtls() {
    let config = EuRegistrySyncConfig::production("id".into(), "secret".into());
    assert!(config.endpoint.mtls_required);
}

#[test]
fn response_to_record_maps_status_correctly() {
    let resp = EuRegistryResponse {
        registry_id: "EU-REG-2026-00001".into(),
        passport_id: Uuid::nil(),
        status: RegistryStatusCode::Registered,
        message: None,
        rejection_reasons: None,
        updated_at: Utc::now(),
    };
    let record = EuRegistrySync::response_to_record(&resp);
    assert_eq!(record.status, RegistryStatus::Registered);
    assert_eq!(record.identifiers.registry_id, "EU-REG-2026-00001");
}

#[test]
fn response_to_record_maps_rejected() {
    let resp = EuRegistryResponse {
        registry_id: "EU-REG-2026-00002".into(),
        passport_id: Uuid::nil(),
        status: RegistryStatusCode::Rejected,
        message: Some("invalid data".into()),
        rejection_reasons: Some(vec!["bad GTIN".into()]),
        updated_at: Utc::now(),
    };
    let record = EuRegistrySync::response_to_record(&resp);
    assert_eq!(record.status, RegistryStatus::Rejected);
}

#[test]
fn status_to_record_maps_pending() {
    let resp = StatusResponse {
        registry_id: "EU-REG-2026-00003".into(),
        status: RegistryStatusCode::Pending,
        updated_at: Utc::now(),
        message: None,
    };
    let record = EuRegistrySync::status_to_record(&resp);
    assert_eq!(record.status, RegistryStatus::Pending);
    assert_eq!(record.identifiers.registry_id, "EU-REG-2026-00003");
}

fn request_with_facility(facility: Option<dpp_domain::FacilitySnapshot>) -> RegistrationRequest {
    RegistrationRequest {
        passport_id: PassportId::new(),
        operator_identifier: "did:web:test.example".into(),
        facility_identifier: "LEGACY-FAC".into(),
        facility,
        product_category: "battery".into(),
        data_carrier_uri: String::new(),
        schema_version: "2.0.0".into(),
        jws_signature: None,
        published_at: None,
        country_code: String::new(),
    }
}

#[test]
fn facility_identifier_prefers_full_snapshot() {
    let request = request_with_facility(Some(dpp_domain::FacilitySnapshot {
        scheme: "gln".into(),
        value: "4012345000009".into(),
        name: "Default Plant".into(),
        country: "DE".into(),
        address: Some("1 Allee, Berlin".into()),
    }));
    let fid = facility_identifier_for(&request);
    assert_eq!(fid.scheme, "gln");
    assert_eq!(fid.value, "4012345000009");
    assert_eq!(fid.name.as_deref(), Some("Default Plant"));
    assert_eq!(fid.country, "DE");
    assert_eq!(fid.address.as_deref(), Some("1 Allee, Berlin"));
}

#[test]
fn facility_identifier_falls_back_to_bare_value() {
    let fid = facility_identifier_for(&request_with_facility(None));
    assert_eq!(fid.scheme, "national");
    assert_eq!(fid.value, "LEGACY-FAC");
    assert!(fid.name.is_none());
    assert!(fid.country.is_empty());
}

#[test]
fn extract_gtin_from_valid_gs1_dl() {
    let uri = "https://id.odal-node.io/01/09506000134352/21/abc123";
    assert_eq!(
        extract_gtin_from_gs1_dl(uri),
        Some("09506000134352".to_owned())
    );
}

#[test]
fn extract_gtin_returns_none_for_non_gs1_uri() {
    assert_eq!(
        extract_gtin_from_gs1_dl("https://p.odal-node.io/some-uuid"),
        None
    );
    assert_eq!(
        extract_gtin_from_gs1_dl("https://id.example.com/01/short"),
        None
    );
}

#[test]
fn cached_token_expiry_check() {
    let fresh = CachedToken {
        access_token: "tok".into(),
        expires_at: Instant::now() + Duration::from_secs(3600),
    };
    assert!(!fresh.is_expired());

    let stale = CachedToken {
        access_token: "tok".into(),
        expires_at: Instant::now() + Duration::from_secs(10), // within 30s buffer
    };
    assert!(stale.is_expired());
}
