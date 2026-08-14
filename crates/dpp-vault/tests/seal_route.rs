//! `GET /api/v1/dpp/{dppId}/seal` over real HTTP.
//!
//! The handler is the one part of the sealing feature the other tiers do not
//! reach: the drain tests stop at the database, and the full-loop simulation
//! calls `PassportService` directly. What is asserted here is mostly about
//! *honesty of shape* — that an unsealed passport is a 404 rather than an empty
//! seal object, and that the response carries the preimage a verifier needs plus
//! a plain statement that this node validated nothing.

#![cfg(feature = "integration-tests")]

mod helpers;
use helpers::{TestClient, make_jwt, start_postgres, start_vault};

use chrono::Utc;
use dpp_dal::pg::{PgDal, PgPassportRepo};
use dpp_domain::domain::passport::{ManufacturerInfo, Passport, PassportId};
use dpp_domain::domain::sector::Sector;
use dpp_domain::domain::status::PassportStatus;
use dpp_domain::ports::passport_repo::PassportRepository;
use dpp_domain::ports::seal::{SealFormat, SealedEnvelope};

fn op() -> String {
    "00000000-0000-0000-0000-000000000001".to_owned()
}

/// Deliberately not JWT-shaped. The route serves this back verbatim and hashes
/// it; nothing parses it, so a realistic compact JWS would only trip secret
/// scanners on a literal that is not a credential.
const JWS: &str = "header.payload.signature";

/// A published passport, optionally already sealed.
async fn seed(dal: &PgDal, seal: Option<SealedEnvelope>, jws: Option<&str>) -> PassportId {
    let passport = Passport {
        id: PassportId::new(),
        batch_id: None,
        product_name: "Seal Route Battery".into(),
        sector: Sector::Battery,
        manufacturer: ManufacturerInfo {
            name: "TestCorp GmbH".into(),
            address: "Berlin, DE".into(),
            did_web_url: None,
        },
        materials: vec![],
        co2e_per_unit: None,
        repairability_score: None,
        compliance_result: None,
        lint_result: None,
        sector_data: None,
        status: PassportStatus::Published,
        qr_code_url: None,
        jws_signature: jws.map(ToOwned::to_owned),
        public_jws_signature: None,
        disclosure_signatures: Default::default(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        published_at: Some(Utc::now()),
        schema_version: "2.0.0".into(),
        retention_locked: true,
        version: 1,
        supersedes_id: None,
        parent_passport_ref: None,
        component_refs: Vec::new(),
        retention_until: None,
        product_id: None,
        commodity_code: None,
        operator_identifier: None,
        facility: None,
        seal,
    };
    let id = passport.id;
    PgPassportRepo::new(dal.clone())
        .create(passport)
        .await
        .expect("seed passport");
    id
}

fn envelope() -> SealedEnvelope {
    SealedEnvelope {
        format: SealFormat::Cades,
        seal_value: "BASE64-DETACHED-CADES".into(),
        signing_cert_ref: None,
        sealed_at: Utc::now(),
        placeholder: false,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_sealed_passport_returns_the_seal_and_its_preimage() {
    let pg = start_postgres().await;
    let base = start_vault(pg.dal.clone()).await;
    let id = seed(&pg.dal, Some(envelope()), Some(JWS)).await;
    let client = TestClient::new(&base, make_jwt(&op()));

    let resp = client.get(&format!("/api/v1/dpp/{id}/seal")).await;
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();

    assert_eq!(body["format"], "CADES");
    assert_eq!(body["sealValue"], "BASE64-DETACHED-CADES");
    assert_eq!(body["placeholder"], false);

    // The preimage travels with the seal, so a verifier needs nothing else.
    assert_eq!(body["currentJws"], JWS);
    assert_eq!(
        body["currentPayloadHash"],
        dpp_types::seal::digest_for_jws(JWS),
        "the served digest must be the rule the vault and sweep both use"
    );

    // And the response must not read as a verdict.
    let verification = body["verification"].as_str().expect("verification present");
    assert!(
        verification.contains("not validated by this node"),
        "the response must state plainly that no CAdES check was performed: {verification}"
    );
}

/// An unsealed passport has no seal resource. Returning `200` with an empty or
/// null seal would blur "not sealed yet" into "sealed with nothing" — the exact
/// ambiguity the ghost-honesty invariant exists to prevent.
#[tokio::test(flavor = "multi_thread")]
async fn an_unsealed_passport_is_a_404_not_an_empty_seal() {
    let pg = start_postgres().await;
    let base = start_vault(pg.dal.clone()).await;
    let id = seed(&pg.dal, None, Some(JWS)).await;
    let client = TestClient::new(&base, make_jwt(&op()));

    let resp = client.get(&format!("/api/v1/dpp/{id}/seal")).await;
    assert_eq!(resp.status(), 404);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unknown_passport_is_a_404() {
    let pg = start_postgres().await;
    let base = start_vault(pg.dal.clone()).await;
    let client = TestClient::new(&base, make_jwt(&op()));

    let resp = client
        .get(&format!("/api/v1/dpp/{}/seal", PassportId::new()))
        .await;
    assert_eq!(resp.status(), 404);
}

/// A ghost-backed node must say so on the wire rather than let a placeholder
/// pass as a qualified seal.
#[tokio::test(flavor = "multi_thread")]
async fn a_placeholder_seal_is_reported_as_a_placeholder() {
    let pg = start_postgres().await;
    let base = start_vault(pg.dal.clone()).await;
    let mut ghost = envelope();
    ghost.placeholder = true;
    ghost.seal_value = "GHOST-SEAL-abc".into();
    let id = seed(&pg.dal, Some(ghost), Some(JWS)).await;
    let client = TestClient::new(&base, make_jwt(&op()));

    let resp = client.get(&format!("/api/v1/dpp/{id}/seal")).await;
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["placeholder"], true);
}

/// The route is authenticated: a seal is `Conformity`-tier evidence, not public.
#[tokio::test(flavor = "multi_thread")]
async fn the_route_requires_authentication() {
    let pg = start_postgres().await;
    let base = start_vault(pg.dal.clone()).await;
    let id = seed(&pg.dal, Some(envelope()), Some(JWS)).await;

    let resp = reqwest::Client::new()
        .get(format!("{base}/api/v1/dpp/{id}/seal"))
        .send()
        .await
        .expect("request");
    assert_eq!(resp.status(), 401);
}
