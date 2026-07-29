//! `GET /credential/dpp/{id}` over the real HTTP surface.
//!
//! The credential path had unit coverage below the router — `read_and_verify`
//! against a stub directory, and the field filter as a pure function — but
//! nothing ever drove the route itself. That gap is the reason for this file:
//! every property below is a property of the *endpoint*, and none of them can
//! be observed from either unit layer.
//!
//! What is pinned here:
//!
//! - anonymous reads return the same signed public body as `/public/dpp/{id}`,
//!   because public access must work without registration;
//! - a credential grants exactly its audience's fields, and only on a passport
//!   in the sectors it names;
//! - an unusable credential is a 401 that reveals nothing about whether the
//!   passport exists;
//! - a node with the credential path unconfigured serves public rather than
//!   failing, and rather than silently granting.

#![cfg(feature = "integration-tests")]

mod helpers;

use std::sync::Arc;

use base64::Engine as _;
use chrono::{Duration, Utc};
use ed25519_dalek::{Signer, SigningKey};
use helpers::{
    TestClient, make_jwt, seed_complete_operator, start_postgres, start_vault,
    start_vault_with_credentials,
};
use serde_json::{Value, json};

use dpp_crypto::{
    CredentialBuilder, CredentialRole, DppAccessCredential, DppCredentialSubject,
    StaticTrustedIssuers, StatusList,
};
use dpp_vault::middleware::credential::CredentialDirectory;

const ISSUER: &str = "did:web:issuer.example";
const KID: &str = "route-test-kid";
const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::URL_SAFE_NO_PAD;

// ---------------------------------------------------------------------------
// Credential fixtures
// ---------------------------------------------------------------------------

fn issuer_key() -> SigningKey {
    SigningKey::from_bytes(&[11u8; 32])
}

/// Mint a compact JWS over the JCS-canonical credential, exactly as an issuer
/// would.
fn sign_credential(key: &SigningKey, cred: &DppAccessCredential) -> String {
    let header = B64.encode(format!(r#"{{"alg":"EdDSA","kid":"{KID}"}}"#).as_bytes());
    let value = serde_json::to_value(cred).expect("credential to value");
    let canonical = dpp_crypto::jws::canonicalize(&value).expect("canonicalize");
    let payload = B64.encode(&canonical);
    let signing_input = format!("{header}.{payload}");
    let sig = key.sign(signing_input.as_bytes());
    format!("{signing_input}.{}", B64.encode(sig.to_bytes()))
}

fn credential_for(role: CredentialRole, sectors: &[&str]) -> DppAccessCredential {
    CredentialBuilder::new(
        ISSUER.to_owned(),
        DppCredentialSubject {
            id: "did:web:holder.example".to_owned(),
            name: "Example Repair Co".to_owned(),
            role,
            country: "DE".to_owned(),
            sectors: sectors.iter().map(|s| (*s).to_owned()).collect(),
            product_categories: Vec::new(),
        },
    )
    .expires_at(Utc::now() + Duration::days(30))
    .build()
}

fn credential_header(role: CredentialRole, sectors: &[&str]) -> String {
    sign_credential(&issuer_key(), &credential_for(role, sectors))
}

/// Serves the issuer's DID document from memory. The network half is covered by
/// the adapter's own tests; here the point is the route, so the directory is a
/// fixture.
struct FixtureDirectory;

#[async_trait::async_trait]
impl CredentialDirectory for FixtureDirectory {
    async fn did_document(&self, _issuer: &str) -> Option<Value> {
        let key = issuer_key();
        Some(json!({
            "id": ISSUER,
            "assertionMethod": [format!("{ISSUER}#{KID}")],
            "verificationMethod": [{
                "id": format!("{ISSUER}#{KID}"),
                "type": "JsonWebKey2020",
                "controller": ISSUER,
                "publicKeyJwk": {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": B64.encode(key.verifying_key().to_bytes()),
                }
            }]
        }))
    }

    async fn status_list(&self, _c: &DppAccessCredential) -> Option<StatusList> {
        None
    }
}

fn wiring() -> (
    Arc<dyn CredentialDirectory>,
    Arc<dyn dpp_crypto::TrustedIssuerRegistry>,
) {
    (
        Arc::new(FixtureDirectory),
        // Trusted for both audiences, so the tests below isolate *scope* and
        // *filtering* rather than re-testing issuer trust.
        Arc::new(StaticTrustedIssuers::new(vec![ISSUER], vec![ISSUER])),
    )
}

// ---------------------------------------------------------------------------
// Passport fixture
// ---------------------------------------------------------------------------

/// Create and publish a battery passport carrying one field of each disclosure
/// class, on the current schema:
///
/// - `stateOfHealthPct` — `individual` (Annex XIII point 4), sector-level
/// - `cathodeMaterial` — `restricted` (point 2), sector-level
/// - `batchId` — `restricted`, passport-level
/// - `retentionLocked` — `conformity` (point 3), stamped at publish
///
/// Both a sector-level and a passport-level restricted field are present on
/// purpose: they take different paths through the filter (the sector catalog's
/// disclosure map vs. `PASSPORT_FIELD_DISCLOSURE`), and a fixture with only one
/// would leave the other untested.
async fn publish_battery(client: &TestClient) -> String {
    let resp = client
        .post_json(
            "/api/v1/dpp",
            json!({
                "productName": "Audience Route Cell",
                "productCategory": "BATTERY",
                "manufacturer": { "name": "GreenCell GmbH", "address": "Berlin, DE" },
                "materials": [{ "name": "Lithium", "weightKg": 1.2 }],
                "schemaVersion": "2.4.0",
                "batchId": "LOT-2026-07",
                "sectorData": {
                    "sector": "battery",
                    "gtin": "09506000134352",
                    "batteryChemistry": "LFP",
                    "nominalVoltageV": 48.0,
                    "nominalCapacityAh": 100.0,
                    "expectedLifetimeCycles": 3000,
                    "co2ePerUnitKg": 45.2,
                    "ratedCapacityKwh": 4.8,
                    "stateOfHealthPct": 87.5,
                    "cathodeMaterial": [
                        { "name": "LiFePO4", "weightPct": 92.0 }
                    ]
                }
            }),
        )
        .await;
    assert_eq!(resp.status(), 201, "create failed");
    let created: Value = resp.json().await.unwrap();
    let id = created["id"].as_str().expect("created id").to_owned();

    let resp = client
        .post_json(&format!("/api/v1/dpp/{id}/publish"), json!({}))
        .await;
    assert_eq!(resp.status(), 200, "publish failed");
    id
}

/// GET the audience route with an optional credential header.
async fn get_with_credential(base: &str, id: &str, credential: Option<&str>) -> reqwest::Response {
    let mut req = reqwest::Client::new().get(format!("{base}/credential/dpp/{id}"));
    if let Some(c) = credential {
        req = req.header("X-DPP-Credential", c);
    }
    req.send().await.expect("request failed")
}

fn sector_data(v: &Value) -> &serde_json::Map<String, Value> {
    v.get("sectorData")
        .and_then(Value::as_object)
        .expect("body carries sectorData")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Anonymous access is the baseline, not a degraded case: ESPR Art. 11(b)
/// requires access free of charge, and the toy and detergent regulations forbid
/// requiring a consumer to register. The body must also be *byte-identical* to
/// the public route, or the two representations have already diverged.
#[tokio::test(flavor = "multi_thread")]
async fn an_anonymous_read_serves_exactly_the_public_view() {
    let pg = start_postgres().await;
    let (directory, trust) = wiring();
    let base = start_vault_with_credentials(pg.dal.clone(), directory, trust).await;
    seed_complete_operator(&pg.dal).await;
    let token = make_jwt("00000000-0000-0000-0000-000000000002");
    let client = TestClient::new(&base, &token);
    let id = publish_battery(&client).await;

    let resp = get_with_credential(&base, &id, None).await;
    assert_eq!(resp.status(), 200, "anonymous read must succeed");
    let credential_body: Value = resp.json().await.unwrap();

    let public_body: Value = reqwest::get(format!("{base}/public/dpp/{id}"))
        .await
        .expect("public read")
        .json()
        .await
        .unwrap();

    assert_eq!(
        credential_body, public_body,
        "an anonymous credential-route read must be the same representation as /public"
    );
    assert!(
        !sector_data(&credential_body).contains_key("stateOfHealthPct"),
        "individual-item data must never reach an anonymous caller"
    );
}

/// A legitimate-interest credential receives Annex XIII point 4 individual-item
/// data — the whole point of the route.
#[tokio::test(flavor = "multi_thread")]
async fn a_legitimate_interest_credential_unlocks_individual_item_data() {
    let pg = start_postgres().await;
    let (directory, trust) = wiring();
    let base = start_vault_with_credentials(pg.dal.clone(), directory, trust).await;
    seed_complete_operator(&pg.dal).await;
    let token = make_jwt("00000000-0000-0000-0000-000000000002");
    let client = TestClient::new(&base, &token);
    let id = publish_battery(&client).await;

    let header = credential_header(CredentialRole::AuthorisedRepairer, &["battery"]);
    let resp = get_with_credential(&base, &id, Some(&header)).await;
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();

    assert_eq!(
        sector_data(&body).get("stateOfHealthPct"),
        Some(&json!(87.5)),
        "a repairer must receive individual-item data"
    );
    assert!(
        sector_data(&body).contains_key("cathodeMaterial"),
        "sector-level restricted data is shared with legitimate interest"
    );
    assert_eq!(
        body.get("batchId"),
        Some(&json!("LOT-2026-07")),
        "passport-level restricted data too"
    );
    assert!(
        body.get("retentionLocked").is_none(),
        "conformity evidence is authority-only"
    );
}

/// The proof travels with the view it covers, and the response names the
/// disclosure classes it carries rather than the audience that asked.
///
/// This is the property a repairer's verifier actually runs, and the one that
/// was broken: the response used to carry `publicJwsSignature`, computed over a
/// strictly smaller payload, so checking it reported a mismatch that was not
/// tampering.
#[tokio::test(flavor = "multi_thread")]
async fn a_non_public_view_is_served_with_a_proof_that_covers_it() {
    let pg = start_postgres().await;
    let (directory, trust) = wiring();
    let base = start_vault_with_credentials(pg.dal.clone(), directory, trust).await;
    seed_complete_operator(&pg.dal).await;
    let token = make_jwt("00000000-0000-0000-0000-000000000002");
    let client = TestClient::new(&base, &token);
    let id = publish_battery(&client).await;

    for (role, expected_set) in [
        (
            CredentialRole::AuthorisedRepairer,
            "public+restricted+individual",
        ),
        (
            CredentialRole::MarketSurveillanceAuthority,
            "public+restricted+conformity",
        ),
    ] {
        let header = credential_header(role.clone(), &["battery"]);
        let resp = get_with_credential(&base, &id, Some(&header)).await;
        assert_eq!(resp.status(), 200);
        let body: Value = resp.json().await.unwrap();

        assert_eq!(
            body["disclosureSet"],
            json!(expected_set),
            "the response must name its disclosure classes, not the audience"
        );

        let proof = body["disclosureJwsSignature"]
            .as_str()
            .unwrap_or_else(|| panic!("{role:?}: no proof attached to a non-public view"));

        // Verify the way a caller would: strip what the serving layer added,
        // then compare against the payload the proof was computed over.
        let mut payload = body.clone();
        let obj = payload.as_object_mut().unwrap();
        obj.remove("disclosureJwsSignature");
        obj.remove("disclosureSet");

        let seg = proof.split('.').nth(1).expect("compact JWS");
        let signed: Value =
            serde_json::from_slice(&B64.decode(seg).expect("base64url")).expect("JSON");

        assert_eq!(
            payload, signed,
            "{role:?}: the served body is not what its attached proof covers"
        );

        // Neither sibling proof may ride along — each covers a different body.
        assert!(body.get("publicJwsSignature").is_none());
        assert!(body.get("jwsSignature").is_none());
    }
}

/// Every credentialed read lands in the passport's hash-chained trail, keyed by
/// the disclosure classes granted and naming the issuer and holder — the
/// operator's evidence of who was given the restricted view.
#[tokio::test(flavor = "multi_thread")]
async fn a_credentialed_read_is_recorded_in_the_audit_trail() {
    let pg = start_postgres().await;
    let (directory, trust) = wiring();
    let base = start_vault_with_credentials(pg.dal.clone(), directory, trust).await;
    seed_complete_operator(&pg.dal).await;
    let token = make_jwt("00000000-0000-0000-0000-000000000002");
    let client = TestClient::new(&base, &token);
    let id = publish_battery(&client).await;

    let before: Value = client
        .get(&format!("/api/v1/dpp/{id}/history"))
        .await
        .json()
        .await
        .unwrap();
    let before_len = before.as_array().map_or(0, Vec::len);

    // An anonymous read must NOT be audited: it is the free, unregistered
    // baseline, and recording it would turn a public right into a tracked event.
    let resp = get_with_credential(&base, &id, None).await;
    assert_eq!(resp.status(), 200);

    let header = credential_header(CredentialRole::AuthorisedRepairer, &["battery"]);
    let resp = get_with_credential(&base, &id, Some(&header)).await;
    assert_eq!(resp.status(), 200);

    let after: Value = client
        .get(&format!("/api/v1/dpp/{id}/history"))
        .await
        .json()
        .await
        .unwrap();
    let entries = after.as_array().expect("history is an array");
    assert_eq!(
        entries.len(),
        before_len + 1,
        "exactly one entry: the credentialed read, not the anonymous one"
    );

    let entry = entries.last().expect("the read entry");
    assert_eq!(entry["action"], json!("credentialed_read"));
    assert_eq!(entry["actor"], json!("did:web:holder.example"));

    let meta = &entry["metadata"];
    assert_eq!(meta["issuerDid"], json!(ISSUER));
    assert_eq!(meta["disclosureSet"], json!("public+restricted+individual"));
    assert_eq!(
        meta["disclosureClasses"],
        json!(["public", "restricted", "individual"]),
        "the grant is recorded as classes, never as an audience name"
    );

    let serialised = entry.to_string();
    for audience_name in ["legitimateInterest", "LegitimateInterest", "authority"] {
        assert!(
            !serialised.contains(audience_name),
            "audit entry leaks the audience name {audience_name}, which ESPR's actor \
             vocabulary would invalidate"
        );
    }
}

/// An out-of-scope credential is recorded too, with the public classes it was
/// reduced to — a credential presented against a product it does not cover is
/// exactly what an operator wants to find later.
#[tokio::test(flavor = "multi_thread")]
async fn an_out_of_scope_credentialed_read_is_still_recorded() {
    let pg = start_postgres().await;
    let (directory, trust) = wiring();
    let base = start_vault_with_credentials(pg.dal.clone(), directory, trust).await;
    seed_complete_operator(&pg.dal).await;
    let token = make_jwt("00000000-0000-0000-0000-000000000002");
    let client = TestClient::new(&base, &token);
    let id = publish_battery(&client).await;

    let header = credential_header(CredentialRole::AuthorisedRepairer, &["textile"]);
    let resp = get_with_credential(&base, &id, Some(&header)).await;
    assert_eq!(resp.status(), 200);

    let history: Value = client
        .get(&format!("/api/v1/dpp/{id}/history"))
        .await
        .json()
        .await
        .unwrap();
    let entry = history
        .as_array()
        .expect("history")
        .iter()
        .rev()
        .find(|e| e["action"] == json!("credentialed_read"))
        .expect("the out-of-scope read was recorded");

    assert_eq!(
        entry["metadata"]["disclosureSet"],
        json!("public"),
        "the record must show what was actually granted, not what was claimed"
    );
}

/// The scope rule, over HTTP: a credential naming `textile` must not unlock a
/// battery passport. It is not rejected — it is simply not elevated, which is
/// why the answer is a 200 carrying the public view.
#[tokio::test(flavor = "multi_thread")]
async fn a_credential_for_another_sector_grants_only_public() {
    let pg = start_postgres().await;
    let (directory, trust) = wiring();
    let base = start_vault_with_credentials(pg.dal.clone(), directory, trust).await;
    seed_complete_operator(&pg.dal).await;
    let token = make_jwt("00000000-0000-0000-0000-000000000002");
    let client = TestClient::new(&base, &token);
    let id = publish_battery(&client).await;

    let header = credential_header(CredentialRole::AuthorisedRepairer, &["textile"]);
    let resp = get_with_credential(&base, &id, Some(&header)).await;
    assert_eq!(
        resp.status(),
        200,
        "an out-of-scope credential is not an error"
    );
    let body: Value = resp.json().await.unwrap();

    assert!(
        !sector_data(&body).contains_key("stateOfHealthPct"),
        "a textile credential must not unlock battery individual-item data"
    );
    assert!(body.get("batchId").is_none(), "nor restricted data");
}

/// An unusable credential is a 401 carrying an RFC 7807 body, and it names the
/// header the caller must fix.
#[tokio::test(flavor = "multi_thread")]
async fn an_unusable_credential_is_a_problem_response() {
    let pg = start_postgres().await;
    let (directory, trust) = wiring();
    let base = start_vault_with_credentials(pg.dal.clone(), directory, trust).await;
    seed_complete_operator(&pg.dal).await;
    let token = make_jwt("00000000-0000-0000-0000-000000000002");
    let client = TestClient::new(&base, &token);
    let id = publish_battery(&client).await;

    let resp = get_with_credential(&base, &id, Some("not-a-jws")).await;
    assert_eq!(resp.status(), 401);
    assert!(
        resp.headers().contains_key("www-authenticate"),
        "a 401 must tell the caller which scheme failed"
    );
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], json!(401));
    assert!(
        body.get("detail").and_then(Value::as_str).is_some(),
        "RFC 7807 body carries a detail"
    );
}

/// The probe-resistance property, asserted rather than asserted-about: a
/// rejected credential must produce the identical response whether or not the
/// passport exists. If credential resolution ever moved after the database
/// read, this is the test that would catch it.
#[tokio::test(flavor = "multi_thread")]
async fn a_rejected_credential_cannot_probe_for_passport_ids() {
    let pg = start_postgres().await;
    let (directory, trust) = wiring();
    let base = start_vault_with_credentials(pg.dal.clone(), directory, trust).await;
    seed_complete_operator(&pg.dal).await;
    let token = make_jwt("00000000-0000-0000-0000-000000000002");
    let client = TestClient::new(&base, &token);
    let real = publish_battery(&client).await;
    let absent = "0190a9f0-dead-7abc-8def-0123456789ab";

    // `requestId` is per-request by design and is the one field expected to
    // differ; everything else must be identical.
    let strip_request_id = |mut v: Value| {
        if let Some(o) = v.as_object_mut() {
            o.remove("requestId");
        }
        v
    };

    let on_real = get_with_credential(&base, &real, Some("not-a-jws")).await;
    let real_status = on_real.status();
    let real_body = strip_request_id(on_real.json().await.unwrap());

    let on_absent = get_with_credential(&base, absent, Some("not-a-jws")).await;
    let absent_status = on_absent.status();
    let absent_body = strip_request_id(on_absent.json().await.unwrap());

    assert_eq!(real_status, 401);
    assert_eq!(
        real_status, absent_status,
        "a bad credential must not reveal whether the passport exists"
    );
    assert_eq!(
        real_body, absent_body,
        "the rejection body must not vary with passport existence"
    );
}

/// A suspended passport is Gone on this route too, exactly as on the public
/// one — a credential does not resurrect a withdrawn passport.
#[tokio::test(flavor = "multi_thread")]
async fn a_suspended_passport_is_gone_even_with_a_credential() {
    let pg = start_postgres().await;
    let (directory, trust) = wiring();
    let base = start_vault_with_credentials(pg.dal.clone(), directory, trust).await;
    seed_complete_operator(&pg.dal).await;
    let token = make_jwt("00000000-0000-0000-0000-000000000002");
    let client = TestClient::new(&base, &token);
    let id = publish_battery(&client).await;

    let resp = client
        .post_json(&format!("/api/v1/dpp/{id}/suspend"), json!({}))
        .await;
    assert_eq!(resp.status(), 200, "suspend failed");

    let header = credential_header(CredentialRole::MarketSurveillanceAuthority, &["battery"]);
    let resp = get_with_credential(&base, &id, Some(&header)).await;
    assert_eq!(
        resp.status(),
        410,
        "a suspended passport is Gone for every audience"
    );
}

/// A node with no credential path configured serves the public view rather than
/// denying — and rather than granting. The trust report is where the absence is
/// announced; the route stays useful.
#[tokio::test(flavor = "multi_thread")]
async fn an_unconfigured_node_serves_public_and_grants_nothing() {
    let pg = start_postgres().await;
    let base = start_vault(pg.dal.clone()).await; // no credential wiring
    seed_complete_operator(&pg.dal).await;
    let token = make_jwt("00000000-0000-0000-0000-000000000002");
    let client = TestClient::new(&base, &token);
    let id = publish_battery(&client).await;

    let header = credential_header(CredentialRole::MarketSurveillanceAuthority, &["battery"]);
    let resp = get_with_credential(&base, &id, Some(&header)).await;
    assert_eq!(
        resp.status(),
        200,
        "an unconfigured node must not turn a credential into an error"
    );
    let body: Value = resp.json().await.unwrap();
    assert!(
        !sector_data(&body).contains_key("cathodeMaterial") && body.get("batchId").is_none(),
        "an unconfigured node must not grant restricted data either"
    );
}
