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
//!   in the product groups and categories it names;
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
    TestClient, make_jwt, real_signer, seed_complete_operator, start_postgres, start_vault,
    start_vault_with_credentials, start_vault_with_credentials_signed_by,
};
use serde_json::{Value, json};

use dpp_vault::middleware::credential::CredentialDirectory;
use dpp_vc::{
    CredentialBuilder, CredentialRole, DppAccessCredential, DppCredentialSubject,
    StaticTrustedIssuers, StatusList,
};

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
    let header = B64.encode(
        format!(r#"{{"alg":"EdDSA","cty":"vc","kid":"{ISSUER}#{KID}","typ":"vc+jwt"}}"#).as_bytes(),
    );
    let value = serde_json::to_value(cred).expect("credential to value");
    let canonical = dpp_crypto::jws::canonicalize(&value).expect("canonicalize");
    let payload = B64.encode(&canonical);
    let signing_input = format!("{header}.{payload}");
    let sig = key.sign(signing_input.as_bytes());
    format!("{signing_input}.{}", B64.encode(sig.to_bytes()))
}

fn credential_for(role: CredentialRole, product_groups: &[&str]) -> DppAccessCredential {
    CredentialBuilder::new(
        ISSUER.to_owned(),
        DppCredentialSubject {
            id: "did:web:holder.example".to_owned(),
            name: "Example Repair Co".to_owned(),
            role,
            country: "DE".to_owned(),
            product_groups: product_groups.iter().map(|s| (*s).to_owned()).collect(),
            product_categories: Vec::new(),
        },
    )
    .expires_at(Utc::now() + Duration::days(30))
    .build()
}

fn credential_header(role: CredentialRole, product_groups: &[&str]) -> String {
    sign_credential(&issuer_key(), &credential_for(role, product_groups))
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
    Arc<dyn dpp_vc::TrustedIssuerRegistry>,
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
/// - `stateOfHealthPct` — `individual` (Annex XIII point 4), product group-level
/// - `cathodeMaterial` — `restricted` (point 2), product group-level
/// - `lintResult` — `restricted`, passport-level (`batchId` would not do: the
///   battery schema opens it to the public, as Annex XIII point 1(a) requires)
/// - `retentionLocked` — `conformity` (point 3), stamped at publish
///
/// Both a product group-level and a passport-level restricted field are present on
/// purpose: they take different paths through the filter (the product group catalog's
/// disclosure map vs. `PASSPORT_FIELD_DISCLOSURE`), and a fixture with only one
/// would leave the other untested.
async fn publish_battery(client: &TestClient) -> String {
    let resp = client
        .post_json(
            "/api/v1/dpp",
            json!({
                "productName": "Audience Route Cell",
                "manufacturer": { "name": "Example Batteries GmbH", "address": "Berlin, DE" },
                "materials": [{ "name": "Lithium", "weightKg": 1.2 }],
                "batchId": "LOT-2026-07",
                "productGroupData": {
                    "productGroup": "battery",
                    "productIdentifier": { "scheme": "gs1", "gtin": "09506000134352" },
                    "batteryChemistry": "LFP",
                    "batteryType": "portable",
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

fn product_group_data(v: &Value) -> &serde_json::Map<String, Value> {
    v.get("productGroupData")
        .and_then(Value::as_object)
        .expect("body carries productGroupData")
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
    assert_eq!(
        out_of_scope(&resp),
        None,
        "no credential, so nothing was out of scope"
    );
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
        !product_group_data(&credential_body).contains_key("stateOfHealthPct"),
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
        product_group_data(&body).get("stateOfHealthPct"),
        Some(&json!(87.5)),
        "a repairer must receive individual-item data"
    );
    assert!(
        product_group_data(&body).contains_key("cathodeMaterial"),
        "product_group-level restricted data is shared with legitimate interest"
    );
    assert!(
        body.get("lintResult").is_some(),
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
async fn a_credential_for_another_product_group_grants_only_public() {
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
    assert_eq!(
        out_of_scope(&resp),
        Some("product-group"),
        "the holder is told which axis missed"
    );
    let body: Value = resp.json().await.unwrap();

    assert!(
        !product_group_data(&body).contains_key("stateOfHealthPct"),
        "a textile credential must not unlock battery individual-item data"
    );
    assert!(body.get("lintResult").is_none(), "nor restricted data");

    // The reason travels in the header because the body cannot carry it: a
    // downgraded body is the public view exactly, the payload its proof signs.
    let public_body: Value = reqwest::get(format!("{base}/public/dpp/{id}"))
        .await
        .expect("public read")
        .json()
        .await
        .unwrap();
    assert_eq!(
        body, public_body,
        "a downgraded read must be the same representation as /public"
    );
}

/// The reason a credential was served only the public view, if one was sent.
fn out_of_scope(resp: &reqwest::Response) -> Option<&str> {
    resp.headers()
        .get(dpp_vault::middleware::credential::OUT_OF_SCOPE_HEADER)
        .and_then(|v| v.to_str().ok())
}

/// Category scope, over HTTP: the battery fixture states `batteryType:
/// "portable"`, so a credential narrowed to `portable` unlocks it and one
/// narrowed to `ev` does not.
///
/// The in-scope half is the one that proves the wiring: if the route did not
/// read the category off the loaded passport, the narrowed credential would
/// have nothing to match and would be downgraded too.
#[tokio::test(flavor = "multi_thread")]
async fn a_credential_is_scoped_to_the_category_the_passport_states() {
    let pg = start_postgres().await;
    let (directory, trust) = wiring();
    let base = start_vault_with_credentials(pg.dal.clone(), directory, trust).await;
    seed_complete_operator(&pg.dal).await;
    let token = make_jwt("00000000-0000-0000-0000-000000000002");
    let client = TestClient::new(&base, &token);
    let id = publish_battery(&client).await;

    for (category, unlocks) in [("portable", true), ("ev", false)] {
        let mut cred = credential_for(CredentialRole::AuthorisedRepairer, &["battery"]);
        cred.credential_subject.product_categories = vec![category.to_owned()];
        let header = sign_credential(&issuer_key(), &cred);

        let resp = get_with_credential(&base, &id, Some(&header)).await;
        assert_eq!(
            resp.status(),
            200,
            "{category}: a category mismatch is not an error"
        );
        assert_eq!(
            out_of_scope(&resp),
            (!unlocks).then_some("product-category"),
            "{category}: a reason only when the credential was downgraded"
        );
        let body: Value = resp.json().await.unwrap();
        assert_eq!(
            product_group_data(&body).contains_key("stateOfHealthPct"),
            unlocks,
            "{category}: individual-item data"
        );
        assert_eq!(
            body.get("lintResult").is_some(),
            unlocks,
            "{category}: restricted data"
        );
    }
}

/// An unusable credential is a 401 carrying an RFC 9457 body, and it names the
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
    assert_eq!(
        resp.headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok()),
        Some("application/problem+json"),
        "an RFC 9457 body is served as one"
    );
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], json!(401));
    assert!(
        body.get("detail").and_then(Value::as_str).is_some(),
        "RFC 9457 body carries a detail"
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
        !product_group_data(&body).contains_key("cathodeMaterial")
            && body.get("lintResult").is_none(),
        "an unconfigured node must not grant restricted data either"
    );
}

// ---------------------------------------------------------------------------
// Reading a past version: ?asOf=
// ---------------------------------------------------------------------------
//
// ✅ COMPLIANCE-PIN: EN 18221:2026 clause 4.2 — the version of a passport at a
// past moment is retrievable by authenticated, authorised actors, and an archived
// attribute is limited as the live one is.

/// "Now" by the database's clock: the one that stamps each version and that the
/// route measures the future by. A moment a test asks about is read here and not
/// from this process's clock, which can drift from it where Postgres runs in a VM.
async fn db_now(dal: &dpp_dal::pg::PgDal) -> chrono::DateTime<Utc> {
    dpp_dal::pg::sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(dal.pool())
        .await
        .expect("the database's clock")
}

/// An instant as a query-string value. `Z` and not `+00:00`: a literal `+` in a
/// query is a space, and the offset form would have to be percent-encoded.
fn rfc3339(at: chrono::DateTime<Utc>) -> String {
    at.to_rfc3339_opts(chrono::SecondsFormat::Micros, true)
}

/// GET the audience route for the passport as it stood at `at`.
async fn get_as_of(
    base: &str,
    id: &str,
    at: chrono::DateTime<Utc>,
    credential: Option<&str>,
) -> reqwest::Response {
    let mut req =
        reqwest::Client::new().get(format!("{base}/credential/dpp/{id}?asOf={}", rfc3339(at)));
    if let Some(c) = credential {
        req = req.header("X-DPP-Credential", c);
    }
    req.send().await.expect("request failed")
}

/// Check a served non-public view the way a reader would: the attached proof
/// verifies against the operator's key, and covers exactly the body it arrived
/// with.
fn assert_proof_verifies(body: &Value, public_key: &str) {
    let proof = body["disclosureJwsSignature"]
        .as_str()
        .expect("a non-public view carries its proof");
    assert!(
        dpp_crypto::jws::verify_jws(proof, public_key).expect("the verifier ran"),
        "the proof does not verify against the operator's key"
    );

    let mut payload = body.clone();
    let obj = payload.as_object_mut().expect("a view is an object");
    obj.remove("disclosureJwsSignature");
    obj.remove("disclosureSet");
    let seg = proof.split('.').nth(1).expect("compact JWS");
    let signed: Value = serde_json::from_slice(&B64.decode(seg).expect("base64url")).expect("JSON");
    assert_eq!(
        payload, signed,
        "the served body is not what its proof covers"
    );
}

/// The reason a refusal gave, with the per-request id taken out so two refusals
/// can be compared.
async fn refusal(resp: reqwest::Response) -> (u16, Value) {
    let status = resp.status().as_u16();
    let mut body: Value = resp.json().await.expect("a problem document");
    if let Some(o) = body.as_object_mut() {
        o.remove("requestId");
    }
    (status, body)
}

/// The done-when for reading a version at a past instant: an authority and a
/// legitimate interest each receive only their own classes, with a proof that
/// verifies against the operator's key.
///
/// The passport is suspended afterwards, so the live read is `410` and the only
/// thing that can have answered the past one is the archived version. Each past
/// view is also byte-identical to what the same credential was given live before
/// the change: the version carries the classes it was published with, and the
/// route releases nothing the passport's own signed views do not.
#[tokio::test(flavor = "multi_thread")]
async fn a_past_version_is_served_to_each_credential_as_its_own_classes_with_a_proof_that_verifies()
{
    let pg = start_postgres().await;
    let (directory, trust) = wiring();
    let signer = real_signer().await;
    let base = start_vault_with_credentials_signed_by(
        pg.dal.clone(),
        signer.identity.clone(),
        directory,
        trust,
    )
    .await;
    seed_complete_operator(&pg.dal).await;
    let token = make_jwt("00000000-0000-0000-0000-000000000002");
    let client = TestClient::new(&base, &token);
    let id = publish_battery(&client).await;

    let repairer = credential_header(CredentialRole::AuthorisedRepairer, &["battery"]);
    let authority = credential_header(CredentialRole::MarketSurveillanceAuthority, &["battery"]);

    let live_repairer: Value = get_with_credential(&base, &id, Some(&repairer))
        .await
        .json()
        .await
        .unwrap();
    let live_authority: Value = get_with_credential(&base, &id, Some(&authority))
        .await
        .json()
        .await
        .unwrap();

    let moment = db_now(&pg.dal).await;
    let resp = client
        .post_json(&format!("/api/v1/dpp/{id}/suspend"), json!({}))
        .await;
    assert_eq!(resp.status(), 200, "suspend failed");
    assert_eq!(
        get_with_credential(&base, &id, Some(&repairer))
            .await
            .status(),
        410,
        "the passport is withdrawn now, so a read of the past can only come from the archive"
    );

    let resp = get_as_of(&base, &id, moment, Some(&repairer)).await;
    assert_eq!(resp.status(), 200, "a legitimate interest reads the past");
    let past_repairer: Value = resp.json().await.unwrap();
    assert_eq!(
        past_repairer["disclosureSet"],
        json!("public+restricted+individual")
    );
    assert_eq!(
        product_group_data(&past_repairer).get("stateOfHealthPct"),
        Some(&json!(87.5)),
        "a legitimate interest receives individual-item data"
    );
    assert!(
        past_repairer.get("retentionLocked").is_none(),
        "and not conformity evidence"
    );
    assert_proof_verifies(&past_repairer, &signer.public_key);
    assert_eq!(
        past_repairer, live_repairer,
        "the past view is what the same credential was given before the change"
    );

    let resp = get_as_of(&base, &id, moment, Some(&authority)).await;
    assert_eq!(resp.status(), 200, "an authority reads the past");
    let past_authority: Value = resp.json().await.unwrap();
    assert_eq!(
        past_authority["disclosureSet"],
        json!("public+restricted+conformity")
    );
    assert_eq!(
        past_authority.get("retentionLocked"),
        Some(&json!(true)),
        "an authority receives conformity evidence"
    );
    assert!(
        !product_group_data(&past_authority).contains_key("stateOfHealthPct"),
        "and not individual-item data: Art. 77(2)(b) withholds point 4 from authorities"
    );
    assert_proof_verifies(&past_authority, &signer.public_key);
    assert_eq!(past_authority, live_authority);
}

/// A past version has no public view to fall back to.
///
/// Without a credential the live route answers with the public view. For `asOf`
/// that would answer a question about the past with the present passport, so it
/// is refused instead, with the `401` and `WWW-Authenticate` a failed credential
/// gets. A node that cannot verify credentials says so, because telling its
/// caller to present one would send them in a circle.
#[tokio::test(flavor = "multi_thread")]
async fn a_past_version_is_refused_without_a_credential_not_answered_with_the_present_passport() {
    let pg = start_postgres().await;
    let (directory, trust) = wiring();
    let base = start_vault_with_credentials(pg.dal.clone(), directory, trust).await;
    seed_complete_operator(&pg.dal).await;
    let token = make_jwt("00000000-0000-0000-0000-000000000002");
    let client = TestClient::new(&base, &token);
    let id = publish_battery(&client).await;
    let moment = db_now(&pg.dal).await;

    let resp = get_as_of(&base, &id, moment, None).await;
    assert_eq!(resp.status(), 401);
    assert!(
        resp.headers().contains_key("www-authenticate"),
        "a 401 must tell the caller which header to present"
    );
    let body: Value = resp.json().await.unwrap();
    assert!(
        body.get("id").is_none() && body.get("productName").is_none(),
        "the refusal is a problem document, not the passport: {body}"
    );
    assert!(
        body["detail"]
            .as_str()
            .is_some_and(|d| d.contains("X-DPP-Credential")),
        "and it names the header to present: {body}"
    );

    // The same passport's public read is untouched: the refusal is for `asOf`.
    assert_eq!(
        reqwest::get(format!("{base}/public/dpp/{id}"))
            .await
            .expect("public read")
            .status(),
        200
    );

    // A node with the credential path unconfigured honours no credential, so
    // presenting one cannot help and the answer must not say it can.
    let pg = start_postgres().await;
    let base = start_vault(pg.dal.clone()).await;
    seed_complete_operator(&pg.dal).await;
    let token = make_jwt("00000000-0000-0000-0000-000000000002");
    let client = TestClient::new(&base, &token);
    let id = publish_battery(&client).await;
    let header = credential_header(CredentialRole::MarketSurveillanceAuthority, &["battery"]);
    let resp = get_as_of(&base, &id, Utc::now(), Some(&header)).await;
    assert_eq!(
        resp.status(),
        401,
        "an unconfigured node serves no past version, not a present one"
    );
    let body: Value = resp.json().await.unwrap();
    assert!(
        body["detail"]
            .as_str()
            .is_some_and(|d| d.contains("does not verify access credentials")),
        "{body}"
    );
}

/// A credential that does not cover the passport is refused, and the refusal
/// names the axis that missed and lands in the audit trail.
///
/// The live route serves such a credential the public view. There is none here
/// to serve, and answering `200` would make "any valid credential" the rule for
/// reading history, which clause 4.2 does not say: it says authorised.
#[tokio::test(flavor = "multi_thread")]
async fn a_credential_that_does_not_cover_the_passport_is_refused_a_past_version() {
    let pg = start_postgres().await;
    let (directory, trust) = wiring();
    let base = start_vault_with_credentials(pg.dal.clone(), directory, trust).await;
    seed_complete_operator(&pg.dal).await;
    let token = make_jwt("00000000-0000-0000-0000-000000000002");
    let client = TestClient::new(&base, &token);
    let id = publish_battery(&client).await;
    let moment = db_now(&pg.dal).await;

    let header = credential_header(CredentialRole::AuthorisedRepairer, &["textile"]);
    let resp = get_as_of(&base, &id, moment, Some(&header)).await;
    assert_eq!(resp.status(), 403);
    assert_eq!(
        out_of_scope(&resp),
        Some("product-group"),
        "the holder is told which axis missed, as on the live route"
    );

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
        .expect("the refused read was recorded");
    assert_eq!(
        entry["metadata"]["disclosureSet"],
        json!("public"),
        "the record shows what was actually granted"
    );
    assert_eq!(entry["metadata"]["asOf"], json!(rfc3339(moment)));
}

/// Every credentialed read of a past version names the instant it asked for and
/// the archived version that answered, so the operator's evidence of who was
/// shown which moment can be tied to the archive row.
#[tokio::test(flavor = "multi_thread")]
async fn a_read_of_a_past_version_is_recorded_with_its_instant_and_the_version() {
    let pg = start_postgres().await;
    let (directory, trust) = wiring();
    let base = start_vault_with_credentials(pg.dal.clone(), directory, trust).await;
    seed_complete_operator(&pg.dal).await;
    let token = make_jwt("00000000-0000-0000-0000-000000000002");
    let client = TestClient::new(&base, &token);
    let id = publish_battery(&client).await;

    let moment = db_now(&pg.dal).await;
    let resp = client
        .post_json(&format!("/api/v1/dpp/{id}/suspend"), json!({}))
        .await;
    assert_eq!(resp.status(), 200, "suspend failed");

    let header = credential_header(CredentialRole::MarketSurveillanceAuthority, &["battery"]);
    assert_eq!(
        get_as_of(&base, &id, moment, Some(&header)).await.status(),
        200
    );

    // The archive row the operator's own route names for that moment.
    let versions: Value = client
        .get(&format!(
            "/api/v1/dpp/{id}/versions?asOf={}",
            rfc3339(moment)
        ))
        .await
        .json()
        .await
        .unwrap();
    let version_id = versions[0]["id"].clone();
    assert!(version_id.is_string(), "the operator route names it");

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
        .expect("the read was recorded");
    assert_eq!(entry["metadata"]["asOf"], json!(rfc3339(moment)));
    assert_eq!(
        entry["metadata"]["archivedVersionId"], version_id,
        "the entry names the archived version that answered"
    );
    assert_eq!(
        entry["metadata"]["disclosureSet"],
        json!("public+restricted+conformity")
    );
}

/// The instants nothing was the passport's state at are told apart from each
/// other, and a moment after the last change is answered by the live record.
///
/// `422` is the instant that cannot be asked about (not a timestamp, or not yet
/// reached) and `404` the one that is well formed and falls before the passport
/// existed: the same pair the operator's route draws.
#[tokio::test(flavor = "multi_thread")]
async fn the_moments_no_version_covers_are_told_apart() {
    let pg = start_postgres().await;
    let (directory, trust) = wiring();
    let base = start_vault_with_credentials(pg.dal.clone(), directory, trust).await;
    seed_complete_operator(&pg.dal).await;
    let token = make_jwt("00000000-0000-0000-0000-000000000002");
    let client = TestClient::new(&base, &token);
    let before_it_existed = Utc::now() - Duration::days(1);
    let id = publish_battery(&client).await;
    let header = credential_header(CredentialRole::MarketSurveillanceAuthority, &["battery"]);

    let (status, body) =
        refusal(get_as_of(&base, &id, before_it_existed, Some(&header)).await).await;
    assert_eq!(status, 404);
    assert!(
        body["detail"]
            .as_str()
            .is_some_and(|d| d.contains("before this passport was created")),
        "{body}"
    );

    let (status, body) =
        refusal(get_as_of(&base, &id, Utc::now() + Duration::days(1), Some(&header)).await).await;
    assert_eq!(status, 422);
    assert!(
        body["detail"]
            .as_str()
            .is_some_and(|d| d.contains("must not be in the future")),
        "{body}"
    );
    // And alike for a passport that does not exist, which a draft is not told
    // apart from: the future is refused before anything is looked up.
    let absent = "0190a9f0-dead-7abc-8def-0123456789ab";
    let on_absent =
        refusal(get_as_of(&base, absent, Utc::now() + Duration::days(1), Some(&header)).await)
            .await;
    assert_eq!(on_absent, (status, body), "the future, for no passport");
    // The operator's route measures the future the same way.
    let resp = client
        .get(&format!(
            "/api/v1/dpp/{id}/versions?asOf={}",
            rfc3339(Utc::now() + Duration::days(1))
        ))
        .await;
    assert_eq!(
        resp.status(),
        422,
        "the operator's route, asked of the future"
    );

    let resp = reqwest::Client::new()
        .get(format!("{base}/credential/dpp/{id}?asOf=yesterday"))
        .header("X-DPP-Credential", &header)
        .send()
        .await
        .expect("request failed");
    let (status, body) = refusal(resp).await;
    assert_eq!(status, 422);
    assert!(
        body["detail"]
            .as_str()
            .is_some_and(|d| d.contains("RFC 3339")),
        "{body}"
    );

    // Nothing has changed since publish, so the live record is the state now.
    let resp = get_as_of(&base, &id, db_now(&pg.dal).await, Some(&header)).await;
    assert_eq!(
        resp.status(),
        200,
        "the live record answers a moment after the last change"
    );
    let at_now: Value = resp.json().await.unwrap();
    let live: Value = get_with_credential(&base, &id, Some(&header))
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(at_now, live);
}

/// A version is served on the terms the live read serves a passport on: a moment
/// when it was a draft is `404`, and one when it was suspended is `410`.
#[tokio::test(flavor = "multi_thread")]
async fn a_moment_the_passport_was_a_draft_or_suspended_is_not_served() {
    let pg = start_postgres().await;
    let (directory, trust) = wiring();
    let base = start_vault_with_credentials(pg.dal.clone(), directory, trust).await;
    seed_complete_operator(&pg.dal).await;
    let token = make_jwt("00000000-0000-0000-0000-000000000002");
    let client = TestClient::new(&base, &token);
    let header = credential_header(CredentialRole::MarketSurveillanceAuthority, &["battery"]);

    // Created, not yet published: the version current then is the draft, which
    // was never public and has no proof to serve.
    let resp = client
        .post_json(
            "/api/v1/dpp",
            json!({
                "productName": "Draft Then Published",
                "manufacturer": { "name": "Example Batteries GmbH", "address": "Berlin, DE" },
                "productGroupData": {
                    "productGroup": "battery",
                    "productIdentifier": { "scheme": "gs1", "gtin": "09506000134352" },
                    "batteryChemistry": "LFP",
                    "batteryType": "portable",
                    "nominalVoltageV": 48.0,
                    "nominalCapacityAh": 100.0,
                    "expectedLifetimeCycles": 3000,
                    "co2ePerUnitKg": 45.2,
                    "ratedCapacityKwh": 4.8
                }
            }),
        )
        .await;
    assert_eq!(resp.status(), 201, "create failed");
    let created: Value = resp.json().await.unwrap();
    let id = created["id"].as_str().expect("created id").to_owned();
    let as_a_draft = db_now(&pg.dal).await;

    // Still a draft: not a published passport, and told apart from none by
    // neither status nor sentence.
    let absent = "0190a9f0-dead-7abc-8def-0123456789ab";
    let on_draft = refusal(get_as_of(&base, &id, db_now(&pg.dal).await, Some(&header)).await).await;
    let on_absent =
        refusal(get_as_of(&base, absent, db_now(&pg.dal).await, Some(&header)).await).await;
    assert_eq!(on_draft.0, 404);
    assert_eq!(
        on_draft, on_absent,
        "a draft must not be told apart from a passport that does not exist"
    );

    let resp = client
        .post_json(&format!("/api/v1/dpp/{id}/publish"), json!({}))
        .await;
    assert_eq!(resp.status(), 200, "publish failed");

    let (status, body) = refusal(get_as_of(&base, &id, as_a_draft, Some(&header)).await).await;
    assert_eq!(status, 404, "a moment the passport was a draft: {body}");
    assert!(
        body["detail"]
            .as_str()
            .is_some_and(|d| d.contains("No published version")),
        "{body}"
    );

    // Suspended now, and the live record is the state at this moment.
    let resp = client
        .post_json(&format!("/api/v1/dpp/{id}/suspend"), json!({}))
        .await;
    assert_eq!(resp.status(), 200, "suspend failed");
    let resp = get_as_of(&base, &id, db_now(&pg.dal).await, Some(&header)).await;
    assert_eq!(resp.status(), 410, "a moment the passport was suspended");
}

/// A suspension that has since been lifted is still `410` for a moment inside
/// it, answered by the archived version rather than the live record.
///
/// The test above reads its suspension from the live record. Here the passport
/// is published again before the read, so the live record is published and only
/// the version the second publish archived can say that the moment fell inside a
/// suspension.
#[tokio::test(flavor = "multi_thread")]
async fn a_moment_inside_a_lifted_suspension_is_still_gone() {
    let pg = start_postgres().await;
    let (directory, trust) = wiring();
    let base = start_vault_with_credentials(pg.dal.clone(), directory, trust).await;
    seed_complete_operator(&pg.dal).await;
    let token = make_jwt("00000000-0000-0000-0000-000000000002");
    let client = TestClient::new(&base, &token);
    let header = credential_header(CredentialRole::MarketSurveillanceAuthority, &["battery"]);
    let id = publish_battery(&client).await;

    let resp = client
        .post_json(&format!("/api/v1/dpp/{id}/suspend"), json!({}))
        .await;
    assert_eq!(resp.status(), 200, "suspend failed");
    let while_suspended = db_now(&pg.dal).await;
    let resp = client
        .post_json(&format!("/api/v1/dpp/{id}/publish"), json!({}))
        .await;
    assert_eq!(resp.status(), 200, "publishing again failed");

    let resp = get_with_credential(&base, &id, Some(&header)).await;
    assert_eq!(resp.status(), 200, "the passport is live again");
    let (status, body) = refusal(get_as_of(&base, &id, while_suspended, Some(&header)).await).await;
    assert_eq!(status, 410, "a moment inside the suspension: {body}");
}

/// A moment before the first publish is not served, even when no draft version
/// was archived to say the passport was a draft then.
///
/// A publish archives the draft it replaces, so the archive usually answers this
/// itself. A record stored as published with nothing archived before it has no
/// such version, and the live record would answer for a moment it was not yet
/// published. The record is put in that shape directly, past the store, since no
/// route of this build leaves one.
#[tokio::test(flavor = "multi_thread")]
async fn a_moment_before_the_first_publish_is_not_served_without_a_draft_version() {
    let pg = start_postgres().await;
    let (directory, trust) = wiring();
    let base = start_vault_with_credentials(pg.dal.clone(), directory, trust).await;
    seed_complete_operator(&pg.dal).await;
    let token = make_jwt("00000000-0000-0000-0000-000000000002");
    let client = TestClient::new(&base, &token);
    let header = credential_header(CredentialRole::MarketSurveillanceAuthority, &["battery"]);

    let resp = client
        .post_json(
            "/api/v1/dpp",
            json!({
                "productName": "Stored Published",
                "manufacturer": { "name": "Example Batteries GmbH", "address": "Berlin, DE" },
                "productGroupData": {
                    "productGroup": "battery",
                    "productIdentifier": { "scheme": "gs1", "gtin": "09506000134352" },
                    "batteryChemistry": "LFP",
                    "batteryType": "portable",
                    "nominalVoltageV": 48.0,
                    "nominalCapacityAh": 100.0,
                    "expectedLifetimeCycles": 3000,
                    "co2ePerUnitKg": 45.2,
                    "ratedCapacityKwh": 4.8
                }
            }),
        )
        .await;
    assert_eq!(resp.status(), 201, "create failed");
    let created: Value = resp.json().await.unwrap();
    let id = created["id"].as_str().expect("created id").to_owned();
    let before_publish = db_now(&pg.dal).await;
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    let published_at = db_now(&pg.dal).await;

    // Published from here on, by the stored record alone: no change was made
    // through the store, so nothing is archived.
    dpp_dal::pg::sqlx::query(
        "UPDATE odal.passport
            SET doc = doc || jsonb_build_object('status', 'published', 'publishedAt', $2::text)
          WHERE id = $1::uuid",
    )
    .bind(&id)
    .bind(published_at.to_rfc3339_opts(chrono::SecondsFormat::Micros, true))
    .execute(pg.dal.pool())
    .await
    .expect("store the passport as published");

    let (status, body) = refusal(get_as_of(&base, &id, before_publish, Some(&header)).await).await;
    assert_eq!(status, 404, "a moment before the first publish: {body}");
    assert!(
        body["detail"]
            .as_str()
            .is_some_and(|d| d.contains("No published version")),
        "{body}"
    );
}
