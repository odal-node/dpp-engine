#![cfg(feature = "integration-tests")]
//! The discard-record routes, end to end over real PostgreSQL.
//!
//! ESPR Art. 24 and Art. 25: a discard is recorded whatever was done with the
//! product, the record is checked as sent against core's schema, and the
//! documents that stand behind it are attached and their absence reported.
//! Nothing here is a passport, so none is created except to name in a record.

mod helpers;

use helpers::{
    PgContainer, TestClient, make_jwt, make_jwt_scoped, seed_complete_operator, start_postgres,
    start_vault,
};

const OPERATOR: &str = "00000000-0000-0000-0000-000000000077";

/// A discard on 2026-08-01, of 1240 jacket units, sent to recycling.
fn record() -> serde_json::Value {
    serde_json::json!({
        "discardedOn": "2026-08-01",
        "cnCodes": ["420300"],
        "description": "Jackets, unsold season stock",
        "units": { "value": 1240 },
        "weight": { "grams": 860500 },
        "packagingIncluded": false,
        "treatment": "recycling",
        "receiver": { "name": "Nord Recycling GmbH" }
    })
}

/// A discard for `reason`, sent to recycling, on `day`.
fn discard(day: &str, reason: Option<&str>) -> serde_json::Value {
    let mut record = record();
    record["discardedOn"] = serde_json::json!(day);
    if let Some(reason) = reason {
        record["reason"] = serde_json::json!(reason);
    }
    serde_json::json!({ "record": record })
}

struct Setup {
    _pg: PgContainer,
    dal: dpp_dal::pg::PgDal,
    base: String,
    write: String,
    read: String,
    admin: String,
}

/// A fresh node, with its operator's size stated as `size` (or not at all).
async fn setup(size: Option<dpp_domain::unsold_goods::EnterpriseSize>) -> Setup {
    let pg = start_postgres().await;
    let base = start_vault(pg.dal.clone()).await;
    seed_complete_operator(&pg.dal).await;
    if let Some(size) = size {
        use dpp_types::operator::{
            OperatorConfig, OperatorConfigRepository, STANDALONE_OPERATOR_ID,
        };
        let mut cfg = OperatorConfig::empty(STANDALONE_OPERATOR_ID);
        cfg.legal_name = "Test Operator GmbH".into();
        cfg.address = "Unter den Linden 1, Berlin".into();
        cfg.country = "DE".into();
        cfg.contact_email = "ops@test.example".into();
        cfg.enterprise_size = Some(size);
        dpp_dal::pg::PgOperatorConfigRepo::new(pg.dal.clone())
            .upsert(cfg)
            .await
            .expect("state the operator's size");
    }
    Setup {
        base,
        write: make_jwt_scoped(OPERATOR, "write"),
        read: make_jwt_scoped(OPERATOR, "read"),
        admin: make_jwt(OPERATOR),
        dal: pg.dal.clone(),
        _pg: pg,
    }
}

async fn store(s: &Setup, body: serde_json::Value) -> serde_json::Value {
    let client = TestClient::new(&s.base, &s.write);
    let resp = client.post_json("/api/v1/discard-records", body).await;
    assert_eq!(
        resp.status(),
        201,
        "{}",
        resp.text().await.unwrap_or_default()
    );
    resp.json().await.expect("the stored record")
}

fn evidence_form(kind: &str, bytes: Vec<u8>) -> reqwest::multipart::Form {
    reqwest::multipart::Form::new()
        .text("kind", kind.to_owned())
        .part(
            "file",
            reqwest::multipart::Part::bytes(bytes).file_name("delivery-note.pdf"),
        )
}

async fn attach(s: &Setup, record_id: &str, form: reqwest::multipart::Form) -> reqwest::Response {
    reqwest::Client::new()
        .post(format!(
            "{}/api/v1/discard-records/{record_id}/evidence",
            s.base
        ))
        .bearer_auth(&s.write)
        .multipart(form)
        .send()
        .await
        .expect("the attachment reaches the node")
}

// ─── Recording ────────────────────────────────────────────────────────────────

/// The record is stored as core's schema checked it, under that version, and
/// reads back on its year.
#[tokio::test(flavor = "multi_thread")]
async fn a_discard_is_stored_and_listed_on_its_year() {
    let s = setup(None).await;
    let stored = store(&s, discard("2026-08-01", None)).await;

    assert_eq!(stored["schemaVersion"], "1.0.0");
    assert_eq!(stored["record"]["discardedOn"], "2026-08-01");
    assert_eq!(stored["passportIds"], serde_json::json!([]));

    let client = TestClient::new(&s.base, &s.admin);
    let listed: Vec<serde_json::Value> = client
        .get("/api/v1/discard-records?financialYearStart=2026-01-01&financialYearEnd=2026-12-31")
        .await
        .json()
        .await
        .expect("a listing");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0]["id"], stored["id"]);
}

/// A misspelt field is refused rather than dropped, and nothing is stored.
#[tokio::test(flavor = "multi_thread")]
async fn a_misspelt_field_is_refused_and_nothing_is_stored() {
    let s = setup(None).await;
    let mut body = discard("2026-08-01", None);
    body["record"]["reasonn"] = serde_json::json!("damagedOrContaminated");

    let client = TestClient::new(&s.base, &s.write);
    let resp = client.post_json("/api/v1/discard-records", body).await;
    assert_eq!(
        resp.status(),
        422,
        "a field the schema does not have is refused"
    );

    let listed: Vec<serde_json::Value> = TestClient::new(&s.base, &s.admin)
        .get("/api/v1/discard-records?financialYearStart=2026-01-01&financialYearEnd=2026-12-31")
        .await
        .json()
        .await
        .expect("a listing");
    assert!(listed.is_empty(), "nothing was stored");
}

/// A value the schema forbids is refused, here an unknown reason.
#[tokio::test(flavor = "multi_thread")]
async fn a_reason_outside_the_derogations_is_refused() {
    let s = setup(None).await;
    let client = TestClient::new(&s.base, &s.write);
    let resp = client
        .post_json(
            "/api/v1/discard-records",
            discard("2026-08-01", Some("endOfSeason")),
        )
        .await;
    assert_eq!(
        resp.status(),
        422,
        "endOfSeason is not a derogation in Del. Reg. 2026/296 Art. 2"
    );
}

/// A passport the node does not hold cannot be named.
#[tokio::test(flavor = "multi_thread")]
async fn a_passport_the_node_does_not_hold_is_refused() {
    let s = setup(None).await;
    let mut body = discard("2026-08-01", None);
    body["passportIds"] = serde_json::json!(["00000000-0000-7000-8000-000000000001"]);

    let resp = TestClient::new(&s.base, &s.write)
        .post_json("/api/v1/discard-records", body)
        .await;
    assert_eq!(resp.status(), 422);
    let detail = resp.text().await.unwrap_or_default();
    assert!(
        detail.contains("00000000-0000-7000-8000-000000000001"),
        "{detail}"
    );
}

/// A read-only key may read a discard but not record one.
#[tokio::test(flavor = "multi_thread")]
async fn recording_a_discard_needs_a_write_key() {
    let s = setup(None).await;
    let resp = TestClient::new(&s.base, &s.read)
        .post_json("/api/v1/discard-records", discard("2026-08-01", None))
        .await;
    assert_eq!(resp.status(), 403);
}

#[tokio::test(flavor = "multi_thread")]
async fn recording_a_discard_needs_a_credential() {
    let s = setup(None).await;
    let resp = reqwest::Client::new()
        .post(format!("{}/api/v1/discard-records", s.base))
        .json(&discard("2026-08-01", None))
        .send()
        .await
        .expect("the request reaches the node");
    assert_eq!(resp.status(), 401);
}

/// A body that is not JSON is a syntax error, refused before any schema.
#[tokio::test(flavor = "multi_thread")]
async fn a_body_that_is_not_json_is_a_bad_request() {
    let s = setup(None).await;
    let resp = reqwest::Client::new()
        .post(format!("{}/api/v1/discard-records", s.base))
        .bearer_auth(&s.write)
        .header("content-type", "application/json")
        .body("not json")
        .send()
        .await
        .expect("the request reaches the node");
    assert_eq!(resp.status(), 400);
}

/// The removed line-shape route answers nothing: it was replaced, not kept beside.
#[tokio::test(flavor = "multi_thread")]
async fn the_removed_line_route_is_gone() {
    let s = setup(None).await;
    let resp = TestClient::new(&s.base, &s.write)
        .post_json(
            "/api/v1/unsold-goods",
            serde_json::json!({ "reportingPeriod": "2026", "unitCount": 1, "volumeKg": 1.0 }),
        )
        .await;
    assert_eq!(resp.status(), 404);
}

/// An unsold-goods product group is refused as a passport: a disclosure is not
/// one, and core no longer has the group.
#[tokio::test(flavor = "multi_thread")]
async fn an_unsold_goods_passport_is_refused() {
    let s = setup(None).await;
    let body = serde_json::json!({
        "productName": "Unsold jackets",
        "manufacturer": {"name": "Nord Textiles GmbH", "address": "Test"},
        "productGroupData": { "productGroup": "unsold-goods" }
    });
    let resp = TestClient::new(&s.base, &s.write)
        .post_json("/api/v1/dpp", body)
        .await;
    assert_eq!(resp.status(), 422, "unsold-goods is not a product group");
}

// ─── Listing ──────────────────────────────────────────────────────────────────

/// The listing is admin, so a write key cannot read the year back.
#[tokio::test(flavor = "multi_thread")]
async fn listing_a_year_needs_an_admin_key() {
    let s = setup(None).await;
    let resp = TestClient::new(&s.base, &s.write)
        .get("/api/v1/discard-records?financialYearStart=2026-01-01&financialYearEnd=2026-12-31")
        .await;
    assert_eq!(resp.status(), 403);
}

/// A year is two dates; without them there is nothing to list.
#[tokio::test(flavor = "multi_thread")]
async fn listing_without_the_year_is_a_bad_request() {
    let s = setup(None).await;
    let resp = TestClient::new(&s.base, &s.admin)
        .get("/api/v1/discard-records?financialYearStart=2026-01-01")
        .await;
    assert_eq!(resp.status(), 400);
}

// ─── Attaching evidence ───────────────────────────────────────────────────────

/// A document attaches under its kind, with the hash the node computed.
#[tokio::test(flavor = "multi_thread")]
async fn a_document_attaches_under_its_kind() {
    use sha2::{Digest, Sha256};
    let s = setup(None).await;
    let stored = store(&s, discard("2026-08-01", None)).await;
    let id = stored["id"].as_str().expect("an id");

    let resp = attach(
        &s,
        id,
        evidence_form("deliveryDocumentation", b"note".to_vec()),
    )
    .await;
    assert_eq!(
        resp.status(),
        201,
        "{}",
        resp.text().await.unwrap_or_default()
    );
    let body: serde_json::Value = resp.json().await.expect("the attachment");
    assert_eq!(body["kind"], "deliveryDocumentation");
    assert_eq!(body["sizeBytes"], 4);
    // The handler hashes the uploaded bytes as lower-case hex SHA-256.
    let expected = hex::encode(Sha256::digest(b"note"));
    assert_eq!(body["sha256"], expected);
}

/// The same document under the same kind is refused the second time.
#[tokio::test(flavor = "multi_thread")]
async fn the_same_document_under_the_same_kind_is_a_conflict() {
    let s = setup(None).await;
    let stored = store(&s, discard("2026-08-01", None)).await;
    let id = stored["id"].as_str().expect("an id");

    assert_eq!(
        attach(
            &s,
            id,
            evidence_form("deliveryDocumentation", b"note".to_vec())
        )
        .await
        .status(),
        201
    );
    assert_eq!(
        attach(
            &s,
            id,
            evidence_form("deliveryDocumentation", b"note".to_vec())
        )
        .await
        .status(),
        409
    );
}

/// A document cited by two records is stored once.
#[tokio::test(flavor = "multi_thread")]
async fn a_document_cited_by_two_records_is_stored_once() {
    let s = setup(None).await;
    let first = store(&s, discard("2026-08-01", None)).await;
    let second = store(&s, discard("2026-08-02", None)).await;

    for record in [&first, &second] {
        let id = record["id"].as_str().expect("an id");
        assert_eq!(
            attach(
                &s,
                id,
                evidence_form("deliveryDocumentation", b"the same note".to_vec())
            )
            .await
            .status(),
            201
        );
    }

    let rows: i64 = dpp_dal::pg::sqlx::query_scalar("SELECT count(*) FROM odal.evidence_file")
        .fetch_one(s.dal.pool())
        .await
        .expect("a count");
    assert_eq!(rows, 1, "one stored file, cited by two records");
}

/// A file over the 25 MiB cap is refused with `413`.
#[tokio::test(flavor = "multi_thread")]
async fn a_file_over_the_cap_is_refused_with_413() {
    let s = setup(None).await;
    let stored = store(&s, discard("2026-08-01", None)).await;
    let id = stored["id"].as_str().expect("an id");

    let over = vec![0u8; dpp_types::EVIDENCE_FILE_MAX_BYTES + 1];
    let resp = attach(&s, id, evidence_form("deliveryDocumentation", over)).await;
    assert_eq!(resp.status(), 413);
}

/// A file of exactly the cap attaches. The 413 tests above would also pass if
/// the route lost its raised body limit, so this one proves the limit admits
/// a file at the cap.
#[tokio::test(flavor = "multi_thread")]
async fn a_file_at_the_cap_attaches() {
    let s = setup(None).await;
    let stored = store(&s, discard("2026-08-01", None)).await;
    let id = stored["id"].as_str().expect("an id");

    let at_cap = vec![0u8; dpp_types::EVIDENCE_FILE_MAX_BYTES];
    let resp = attach(&s, id, evidence_form("deliveryDocumentation", at_cap)).await;
    assert_eq!(
        resp.status(),
        201,
        "{}",
        resp.text().await.unwrap_or_default()
    );
    let body: serde_json::Value = resp.json().await.expect("the attachment");
    assert_eq!(body["sizeBytes"], dpp_types::EVIDENCE_FILE_MAX_BYTES);
}

/// A form far past the cap is refused by the body limit, also as `413`.
#[tokio::test(flavor = "multi_thread")]
async fn a_form_far_past_the_cap_is_refused_by_the_body_limit_with_413() {
    let s = setup(None).await;
    let stored = store(&s, discard("2026-08-01", None)).await;
    let id = stored["id"].as_str().expect("an id");

    let far_over = vec![0u8; dpp_types::EVIDENCE_FILE_MAX_BYTES + 4 * 1024 * 1024];
    let resp = attach(&s, id, evidence_form("deliveryDocumentation", far_over)).await;
    assert_eq!(resp.status(), 413);
}

/// The kind must be one core names, and both fields must be present.
#[tokio::test(flavor = "multi_thread")]
async fn an_attachment_needs_a_known_kind_and_a_file() {
    let s = setup(None).await;
    let stored = store(&s, discard("2026-08-01", None)).await;
    let id = stored["id"].as_str().expect("an id");

    assert_eq!(
        attach(&s, id, evidence_form("receipt", b"x".to_vec()))
            .await
            .status(),
        422,
        "a kind core does not name is refused"
    );
    let no_file = reqwest::multipart::Form::new().text("kind", "deliveryDocumentation");
    assert_eq!(attach(&s, id, no_file).await.status(), 422);
    let no_kind = reqwest::multipart::Form::new().part(
        "file",
        reqwest::multipart::Part::bytes(b"x".to_vec()).file_name("x.pdf"),
    );
    assert_eq!(attach(&s, id, no_kind).await.status(), 422);
}

/// An unknown record is `404`; a malformed id is `400`, before anything is read.
#[tokio::test(flavor = "multi_thread")]
async fn attaching_to_an_unknown_or_malformed_record() {
    let s = setup(None).await;
    let unknown = "00000000-0000-7000-8000-00000000abcd";
    assert_eq!(
        attach(
            &s,
            unknown,
            evidence_form("deliveryDocumentation", b"x".to_vec())
        )
        .await
        .status(),
        404
    );
    assert_eq!(
        attach(
            &s,
            "not-a-record",
            evidence_form("deliveryDocumentation", b"x".to_vec())
        )
        .await
        .status(),
        400
    );
}

// ─── What a record still lacks ────────────────────────────────────────────────

/// A damaged discard, sent to recycling, owes delivery, treatment and quality
/// documents; each attachment takes one off the list.
#[tokio::test(flavor = "multi_thread")]
async fn what_a_record_lacks_shrinks_as_documents_are_attached() {
    let s = setup(None).await;
    let stored = store(&s, discard("2026-08-01", Some("damagedOrContaminated"))).await;
    let id = stored["id"].as_str().expect("an id").to_owned();
    let missing = |body: &serde_json::Value| {
        body["missingEvidence"]
            .as_array()
            .expect("a list")
            .iter()
            .map(|r| r["anyOf"][0].as_str().unwrap_or("").to_owned())
            .collect::<Vec<String>>()
    };

    let client = TestClient::new(&s.base, &s.admin);
    let before: serde_json::Value = client
        .get(&format!("/api/v1/discard-records/{id}/missing-evidence"))
        .await
        .json()
        .await
        .expect("the answer");
    assert_eq!(
        before["enterpriseSize"], "large",
        "an unset size reads as large"
    );
    assert_eq!(
        missing(&before),
        vec![
            "deliveryDocumentation",
            "treatmentStatement",
            "qualityAssessmentEvidence"
        ]
    );

    attach(
        &s,
        &id,
        evidence_form("deliveryDocumentation", b"note".to_vec()),
    )
    .await;
    attach(
        &s,
        &id,
        evidence_form("treatmentStatement", b"statement".to_vec()),
    )
    .await;
    let after: serde_json::Value = client
        .get(&format!("/api/v1/discard-records/{id}/missing-evidence"))
        .await
        .json()
        .await
        .expect("the answer");
    assert_eq!(missing(&after), vec!["qualityAssessmentEvidence"]);
}

/// A micro-enterprise owes nothing for a discard, so its list is empty.
#[tokio::test(flavor = "multi_thread")]
async fn a_micro_enterprise_owes_no_evidence_for_a_discard() {
    let s = setup(Some(dpp_domain::unsold_goods::EnterpriseSize::Micro)).await;
    let stored = store(&s, discard("2026-08-01", Some("damagedOrContaminated"))).await;
    let id = stored["id"].as_str().expect("an id");

    let body: serde_json::Value = TestClient::new(&s.base, &s.admin)
        .get(&format!("/api/v1/discard-records/{id}/missing-evidence"))
        .await
        .json()
        .await
        .expect("the answer");
    assert_eq!(body["enterpriseSize"], "micro");
    assert_eq!(body["missingEvidence"], serde_json::json!([]));
}

/// The missing-evidence answer is admin, and an unknown or malformed record is
/// refused as the other routes refuse them.
#[tokio::test(flavor = "multi_thread")]
async fn missing_evidence_is_admin_and_refuses_unknown_and_malformed_records() {
    let s = setup(None).await;
    let stored = store(&s, discard("2026-08-01", None)).await;
    let id = stored["id"].as_str().expect("an id");

    assert_eq!(
        TestClient::new(&s.base, &s.write)
            .get(&format!("/api/v1/discard-records/{id}/missing-evidence"))
            .await
            .status(),
        403
    );
    assert_eq!(
        TestClient::new(&s.base, &s.admin)
            .get("/api/v1/discard-records/00000000-0000-7000-8000-00000000abcd/missing-evidence")
            .await
            .status(),
        404
    );
    assert_eq!(
        TestClient::new(&s.base, &s.admin)
            .get("/api/v1/discard-records/not-a-record/missing-evidence")
            .await
            .status(),
        400
    );
}

// ─── Citing a record from an end-of-life destruction ─────────────────────────

/// A battery passport, published, so that it can be declared end of life.
async fn published_passport(s: &Setup) -> String {
    let client = TestClient::new(&s.base, &s.write);
    let draft = serde_json::json!({
        "productName": "Discarded battery",
        "manufacturer": {"name": "Nord Batteries GmbH", "address": "Test"},
        "materials": [{"name": "Nickel", "weightKg": 0.5}],
        "productGroupData": {
            "productGroup": "battery",
            "productIdentifier": { "scheme": "gs1", "gtin": "09506000134352" },
            "batteryChemistry": "NiMH",
            "batteryType": "portable",
            "nominalVoltageV": 12.0,
            "nominalCapacityAh": 40.0,
            "expectedLifetimeCycles": 1000,
            "co2ePerUnitKg": 20.0
        }
    });
    let created: serde_json::Value = client
        .post_json("/api/v1/dpp", draft)
        .await
        .json()
        .await
        .expect("the created passport");
    let id = created["id"].as_str().expect("an id").to_owned();
    let published = client
        .post_json(&format!("/api/v1/dpp/{id}/publish"), serde_json::json!({}))
        .await;
    assert_eq!(
        published.status(),
        200,
        "{}",
        published.text().await.unwrap_or_default()
    );
    id
}

async fn declare_eol(s: &Setup, passport: &str, body: serde_json::Value) -> reqwest::Response {
    TestClient::new(&s.base, &s.write)
        .post_json(&format!("/api/v1/dpp/{passport}/eol"), body)
        .await
}

async fn passport_status(s: &Setup, passport: &str) -> String {
    let body: serde_json::Value = TestClient::new(&s.base, &s.admin)
        .get(&format!("/api/v1/dpp/{passport}"))
        .await
        .json()
        .await
        .expect("the passport");
    body["status"].as_str().unwrap_or("").to_owned()
}

/// A destruction that cites a record for the same derogation point is recorded,
/// and the passport is joined to the record.
#[tokio::test(flavor = "multi_thread")]
async fn a_destruction_is_joined_to_the_record_that_cites_its_point() {
    let s = setup(None).await;
    let record = store(&s, discard("2026-08-01", Some("damagedOrContaminated"))).await;
    let record_id = record["id"].as_str().expect("an id").to_owned();
    let passport = published_passport(&s).await;

    let resp = declare_eol(
        &s,
        &passport,
        serde_json::json!({
            "reason": {"kind": "destroyed", "derogation": "damagedOrContaminated"},
            "unsold": false,
            "discardRecordId": record_id
        }),
    )
    .await;
    assert_eq!(
        resp.status(),
        200,
        "{}",
        resp.text().await.unwrap_or_default()
    );

    let joined: i64 = dpp_dal::pg::sqlx::query_scalar(
        "SELECT count(*) FROM odal.discard_record_passport
          WHERE discard_record_id = $1::uuid AND passport_id = $2::uuid",
    )
    .bind(&record_id)
    .bind(&passport)
    .fetch_one(s.dal.pool())
    .await
    .expect("a count");
    assert_eq!(
        joined, 1,
        "the destruction is joined to the record that documents it"
    );

    // The citation is in the tamper-evident chain too: the deactivation's audit
    // entry carries the record id beside the serialised EOL reason.
    let cited_in_audit: i64 = dpp_dal::pg::sqlx::query_scalar(
        "SELECT count(*) FROM odal.passport_audit
          WHERE passport_id = $1 AND action = 'deactivated'
            AND metadata->>'discardRecordId' = $2",
    )
    .bind(&passport)
    .bind(&record_id)
    .fetch_one(s.dal.pool())
    .await
    .expect("a count");
    assert_eq!(
        cited_in_audit, 1,
        "the deactivation's audit entry records the discard record it cites"
    );
}

/// A record for another derogation point documents a different act, so the
/// destruction is refused, the passport is unchanged, and nothing is joined.
#[tokio::test(flavor = "multi_thread")]
async fn a_record_citing_another_point_does_not_document_the_destruction() {
    let s = setup(None).await;
    let record = store(&s, discard("2026-08-01", Some("damagedOrContaminated"))).await;
    let record_id = record["id"].as_str().expect("an id").to_owned();
    let passport = published_passport(&s).await;

    let resp = declare_eol(
        &s,
        &passport,
        serde_json::json!({
            "reason": {"kind": "destroyed", "derogation": "dangerousProduct"},
            "unsold": false,
            "discardRecordId": record_id
        }),
    )
    .await;
    assert_eq!(resp.status(), 422);
    assert_eq!(
        passport_status(&s, &passport).await,
        "active",
        "a refused declaration changed nothing"
    );
    let joined: i64 =
        dpp_dal::pg::sqlx::query_scalar("SELECT count(*) FROM odal.discard_record_passport")
            .fetch_one(s.dal.pool())
            .await
            .expect("a count");
    assert_eq!(joined, 0);
}

/// A destruction that cites no point and a record that cites no point agree, so
/// the destruction is recorded and the passport is joined to the record.
#[tokio::test(flavor = "multi_thread")]
async fn a_destruction_without_a_point_is_joined_to_a_record_that_cites_none() {
    let s = setup(None).await;
    let uncited = store(&s, discard("2026-08-01", None)).await;
    let uncited_id = uncited["id"].as_str().expect("an id").to_owned();
    let passport = published_passport(&s).await;

    let resp = declare_eol(
        &s,
        &passport,
        serde_json::json!({
            "reason": {"kind": "destroyed"},
            "unsold": false,
            "discardRecordId": uncited_id
        }),
    )
    .await;
    assert_eq!(
        resp.status(),
        200,
        "{}",
        resp.text().await.unwrap_or_default()
    );

    let joined: i64 = dpp_dal::pg::sqlx::query_scalar(
        "SELECT count(*) FROM odal.discard_record_passport
          WHERE discard_record_id = $1::uuid AND passport_id = $2::uuid",
    )
    .bind(&uncited_id)
    .bind(&passport)
    .fetch_one(s.dal.pool())
    .await
    .expect("a count");
    assert_eq!(
        joined, 1,
        "both cite no point, so the destruction is joined to the record"
    );
}

/// A point on one side only is a mismatch, in either direction, and a refused
/// declaration changes nothing.
#[tokio::test(flavor = "multi_thread")]
async fn a_point_cited_on_one_side_only_is_refused() {
    let s = setup(None).await;
    let uncited = store(&s, discard("2026-08-01", None)).await;
    let uncited_id = uncited["id"].as_str().expect("an id").to_owned();
    let cited = store(&s, discard("2026-08-02", Some("damagedOrContaminated"))).await;
    let cited_id = cited["id"].as_str().expect("an id").to_owned();
    let passport = published_passport(&s).await;

    let point_against_uncited = declare_eol(
        &s,
        &passport,
        serde_json::json!({
            "reason": {"kind": "destroyed", "derogation": "dangerousProduct"},
            "unsold": false,
            "discardRecordId": uncited_id
        }),
    )
    .await;
    assert_eq!(
        point_against_uncited.status(),
        422,
        "the destruction cites a point the record does not"
    );

    let no_point_against_cited = declare_eol(
        &s,
        &passport,
        serde_json::json!({
            "reason": {"kind": "destroyed"},
            "unsold": false,
            "discardRecordId": cited_id
        }),
    )
    .await;
    assert_eq!(
        no_point_against_cited.status(),
        422,
        "the record cites a point the destruction does not"
    );
    assert_eq!(passport_status(&s, &passport).await, "active");
}

/// The record must exist, and it is named only with a destruction.
#[tokio::test(flavor = "multi_thread")]
async fn a_record_is_named_only_by_an_existing_destruction() {
    let s = setup(None).await;
    let record = store(&s, discard("2026-08-01", Some("damagedOrContaminated"))).await;
    let record_id = record["id"].as_str().expect("an id").to_owned();
    let passport = published_passport(&s).await;

    let unknown = declare_eol(
        &s,
        &passport,
        serde_json::json!({
            "reason": {"kind": "destroyed", "derogation": "damagedOrContaminated"},
            "unsold": false,
            "discardRecordId": "00000000-0000-7000-8000-00000000abcd"
        }),
    )
    .await;
    assert_eq!(
        unknown.status(),
        422,
        "a record the node does not hold is refused"
    );

    let not_a_destruction = declare_eol(
        &s,
        &passport,
        serde_json::json!({
            "reason": {"kind": "recycled"},
            "discardRecordId": record_id
        }),
    )
    .await;
    assert_eq!(
        not_a_destruction.status(),
        422,
        "a recycled passport is not a discard"
    );
    assert_eq!(passport_status(&s, &passport).await, "active");
}
