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
use dpp_dal::pg::{PgDal, PgPassportRepo, PgTransferRepo};
use dpp_domain::passport::{ManufacturerInfo, Passport, PassportId};
use dpp_domain::ports::passport_repo::PassportRepository;
use dpp_domain::product_group::ProductGroup;
use dpp_domain::seal::{SealFormat, SealedEnvelope};
use dpp_domain::status::PassportStatus;
use dpp_domain::transfer::{
    OperatorRole, ResponsibleOperator, TransferChain, TransferReason, TransferRecord,
};
use dpp_types::TransferStore;
use uuid::Uuid;

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
        product_group: ProductGroup::Battery,
        applicable_instruments: Vec::new(),
        granularity: None,
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
        product_group_data: None,
        status: PassportStatus::Published,
        qr_code_url: None,
        jws_signature: jws.map(ToOwned::to_owned),
        public_jws_signature: None,
        disclosure_signatures: Default::default(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        published_at: Some(Utc::now()),
        placed_on_market_date: None,
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

/// The summary counts **passports**, not outbox rows, and this is the case that
/// makes the distinction load-bearing.
///
/// `enqueue` runs after the publish commits, so a crash in that window leaves a
/// published passport with no row anywhere. An empty outbox is therefore fully
/// consistent with unsealed passports — and a summary built on row counts alone
/// would report all clear while the obligation went unmet. Seeding a published,
/// unsealed passport and no rows at all reproduces exactly that state.
#[tokio::test(flavor = "multi_thread")]
async fn the_summary_counts_unsealed_passports_not_outbox_rows() {
    let pg = start_postgres().await;
    let base = start_vault(pg.dal.clone()).await;
    seed(&pg.dal, None, Some(JWS)).await;
    let client = TestClient::new(&base, make_jwt(&op()));

    let resp = client.get("/api/v1/seal").await;
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();

    assert_eq!(
        body["unsealedPublished"], 1,
        "a published passport with no seal must be counted, with or without a row"
    );
    assert_eq!(
        body["pending"], 0,
        "no row was ever enqueued — this is the lost-enqueue state"
    );
    assert_eq!(body["exhausted"], 0);
    assert_eq!(
        body["sealingConfigured"], true,
        "the harness wires an outbox, as any node with a provider does"
    );
}

/// A sealed passport is not counted, and the count is what a reader acts on.
#[tokio::test(flavor = "multi_thread")]
async fn a_sealed_passport_is_not_reported_as_unsealed() {
    let pg = start_postgres().await;
    let base = start_vault(pg.dal.clone()).await;
    seed(&pg.dal, Some(envelope()), Some(JWS)).await;
    let client = TestClient::new(&base, make_jwt(&op()));

    let resp = client.get("/api/v1/seal").await;
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["unsealedPublished"], 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_summary_route_requires_authentication() {
    let pg = start_postgres().await;
    let base = start_vault(pg.dal.clone()).await;
    let client = reqwest::Client::new();

    let resp = client
        .get(format!("{base}/api/v1/seal"))
        .send()
        .await
        .expect("request");
    assert_eq!(resp.status(), 401);
}

/// **A seal is never served without a legible declaring party.**
///
/// A seal proves a document came from whoever holds the certificate. It says
/// nothing about *scope* — "we vouch for this content" and "we transmitted this
/// intact" look identical — so a response carrying a seal and no declarer lets a
/// reader conclude the sealer authored the content.
///
/// Every audience view strips the seal, which makes this route the only surface
/// where that conclusion is reachable. Its readers being authenticated and
/// technical is a reason to be more careful, not less: they are the ones who
/// build systems on the assumption.
#[tokio::test(flavor = "multi_thread")]
async fn a_served_seal_always_names_who_declared_the_content() {
    let pg = start_postgres().await;
    let base = start_vault(pg.dal.clone()).await;
    let id = seed(&pg.dal, Some(envelope()), Some(JWS)).await;
    let client = TestClient::new(&base, make_jwt(&op()));

    let resp = client.get(&format!("/api/v1/dpp/{id}/seal")).await;
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();

    // The property, asserted against the seal rather than on its own: if a seal
    // is present, a declarer must be too.
    assert!(
        body.get("sealValue").is_some(),
        "fixture must actually serve a seal, or this proves nothing"
    );
    let declared = &body["declaredBy"];
    assert_eq!(
        declared["manufacturer"], "TestCorp GmbH",
        "the declaring party must be legible beside the seal: {body}"
    );

    // Nothing was transferred, so the response must not hint that it was.
    assert_eq!(
        declared["responsibilityMayHaveTransferred"], false,
        "an untransferred passport must not suggest responsibility moved"
    );

    // And the distinction is stated, not left to be inferred from field names.
    let note = declared["note"].as_str().expect("note present");
    assert!(
        note.contains("no statement about who authored"),
        "the note must separate sealing from authorship: {note}"
    );
}

/// **The flag flips when a handover actually completed.**
///
/// The test above pins the `false` side, which is the easy half: a passport with
/// no completed handover must not hint that responsibility moved. This pins the
/// half the field exists for — and it is the one that can rot silently, because
/// every way of *failing* to detect a transfer produces `false`, which is also
/// the correct answer almost everywhere.
///
/// That is not hypothetical. Until the harness wired a transfer store, the seal
/// handler took its `None => false` branch on every request here, so the `false`
/// assertion above held because nothing could be recorded rather than because
/// nothing was. Both sides are now asserted against the same wiring production
/// uses.
#[tokio::test(flavor = "multi_thread")]
async fn a_completed_handover_says_responsibility_may_have_moved() {
    let pg = start_postgres().await;
    let base = start_vault(pg.dal.clone()).await;
    let id = seed(&pg.dal, Some(envelope()), Some(JWS)).await;

    // A chain carrying one *completed* handover. Written straight to the store
    // rather than driven through initiate/accept, because this test is about
    // what the seal route reports, not about how a transfer gets completed —
    // that path has its own tests.
    let operator = |did: &str, name: &str| ResponsibleOperator {
        did: did.to_owned(),
        name: name.to_owned(),
        role: OperatorRole::Manufacturer,
        eu_operator_id: None,
        eu_operator_id_scheme: None,
        country: "DE".to_owned(),
    };
    let from = operator("did:web:acme.example", "Acme GmbH");
    let mut chain = TransferChain::new(id, from.clone());
    chain
        .initiate_transfer(TransferRecord {
            transfer_id: Uuid::now_v7(),
            passport_id: id,
            from_operator: from,
            to_operator: operator("did:web:reco.example", "ReCo"),
            reason: TransferReason::Sale,
            // All three present is what `status()` reads as `Completed`; the
            // signatures are opaque to this route.
            from_signature: Some("from-jws".to_owned()),
            node_acceptance_attestation: Some("to-jws".to_owned()),
            initiated_at: Utc::now(),
            completed_at: Some(Utc::now()),
            rejected_at: None,
            cancelled_at: None,
            notes: None,
        })
        .expect("chain accepts the first handover");
    PgTransferRepo::new(pg.dal.clone())
        .save_chain(&chain)
        .await
        .expect("save transfer chain");

    let client = TestClient::new(&base, make_jwt(&op()));
    let resp = client.get(&format!("/api/v1/dpp/{id}/seal")).await;
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();

    assert_eq!(
        body["declaredBy"]["responsibilityMayHaveTransferred"],
        serde_json::Value::Bool(true),
        "a completed handover must be reported beside the seal: {body}"
    );

    // The declarer itself is still the party frozen at publish — the whole point
    // of the flag is that these two answers differ.
    assert_eq!(
        body["declaredBy"]["manufacturer"], "TestCorp GmbH",
        "the sealed names are frozen and must not be rewritten by a transfer"
    );
}
