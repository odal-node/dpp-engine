//! `POST /api/v1/dpp/{dppId}/seal/repair` over real HTTP.
//!
//! This is the only route in the vault that **spends money**: it re-arms a row
//! whose seal was already bought, so the node's drain buys a second one. Every
//! other sealing path is explicitly built not to — `enqueue` re-arms `exhausted`
//! rows only, and the unsealed sweep queues passports carrying no seal at all —
//! and each of those carries its reasoning in its own code.
//!
//! So what is asserted here is mostly **refusals**. The full loop (corrupt a
//! stored seal, find it, repair it, watch the replacement bind) is proven in the
//! node's simulation against real CAdES bytes; what that suite cannot reach is
//! the handler's judgement about *when* the line may be crossed, because it
//! never has a broken seal and a sound one to tell apart. Each test below is one
//! state that looks repairable and is not.
//!
//! The inspector is scripted rather than real, and deliberately: the vault must
//! not link the crate that parses CAdES — it depends on the *question*, not on
//! whichever adapter answers it. Every branch of this handler is chosen by that
//! one verdict, and the adapter that produces it for real bytes is proven where
//! it lives.

#![cfg(feature = "integration-tests")]

mod helpers;
use helpers::{
    SealWiring, TestClient, make_jwt, make_jwt_scoped, start_postgres, start_vault,
    start_vault_with_seal,
};

use std::sync::Arc;

use chrono::{DateTime, Utc};
use dpp_dal::pg::{PgDal, PgPassportRepo, PgSealOutboxRepo};
use dpp_domain::passport::{ManufacturerInfo, Passport, PassportId};
use dpp_domain::ports::passport_repo::PassportRepository;
use dpp_domain::product_group::ProductGroup;
use dpp_domain::seal::{SealConformanceLevel, SealFormat, SealedEnvelope};
use dpp_domain::status::PassportStatus;
use dpp_types::{ArchivalFreshness, SealBinding, SealInspector, SealOrigin, SealOutbox};

fn op() -> String {
    "00000000-0000-0000-0000-000000000001".to_owned()
}

/// Not JWT-shaped on purpose — nothing here parses it, and a realistic compact
/// JWS would only trip secret scanners on a literal that is not a credential.
const JWS: &str = "header.payload.signature";

/// An inspector whose verdict is whatever the test says it is.
struct ScriptedInspector(SealBinding);

impl SealInspector for ScriptedInspector {
    fn origin(&self, _envelope: &SealedEnvelope) -> Option<SealOrigin> {
        None
    }

    fn binding(&self, _envelope: &SealedEnvelope, _payload_hash: &str) -> SealBinding {
        self.0.clone()
    }

    fn evidenced_level(&self, _envelope: &SealedEnvelope) -> Option<SealConformanceLevel> {
        None
    }

    fn attested_sealing_time(&self, _envelope: &SealedEnvelope) -> Option<DateTime<Utc>> {
        None
    }

    fn archival_freshness(
        &self,
        _envelope: &SealedEnvelope,
        _now: DateTime<Utc>,
    ) -> ArchivalFreshness {
        ArchivalFreshness::NotArchived
    }

    /// Nothing: this suite is about the repair route's judgement of the
    /// *binding*, and a scripted certificate standing would only add a second
    /// scripted value for the handler to ignore.
    fn certificate_standing(
        &self,
        _envelope: &SealedEnvelope,
        _now: DateTime<Utc>,
    ) -> Option<dpp_types::CertificateStanding> {
        None
    }
}

/// A vault whose stored seals all read as `verdict`.
async fn vault_reading(dal: &PgDal, verdict: SealBinding) -> String {
    start_vault_with_seal(
        dal.clone(),
        SealWiring {
            inspector: Some(Arc::new(ScriptedInspector(verdict))),
            outbox: true,
        },
    )
    .await
}

/// A published, signed passport carrying no seal yet.
async fn seed(dal: &PgDal) -> PassportId {
    let passport = Passport {
        id: PassportId::new(),
        batch_id: None,
        serial_number: None,
        product_name: "Repair Route Battery".into(),
        product_group: ProductGroup::Battery,
        applicable_instruments: Vec::new(),
        granularity: None,
        manufacturer: ManufacturerInfo {
            name: "TestCorp GmbH".into(),
            address: "Berlin, DE".into(),
            registered_trade_name: None,
            electronic_address: None,
            country: None,
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
        jws_signature: Some(JWS.to_owned()),
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
        derived_from: Vec::new(),
        component_refs: Vec::new(),
        life_status: None,
        retention_until: None,
        product_id: None,
        commodity_code: None,
        operator_identifier: None,
        responsible_operator: None,
        facility: None,
        seal: None,
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
        conformance_level: None,
        sealed_at: Utc::now(),
        placeholder: false,
    }
}

/// Take one passport all the way to a closed `sealed` row over `digest`.
///
/// Driven through the outbox port rather than written with SQL: `mark_sealed`
/// is what puts the envelope on the passport in production, and a fixture that
/// wrote both halves itself could put them in a combination the drain cannot
/// produce.
async fn seal_it(dal: &PgDal, id: PassportId, digest: &str) {
    let outbox = PgSealOutboxRepo::new(dal.clone());
    outbox.enqueue(id, digest).await.expect("queue");
    let due = outbox.due(10).await.expect("due");
    let row = due
        .iter()
        .find(|r| r.passport_id == id)
        .expect("the row just queued is due");
    outbox
        .mark_sealed(row.id, &envelope())
        .await
        .expect("close the row");
}

async fn counts(dal: &PgDal) -> dpp_types::SealOutboxCounts {
    PgSealOutboxRepo::new(dal.clone())
        .status_counts()
        .await
        .expect("counts")
}

fn detail(body: &serde_json::Value) -> String {
    body["detail"].as_str().unwrap_or_default().to_owned()
}

fn note(body: &serde_json::Value) -> String {
    body["note"].as_str().unwrap_or_default().to_owned()
}

// ---------------------------------------------------------------------------
// The two repairs
// ---------------------------------------------------------------------------

/// **A broken seal is re-armed, and the response names the digest it will buy.**
///
/// The payload hash matters as much as the action: a replacement covers the
/// passport's *current* signature, so an operator reading the response can check
/// what they are paying for against what the passport now carries.
#[tokio::test(flavor = "multi_thread")]
async fn a_broken_seal_is_rearmed_and_names_the_digest_it_will_cover() {
    let pg = start_postgres().await;
    let base = vault_reading(&pg.dal, SealBinding::NotIntact).await;
    let id = seed(&pg.dal).await;
    let digest = dpp_types::digest_for_jws(JWS);
    seal_it(&pg.dal, id, &digest).await;
    assert_eq!(counts(&pg.dal).await.sealed, 1, "fixture must start sealed");

    let client = TestClient::new(&base, make_jwt(&op()));
    let resp = client
        .post_json(
            &format!("/api/v1/dpp/{id}/seal/repair"),
            serde_json::json!({}),
        )
        .await;
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();

    assert_eq!(
        body["action"], "rearmed",
        "a sealed row over this digest is re-armed, not queued afresh: {body}"
    );
    assert_eq!(
        body["payloadHash"], digest,
        "the response must name the signature the replacement will cover"
    );
    assert!(
        note(&body).contains("costs a seal"),
        "the note must say plainly that this spends: {body}"
    );

    let after = counts(&pg.dal).await;
    assert_eq!(after.pending, 1, "the row is back in front of the drain");
    assert_eq!(
        after.sealed, 0,
        "and is no longer counted as a seal this node holds"
    );
}

/// **A broken seal over a superseded signature is queued, and buys nothing
/// twice.**
///
/// The passport was re-published after the seal was made, so the digest now
/// needing a seal has never been sealed. That makes this an ordinary enqueue —
/// the distinction the response draws between `rearmed` and `queued` — and the
/// old row must be left exactly where it is, because it still records a seal
/// that was bought.
#[tokio::test(flavor = "multi_thread")]
async fn a_broken_seal_over_a_superseded_signature_is_queued_not_rearmed() {
    let pg = start_postgres().await;
    let base = vault_reading(&pg.dal, SealBinding::NotIntact).await;
    let id = seed(&pg.dal).await;

    // Sealed over an older signature than the one the passport now carries.
    let superseded = dpp_types::digest_for_jws("header.older-payload.signature");
    seal_it(&pg.dal, id, &superseded).await;

    let client = TestClient::new(&base, make_jwt(&op()));
    let resp = client
        .post_json(
            &format!("/api/v1/dpp/{id}/seal/repair"),
            serde_json::json!({}),
        )
        .await;
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();

    assert_eq!(body["action"], "queued");
    assert_eq!(
        body["payloadHash"],
        dpp_types::digest_for_jws(JWS),
        "the queued row must cover the passport's current signature"
    );

    let after = counts(&pg.dal).await;
    assert_eq!(after.pending, 1, "one new row, for the current signature");
    assert_eq!(
        after.sealed, 1,
        "and the row recording the seal that was already bought is untouched"
    );
}

/// **Retrying a repair queues nothing more.**
///
/// The route is not idempotency-keyed, and this is the claim that stands in for
/// a key: a seal row is keyed by `(passport_id, payload_hash)`, so a second
/// request lands on a row that is already `pending` — which `enqueue` leaves
/// alone and `rearm_sealed` does not match. A client that retries on a timeout
/// must not buy a third seal.
#[tokio::test(flavor = "multi_thread")]
async fn a_repeated_repair_does_not_queue_a_second_seal() {
    let pg = start_postgres().await;
    let base = vault_reading(&pg.dal, SealBinding::NotIntact).await;
    let id = seed(&pg.dal).await;
    seal_it(&pg.dal, id, &dpp_types::digest_for_jws(JWS)).await;

    let client = TestClient::new(&base, make_jwt(&op()));
    let path = format!("/api/v1/dpp/{id}/seal/repair");
    let first = client.post_json(&path, serde_json::json!({})).await;
    assert_eq!(first.status(), 200);

    let second = client.post_json(&path, serde_json::json!({})).await;
    assert_eq!(second.status(), 200, "a retry is answered, not rejected");
    let body: serde_json::Value = second.json().await.unwrap();
    assert_eq!(
        body["action"], "queued",
        "there is no sealed row left to re-arm — the repair is already in flight"
    );

    let after = counts(&pg.dal).await;
    assert_eq!(
        after.pending, 1,
        "still exactly one repair queued, not one per request"
    );
    assert_eq!(after.sealed, 0);
}

// ---------------------------------------------------------------------------
// The refusals — each is a state that looks repairable and is not
// ---------------------------------------------------------------------------

/// A seal that verifies over this signature is the healthy state. Repairing it
/// would buy a second seal for a sound one, which is the failure this route
/// exists to make impossible rather than merely unlikely.
#[tokio::test(flavor = "multi_thread")]
async fn a_sound_seal_is_refused() {
    let pg = start_postgres().await;
    let base = vault_reading(&pg.dal, SealBinding::CoversThisSignature).await;
    let id = seed(&pg.dal).await;
    seal_it(&pg.dal, id, &dpp_types::digest_for_jws(JWS)).await;

    let client = TestClient::new(&base, make_jwt(&op()));
    let resp = client
        .post_json(
            &format!("/api/v1/dpp/{id}/seal/repair"),
            serde_json::json!({}),
        )
        .await;
    assert_eq!(resp.status(), 422);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(
        detail(&body).contains("verifies"),
        "the refusal must say the seal is sound: {body}"
    );

    assert_eq!(
        counts(&pg.dal).await.pending,
        0,
        "and nothing may be queued on the way to refusing"
    );
}

/// An **intact** seal over another digest is an ordinary re-publish, not damage.
/// The signature now needing a seal already has its own row from that publish,
/// so there is nothing here to repair — and the seal being repaired would still
/// be a valid attestation of the signature it covers.
#[tokio::test(flavor = "multi_thread")]
async fn a_superseded_but_intact_seal_is_refused() {
    let pg = start_postgres().await;
    let base = vault_reading(
        &pg.dal,
        SealBinding::CoversAnotherDigest {
            covered: "00".repeat(32),
        },
    )
    .await;
    let id = seed(&pg.dal).await;
    seal_it(&pg.dal, id, &dpp_types::digest_for_jws(JWS)).await;

    let client = TestClient::new(&base, make_jwt(&op()));
    let resp = client
        .post_json(
            &format!("/api/v1/dpp/{id}/seal/repair"),
            serde_json::json!({}),
        )
        .await;
    assert_eq!(resp.status(), 422);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(
        detail(&body).contains("re-published"),
        "the refusal must name the ordinary cause rather than imply damage: {body}"
    );
    assert_eq!(counts(&pg.dal).await.pending, 0);
}

/// **"Cannot check" must not become "worthless".**
///
/// An unreadable seal may be a format this node does not parse, or a provider's
/// envelope this adapter has never met. Treating that as broken would spend an
/// operator's money on the node's own ignorance — and would do it at exactly the
/// moment a new provider was introduced.
#[tokio::test(flavor = "multi_thread")]
async fn an_unreadable_seal_is_refused() {
    let pg = start_postgres().await;
    let base = vault_reading(&pg.dal, SealBinding::Unknown).await;
    let id = seed(&pg.dal).await;
    seal_it(&pg.dal, id, &dpp_types::digest_for_jws(JWS)).await;

    let client = TestClient::new(&base, make_jwt(&op()));
    let resp = client
        .post_json(
            &format!("/api/v1/dpp/{id}/seal/repair"),
            serde_json::json!({}),
        )
        .await;
    assert_eq!(resp.status(), 422);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(
        detail(&body).contains("could not be read"),
        "the refusal must distinguish unreadable from broken: {body}"
    );
    assert_eq!(counts(&pg.dal).await.pending, 0);
}

/// A passport with no seal is the sweep's job, and the sweep costs nothing
/// extra because no seal was ever bought for it. Answering here would route an
/// ordinary case through the one path that can double-bill.
#[tokio::test(flavor = "multi_thread")]
async fn a_passport_with_no_seal_is_refused() {
    let pg = start_postgres().await;
    let base = vault_reading(&pg.dal, SealBinding::NotIntact).await;
    let id = seed(&pg.dal).await;

    let client = TestClient::new(&base, make_jwt(&op()));
    let resp = client
        .post_json(
            &format!("/api/v1/dpp/{id}/seal/repair"),
            serde_json::json!({}),
        )
        .await;
    assert_eq!(resp.status(), 422);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(
        detail(&body).contains("no seal"),
        "the refusal must point at the sweep rather than repair: {body}"
    );
}

/// A node that cannot open a seal cannot establish that one is broken, so it
/// must not act on the assumption that it is. This is the shipped default: the
/// CAdES reader is resolved by the composition root, and a standalone vault
/// links nothing that parses seals.
#[tokio::test(flavor = "multi_thread")]
async fn a_node_that_cannot_read_seals_refuses_to_repair() {
    let pg = start_postgres().await;
    let base = start_vault(pg.dal.clone()).await;
    let id = seed(&pg.dal).await;
    seal_it(&pg.dal, id, &dpp_types::digest_for_jws(JWS)).await;

    let client = TestClient::new(&base, make_jwt(&op()));
    let resp = client
        .post_json(
            &format!("/api/v1/dpp/{id}/seal/repair"),
            serde_json::json!({}),
        )
        .await;
    assert_eq!(resp.status(), 422);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(
        detail(&body).contains("cannot read seals"),
        "the refusal must name the missing capability: {body}"
    );
}

/// **A queued repair on a node with nothing to drain is a lie.**
///
/// The row would sit for ever while the response said the repair was under way.
/// The only honest answer is to refuse and say what is missing — and this one
/// only surfaced from asking what happens *after* the row is written.
#[tokio::test(flavor = "multi_thread")]
async fn a_node_with_no_sealing_backend_refuses_to_repair() {
    let pg = start_postgres().await;
    let id = seed(&pg.dal).await;
    // Seeded while an outbox still exists, then served by a vault without one —
    // the state a node lands in when a provider is removed from its config.
    seal_it(&pg.dal, id, &dpp_types::digest_for_jws(JWS)).await;

    let base = start_vault_with_seal(
        pg.dal.clone(),
        SealWiring {
            inspector: Some(Arc::new(ScriptedInspector(SealBinding::NotIntact))),
            outbox: false,
        },
    )
    .await;
    let client = TestClient::new(&base, make_jwt(&op()));
    let resp = client
        .post_json(
            &format!("/api/v1/dpp/{id}/seal/repair"),
            serde_json::json!({}),
        )
        .await;
    assert_eq!(resp.status(), 422);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(
        detail(&body).contains("never drain"),
        "the refusal must say why a queued repair would not help: {body}"
    );
}

// ---------------------------------------------------------------------------
// Who may ask
// ---------------------------------------------------------------------------

/// Spending an operator's money is an admin action. A write-scoped key can
/// publish all day and still must not buy a second seal.
#[tokio::test(flavor = "multi_thread")]
async fn the_route_requires_admin() {
    let pg = start_postgres().await;
    let base = vault_reading(&pg.dal, SealBinding::NotIntact).await;
    let id = seed(&pg.dal).await;
    seal_it(&pg.dal, id, &dpp_types::digest_for_jws(JWS)).await;

    let client = TestClient::new(&base, make_jwt_scoped(&op(), "write"));
    let resp = client
        .post_json(
            &format!("/api/v1/dpp/{id}/seal/repair"),
            serde_json::json!({}),
        )
        .await;
    assert_eq!(resp.status(), 403);
    assert_eq!(
        counts(&pg.dal).await.pending,
        0,
        "a refused caller must not have moved the row"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_route_requires_authentication() {
    let pg = start_postgres().await;
    let base = vault_reading(&pg.dal, SealBinding::NotIntact).await;
    let id = seed(&pg.dal).await;

    let resp = reqwest::Client::new()
        .post(format!("{base}/api/v1/dpp/{id}/seal/repair"))
        .send()
        .await
        .expect("request");
    assert_eq!(resp.status(), 401);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unknown_passport_is_a_404() {
    let pg = start_postgres().await;
    let base = vault_reading(&pg.dal, SealBinding::NotIntact).await;
    let client = TestClient::new(&base, make_jwt(&op()));

    let resp = client
        .post_json(
            &format!("/api/v1/dpp/{}/seal/repair", PassportId::new()),
            serde_json::json!({}),
        )
        .await;
    assert_eq!(
        resp.status(),
        404,
        "a passport that does not exist is a 404, not a 422 about its seal"
    );
}
