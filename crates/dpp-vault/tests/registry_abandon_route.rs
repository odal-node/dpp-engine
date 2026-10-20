//! `POST /api/v1/dpp/{dppId}/registry/abandon` over real HTTP.
//!
//! The route ends an obligation the node was tracking, on a person's word, and what
//! makes that safe is almost entirely what it **refuses**: a registration the
//! registry holds, one the registry could not be shown to hold nothing for, and one
//! in a state this does not end must all be left exactly as they were. So most tests
//! below are one state that looks abandonable and is not, asserting the row and the
//! trail are untouched afterwards.
//!
//! The registry is scripted rather than real: the vault depends on the *question*
//! "does the registry hold a submission for this passport?", not on whichever
//! adapter answers it. The adapter that answers it against the registry's real task
//! list is proven where it lives, in `dpp-node`.

#![cfg(feature = "integration-tests")]

mod helpers;
use helpers::{
    TestClient, make_jwt, make_jwt_scoped, seed_operator_config, start_postgres,
    start_vault_with_registry,
};

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use dpp_dal::pg::{PgDal, PgRegistrySyncRepo, sqlx};
use dpp_domain::DppError;
use dpp_domain::passport::PassportId;
use dpp_domain::ports::registry_sync::{
    RegistrationRequest, RegistryRecord, RegistrySyncPort, SubmissionAcknowledgement,
    SubmissionLookup, SubmissionReport, TransferReport,
};
use dpp_types::{RegistrySyncOutbox, RegistrySyncStatus};

fn op() -> String {
    "00000000-0000-0000-0000-000000000001".to_owned()
}

const REASON: &str = "the product was withdrawn before the registry accepted it";

/// A registry that answers every "does it hold a submission for this passport?"
/// with what the test says, and counts how often it was asked.
struct ScriptedRegistry {
    answer: Mutex<Result<SubmissionLookup, String>>,
    asked: Mutex<usize>,
}

impl ScriptedRegistry {
    fn new(answer: SubmissionLookup) -> Arc<Self> {
        Arc::new(Self {
            answer: Mutex::new(Ok(answer)),
            asked: Mutex::new(0),
        })
    }

    fn unreachable() -> Arc<Self> {
        Arc::new(Self {
            answer: Mutex::new(Err("the registry did not answer".into())),
            asked: Mutex::new(0),
        })
    }

    /// Change what the registry says from now on.
    fn say(&self, answer: SubmissionLookup) {
        *self.answer.lock().unwrap() = Ok(answer);
    }

    fn asked(&self) -> usize {
        *self.asked.lock().unwrap()
    }
}

#[async_trait]
impl RegistrySyncPort for ScriptedRegistry {
    async fn register(
        &self,
        _request: RegistrationRequest,
    ) -> Result<SubmissionAcknowledgement, DppError> {
        unreachable!("the route never submits")
    }

    async fn check_submission(&self, _correlation_id: &str) -> Result<SubmissionReport, DppError> {
        unreachable!("the route looks a submission up, it does not poll one")
    }

    async fn find_submission(
        &self,
        _request: &RegistrationRequest,
    ) -> Result<SubmissionLookup, DppError> {
        *self.asked.lock().unwrap() += 1;
        self.answer
            .lock()
            .unwrap()
            .clone()
            .map_err(DppError::Internal)
    }

    async fn check_status(&self, _registration_id: &str) -> Result<RegistryRecord, DppError> {
        unreachable!("not exercised")
    }

    async fn notify_transfer(
        &self,
        _record: &dpp_domain::transfer::TransferRecord,
        _registration_id: &str,
    ) -> Result<TransferReport, DppError> {
        unreachable!("not exercised")
    }
}

/// Create and publish a passport through the API, as an operator would, so its
/// registry row carries the payload the route looks the registry up by.
async fn published(client: &TestClient) -> String {
    let resp = client
        .post_json(
            "/api/v1/facilities",
            serde_json::json!({
                "name": "Default Plant",
                "identifierScheme": "gln",
                "identifierValue": "4012345000009",
                "country": "DE",
                "isDefault": true
            }),
        )
        .await;
    assert_eq!(resp.status(), 201, "facility create should succeed");
    let resp = client
        .post_json(
            "/api/v1/operator-identifiers",
            serde_json::json!({ "scheme": "vat", "value": "DE123456789", "isPrimary": true }),
        )
        .await;
    assert_eq!(
        resp.status(),
        201,
        "operator identifier create should succeed"
    );

    let id = created(client).await;
    let resp = client
        .post_json(&format!("/api/v1/dpp/{id}/publish"), serde_json::json!({}))
        .await;
    assert_eq!(resp.status(), 200, "publish should succeed: {resp:?}");
    id
}

/// A draft battery passport, created and not published.
async fn created(client: &TestClient) -> String {
    let resp = client
        .post_json(
            "/api/v1/dpp",
            serde_json::json!({
                "productName": "Registry Abandon Battery",
                "productGroup": "battery",
                "manufacturer": { "name": "TestCorp GmbH", "address": "Berlin, DE" },
                "commodityCode": "85076000",
                "productGroupData": {
                    "productGroup": "battery",
                    "productIdentifier": { "scheme": "gs1", "gtin": "09506000134352" },
                    "batteryType": "portable",
                    "batteryChemistry": "LFP",
                    "nominalVoltageV": 3.7,
                    "nominalCapacityAh": 2.5,
                    "co2ePerUnitKg": 1.8
                }
            }),
        )
        .await;
    assert_eq!(resp.status(), 201, "create should succeed");
    let body: serde_json::Value = resp.json().await.unwrap();
    body["id"].as_str().expect("id").to_owned()
}

fn outbox(dal: &PgDal) -> PgRegistrySyncRepo {
    PgRegistrySyncRepo::new(dal.clone())
}

fn pid(id: &str) -> PassportId {
    PassportId(uuid::Uuid::parse_str(id).expect("a uuid"))
}

/// The row as the per-passport registry route shows it.
async fn registration(client: &TestClient, id: &str) -> serde_json::Value {
    let resp = client.get(&format!("/api/v1/dpp/{id}/registry")).await;
    assert_eq!(resp.status(), 200);
    let view: serde_json::Value = resp.json().await.unwrap();
    view["registration"].clone()
}

async fn abandon(client: &TestClient, id: &str, body: serde_json::Value) -> reqwest::Response {
    client
        .post_json(&format!("/api/v1/dpp/{id}/registry/abandon"), body)
        .await
}

async fn audit_actions(client: &TestClient, id: &str) -> Vec<String> {
    let resp = client.get(&format!("/api/v1/dpp/{id}/history")).await;
    assert_eq!(resp.status(), 200);
    let entries: Vec<serde_json::Value> = resp.json().await.unwrap();
    entries
        .iter()
        .filter_map(|e| e["action"].as_str().map(str::to_owned))
        .collect()
}

async fn make_due(dal: &PgDal, id: &str) {
    sqlx::query("UPDATE odal.registry_sync SET next_attempt_at = now() WHERE passport_id = $1")
        .bind(pid(id).0)
        .execute(dal.pool())
        .await
        .expect("make the row due");
}

/// A registration the drain has tried and failed: `pending`, attempted, backed off.
async fn tried_and_failed(dal: &PgDal, id: &str) {
    outbox(dal)
        .mark_attempt_failed(pid(id), "the registry refused the payload".into())
        .await
        .unwrap();
    // A short backoff would let the row fall due while a slow test is still asking,
    // so it is pushed out the way a long run of failures would: an hour.
    sqlx::query(
        "UPDATE odal.registry_sync SET next_attempt_at = now() + interval '1 hour' 
         WHERE passport_id = $1",
    )
    .bind(pid(id).0)
    .execute(dal.pool())
    .await
    .expect("back the row off");
}

/// 🚨 The whole of it: a registration the registry holds nothing for is abandoned,
/// the row says by whom and why, the rollup counts it as abandoned and not owed,
/// and the trail keeps who, why and what the row had been saying.
#[tokio::test(flavor = "multi_thread")]
async fn a_registration_the_registry_holds_nothing_for_is_abandoned_and_audited() {
    let pg = start_postgres().await;
    seed_operator_config(&pg.dal).await;
    let registry = ScriptedRegistry::new(SubmissionLookup::NotFound { exhaustive: true });
    let url = start_vault_with_registry(pg.dal.clone(), registry.clone()).await;
    let client = TestClient::new(&url, make_jwt(&op()));
    let id = published(&client).await;
    tried_and_failed(&pg.dal, &id).await;

    let resp = abandon(&client, &id, serde_json::json!({ "reason": REASON })).await;
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["passportId"], id.as_str());
    assert_eq!(body["alreadyAbandoned"], false);
    assert_eq!(registry.asked(), 1);

    let whoami: serde_json::Value = client.get("/api/v1/whoami").await.json().await.unwrap();
    let actor = whoami["userId"].as_str().unwrap().to_owned();
    let row = registration(&client, &id).await;
    assert_eq!(row["status"], "abandoned");
    assert_eq!(row["message"], format!("abandoned by {actor}: {REASON}"));
    assert_eq!(
        row["stalled"], false,
        "nothing is owed, so nothing is stalled"
    );

    let rollup: serde_json::Value = client.get("/api/v1/registry").await.json().await.unwrap();
    assert_eq!(rollup["registrations"]["abandoned"], 1);
    assert_eq!(rollup["registrations"]["pending"], 0);

    let entries: Vec<serde_json::Value> = client
        .get(&format!("/api/v1/dpp/{id}/history"))
        .await
        .json()
        .await
        .unwrap();
    let entry = entries
        .iter()
        .find(|e| e["action"] == "registry_abandoned")
        .expect("the write is in the trail");
    assert_eq!(entry["actor"], actor.as_str());
    assert_eq!(entry["metadata"]["reason"], REASON);
    assert_eq!(entry["metadata"]["attempts"], 1);
    assert_eq!(
        entry["metadata"]["lastMessage"],
        "the registry refused the payload"
    );

    // An abandoned registration has no submission to record a handle for, and says
    // so: the handle route's `409` reads this state too.
    let resp = client
        .post_json(
            &format!("/api/v1/dpp/{id}/registry/handle"),
            serde_json::json!({ "correlationId": "CORR-1" }),
        )
        .await;
    assert_eq!(resp.status(), 409);
    let problem: serde_json::Value = resp.json().await.unwrap();
    assert!(
        problem["detail"].as_str().unwrap().contains("abandoned"),
        "{problem}"
    );
}

/// A retry after a lost response must not fail on its own success, and must not ask
/// the registry again or write the trail twice.
#[tokio::test(flavor = "multi_thread")]
async fn abandoning_twice_changes_nothing_the_second_time() {
    let pg = start_postgres().await;
    seed_operator_config(&pg.dal).await;
    let registry = ScriptedRegistry::new(SubmissionLookup::NotFound { exhaustive: true });
    let url = start_vault_with_registry(pg.dal.clone(), registry.clone()).await;
    let client = TestClient::new(&url, make_jwt(&op()));
    let id = published(&client).await;
    tried_and_failed(&pg.dal, &id).await;

    let body = serde_json::json!({ "reason": REASON });
    assert_eq!(abandon(&client, &id, body.clone()).await.status(), 200);
    let again = abandon(
        &client,
        &id,
        serde_json::json!({ "reason": "a second opinion" }),
    )
    .await;
    assert_eq!(again.status(), 200);
    let again: serde_json::Value = again.json().await.unwrap();
    assert_eq!(again["alreadyAbandoned"], true);

    assert_eq!(registry.asked(), 1, "the registry was asked once");
    assert!(
        registration(&client, &id).await["message"]
            .as_str()
            .unwrap()
            .ends_with(REASON),
        "the first reason stands"
    );
    let recorded = audit_actions(&client, &id)
        .await
        .iter()
        .filter(|a| *a == "registry_abandoned")
        .count();
    assert_eq!(recorded, 1, "and the trail says it once");
}

/// 🚨 A registration the registry holds, or cannot be shown not to hold, is never
/// abandoned: the row stays `pending`, the trail says nothing, and the answer says
/// which kind of "no" it was. Held is a `409`, because the registration is there;
/// unproven is a `422`, because it may be.
#[tokio::test(flavor = "multi_thread")]
async fn a_registration_the_registry_may_hold_is_not_abandoned() {
    let pg = start_postgres().await;
    seed_operator_config(&pg.dal).await;
    let registry = ScriptedRegistry::new(SubmissionLookup::Unsupported);
    let url = start_vault_with_registry(pg.dal.clone(), registry.clone()).await;
    let client = TestClient::new(&url, make_jwt(&op()));
    let id = published(&client).await;
    tried_and_failed(&pg.dal, &id).await;
    let before = registration(&client, &id).await;

    let cases: [(SubmissionLookup, u16, &str); 4] = [
        (
            SubmissionLookup::Found {
                correlation_id: "CORR-7".into(),
                report: SubmissionReport::Processing,
            },
            409,
            "CORR-7",
        ),
        (
            SubmissionLookup::Ambiguous {
                candidates: vec!["CORR-1".into(), "CORR-2".into()],
            },
            409,
            "CORR-2",
        ),
        (
            SubmissionLookup::NotFound { exhaustive: false },
            422,
            "not read",
        ),
        (
            SubmissionLookup::Unsupported,
            422,
            "cannot look a submission up",
        ),
    ];
    for (answer, status, says) in cases {
        registry.say(answer.clone());

        let resp = abandon(&client, &id, serde_json::json!({ "reason": REASON })).await;
        assert_eq!(resp.status(), status, "{answer:?}");
        let problem: serde_json::Value = resp.json().await.unwrap();
        let detail = problem["detail"].as_str().expect("a detail").to_owned();
        assert!(detail.contains(says), "{answer:?} → {detail}");

        assert_eq!(
            registration(&client, &id).await,
            before,
            "{answer:?}: the row is untouched"
        );
        assert!(
            !audit_actions(&client, &id)
                .await
                .contains(&"registry_abandoned".to_owned()),
            "{answer:?}: nothing is written to the trail"
        );
    }
}

/// The states that look alike and are told apart: no registration at all is `404`; a
/// registration in a state this does not end is `409`. None of them asks the registry.
#[tokio::test(flavor = "multi_thread")]
async fn no_registration_and_a_registration_in_the_wrong_state_are_told_apart() {
    let pg = start_postgres().await;
    seed_operator_config(&pg.dal).await;
    let registry = ScriptedRegistry::new(SubmissionLookup::NotFound { exhaustive: true });
    let url = start_vault_with_registry(pg.dal.clone(), registry.clone()).await;
    let client = TestClient::new(&url, make_jwt(&op()));
    let id = published(&client).await;
    let body = serde_json::json!({ "reason": REASON });

    // A draft owes no registration, and so has no row: `404`, nothing to end.
    let draft = created(&client).await;
    assert_eq!(abandon(&client, &draft, body.clone()).await.status(), 404);
    assert_eq!(
        abandon(
            &client,
            "00000000-0000-0000-0000-0000000000ff",
            body.clone()
        )
        .await
        .status(),
        404
    );

    // Never tried: due now, and indistinguishable from a row about to be submitted.
    let resp = abandon(&client, &id, body.clone()).await;
    assert_eq!(resp.status(), 409);
    let problem: serde_json::Value = resp.json().await.unwrap();
    assert!(
        problem["detail"].as_str().unwrap().contains("not tried"),
        "{problem}"
    );

    // Tried, and the backoff has since run out: due again, so the drain may be in
    // the middle of trying it.
    tried_and_failed(&pg.dal, &id).await;
    make_due(&pg.dal, &id).await;
    assert_eq!(abandon(&client, &id, body.clone()).await.status(), 409);

    // Accepted by the registry: it holds a registration or is deciding one.
    outbox(&pg.dal)
        .mark_submitted(pid(&id), "CORR-1".into())
        .await
        .unwrap();
    let resp = abandon(&client, &id, body.clone()).await;
    assert_eq!(resp.status(), 409);
    let problem: serde_json::Value = resp.json().await.unwrap();
    assert!(
        problem["detail"].as_str().unwrap().contains("accepted"),
        "{problem}"
    );

    // Ruled on: nothing to end.
    outbox(&pg.dal)
        .mark_registered(pid(&id), "EUDPP-2026-0001".into())
        .await
        .unwrap();
    let resp = abandon(&client, &id, body).await;
    assert_eq!(resp.status(), 409);
    let problem: serde_json::Value = resp.json().await.unwrap();
    assert!(
        problem["detail"]
            .as_str()
            .unwrap()
            .contains("already ruled"),
        "{problem}"
    );

    assert_eq!(registry.asked(), 0, "the registry was never asked");
}

/// An unreadable registry is a `502` and nothing is abandoned, so the same request
/// can simply be sent again.
#[tokio::test(flavor = "multi_thread")]
async fn an_unreadable_registry_abandons_nothing_and_can_be_retried() {
    let pg = start_postgres().await;
    seed_operator_config(&pg.dal).await;
    let registry = ScriptedRegistry::unreachable();
    let url = start_vault_with_registry(pg.dal.clone(), registry.clone()).await;
    let client = TestClient::new(&url, make_jwt(&op()));
    let id = published(&client).await;
    tried_and_failed(&pg.dal, &id).await;

    let resp = abandon(&client, &id, serde_json::json!({ "reason": REASON })).await;
    assert_eq!(resp.status(), 502);
    assert_eq!(registration(&client, &id).await["status"], "pending");
    assert_eq!(
        outbox(&pg.dal)
            .pending_for(pid(&id))
            .await
            .unwrap()
            .unwrap()
            .status,
        RegistrySyncStatus::Pending
    );
}

/// Giving up on a registration ends an obligation, so it is an admin's act: a
/// write-scoped credential is refused before the registry is asked.
#[tokio::test(flavor = "multi_thread")]
async fn only_an_admin_can_abandon_a_registration() {
    let pg = start_postgres().await;
    seed_operator_config(&pg.dal).await;
    let registry = ScriptedRegistry::new(SubmissionLookup::NotFound { exhaustive: true });
    let url = start_vault_with_registry(pg.dal.clone(), registry.clone()).await;
    let admin = TestClient::new(&url, make_jwt(&op()));
    let id = published(&admin).await;
    tried_and_failed(&pg.dal, &id).await;

    for scope in ["write", "read"] {
        let client = TestClient::new(&url, make_jwt_scoped(&op(), scope));
        let resp = abandon(&client, &id, serde_json::json!({ "reason": REASON })).await;
        assert_eq!(resp.status(), 403, "{scope}");
    }
    assert_eq!(registry.asked(), 0);
    assert_eq!(registration(&admin, &id).await["status"], "pending");
}

/// A reason is required, and it has to be something worth keeping in an audit trail.
#[tokio::test(flavor = "multi_thread")]
async fn a_registration_is_not_given_up_on_without_a_reason() {
    let pg = start_postgres().await;
    seed_operator_config(&pg.dal).await;
    let registry = ScriptedRegistry::new(SubmissionLookup::NotFound { exhaustive: true });
    let url = start_vault_with_registry(pg.dal.clone(), registry.clone()).await;
    let client = TestClient::new(&url, make_jwt(&op()));
    let id = published(&client).await;
    tried_and_failed(&pg.dal, &id).await;

    for bad in [
        serde_json::json!({ "reason": "" }),
        serde_json::json!({ "reason": "   " }),
        serde_json::json!({ "reason": "tab\there" }),
        serde_json::json!({ "reason": "x".repeat(501) }),
        serde_json::json!({}),
        serde_json::json!({ "reason": REASON, "force": true }),
    ] {
        let resp = abandon(&client, &id, bad.clone()).await;
        assert_eq!(resp.status(), 422, "{bad}");
    }
    assert_eq!(registry.asked(), 0);
    assert_eq!(registration(&client, &id).await["status"], "pending");
}
