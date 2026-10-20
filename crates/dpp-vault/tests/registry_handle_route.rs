//! `POST /api/v1/dpp/{dppId}/registry/handle` over real HTTP.
//!
//! The route puts a person's answer on a registry row, and what makes that safe is
//! almost entirely what it **refuses**: a handle the registry does not show to be
//! this passport's must leave the row exactly as it was, and a row that is not
//! waiting for a handle must not be touched. So most tests below are one state that
//! looks recordable and is not, asserting the row is unchanged afterwards.
//!
//! The registry is scripted rather than real: the vault depends on the *question*
//! "is this handle that passport's?", not on whichever adapter answers it. The
//! adapter that answers it against the registry's real task list is proven where it
//! lives, in `dpp-node`.

#![cfg(feature = "integration-tests")]

mod helpers;
use helpers::{
    TestClient, make_jwt, make_jwt_scoped, seed_operator_config, start_postgres, start_vault,
    start_vault_with_registry, start_vault_without_registry_queues,
};

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use dpp_dal::pg::{PgDal, PgRegistrySyncRepo};
use dpp_domain::DppError;
use dpp_domain::passport::PassportId;
use dpp_domain::ports::registry_sync::{
    RegistrationRequest, RegistryRecord, RegistrySyncPort, SubmissionAcknowledgement,
    SubmissionConfirmation, SubmissionReport, TransferReport,
};
use dpp_types::{RegistrySyncOutbox, RegistrySyncStatus};

fn op() -> String {
    "00000000-0000-0000-0000-000000000001".to_owned()
}

const HANDLE: &str = "7c9e6679-7425-40de-944b-e07fc1f90ae7";

/// A registry that answers every "is this handle that passport's?" with what the
/// test says, and remembers which handles it was asked about.
struct ScriptedRegistry {
    answer: Mutex<Result<SubmissionConfirmation, String>>,
    asked: Mutex<Vec<String>>,
}

impl ScriptedRegistry {
    fn new(answer: SubmissionConfirmation) -> Arc<Self> {
        Arc::new(Self {
            answer: Mutex::new(Ok(answer)),
            asked: Mutex::new(Vec::new()),
        })
    }

    fn unreachable() -> Arc<Self> {
        Arc::new(Self {
            answer: Mutex::new(Err("the registry did not answer".into())),
            asked: Mutex::new(Vec::new()),
        })
    }

    /// Change what the registry says from now on.
    fn say(&self, answer: SubmissionConfirmation) {
        *self.answer.lock().unwrap() = Ok(answer);
    }

    fn asked(&self) -> Vec<String> {
        self.asked.lock().unwrap().clone()
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
        unreachable!("the route confirms, it does not poll")
    }

    async fn confirm_submission(
        &self,
        _request: &RegistrationRequest,
        correlation_id: &str,
    ) -> Result<SubmissionConfirmation, DppError> {
        self.asked.lock().unwrap().push(correlation_id.to_owned());
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
/// registry row carries the payload the route checks the handle against.
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
                "productName": "Registry Handle Battery",
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

async fn record(client: &TestClient, id: &str, body: serde_json::Value) -> reqwest::Response {
    client
        .post_json(&format!("/api/v1/dpp/{id}/registry/handle"), body)
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

/// 🚨 The happy path, all of it: a handle the registry shows to be the passport's
/// is recorded, the row stops reading as stalled, the trail says who did it and
/// what the registry reported, and the drain is left to apply the ruling.
#[tokio::test(flavor = "multi_thread")]
async fn a_confirmed_handle_is_recorded_and_audited() {
    let pg = start_postgres().await;
    seed_operator_config(&pg.dal).await;
    let registry = ScriptedRegistry::new(SubmissionConfirmation::Confirmed {
        report: SubmissionReport::Registered {
            registration_id: "EUDPP-2026-0001".into(),
        },
    });
    let url = start_vault_with_registry(pg.dal.clone(), registry.clone()).await;
    let client = TestClient::new(&url, make_jwt(&op()));
    let id = published(&client).await;

    // A row waiting for a person: submitted, no handle, retried until it stalled.
    let repo = outbox(&pg.dal);
    for _ in 0..6 {
        repo.mark_submitted_noting(pid(&id), "waiting for a person".into())
            .await
            .unwrap();
    }
    let before = registration(&client, &id).await;
    assert_eq!(before["status"], "submitted");
    assert_eq!(before["stalled"], true);
    assert_eq!(before["message"], "waiting for a person");
    assert!(before.get("registryId").is_none());

    let resp = record(&client, &id, serde_json::json!({ "correlationId": HANDLE })).await;
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["passportId"], id.as_str());
    assert_eq!(body["correlationId"], HANDLE);
    assert_eq!(body["recorded"], true);
    assert_eq!(
        body["registry"],
        serde_json::json!({ "outcome": "registered", "registrationId": "EUDPP-2026-0001" }),
        "what the registry said when the handle was checked"
    );
    assert_eq!(registry.asked(), [HANDLE]);

    // The row holds the handle, polls from now on, and is no longer reported as
    // stalled by the attempts that came before it.
    let after = registration(&client, &id).await;
    assert_eq!(after["status"], "submitted");
    assert_eq!(after["registryId"], HANDLE);
    assert_eq!(after["attempts"], 0);
    assert_eq!(after["stalled"], false);
    assert!(
        after.get("message").is_none(),
        "the reason was about the missing handle: {after}"
    );

    // The ruling is not applied here: the drain applies it.
    assert_eq!(
        repo.pending_for(pid(&id)).await.unwrap().unwrap().status,
        RegistrySyncStatus::Submitted
    );

    let entries: Vec<serde_json::Value> = client
        .get(&format!("/api/v1/dpp/{id}/history"))
        .await
        .json()
        .await
        .unwrap();
    let entry = entries
        .iter()
        .find(|e| e["action"] == "registry_handle_recorded")
        .expect("the write is in the trail");
    let whoami: serde_json::Value = client.get("/api/v1/whoami").await.json().await.unwrap();
    assert_eq!(
        entry["actor"], whoami["userId"],
        "the trail names the credential that made the write"
    );
    assert_eq!(entry["metadata"]["correlationId"], HANDLE);
    assert_eq!(entry["metadata"]["report"]["outcome"], "registered");
}

/// A retry after a lost response must not fail on its own success, and must not ask
/// the registry again or write the trail twice.
#[tokio::test(flavor = "multi_thread")]
async fn recording_the_same_handle_twice_changes_nothing_the_second_time() {
    let pg = start_postgres().await;
    seed_operator_config(&pg.dal).await;
    let registry = ScriptedRegistry::new(SubmissionConfirmation::Confirmed {
        report: SubmissionReport::Processing,
    });
    let url = start_vault_with_registry(pg.dal.clone(), registry.clone()).await;
    let client = TestClient::new(&url, make_jwt(&op()));
    let id = published(&client).await;
    outbox(&pg.dal)
        .mark_submitted(pid(&id), String::new())
        .await
        .unwrap();

    let body = serde_json::json!({ "correlationId": HANDLE });
    assert_eq!(record(&client, &id, body.clone()).await.status(), 200);
    let again = record(&client, &id, body).await;
    assert_eq!(again.status(), 200);
    let again: serde_json::Value = again.json().await.unwrap();
    assert_eq!(again["recorded"], false);
    assert!(
        again.get("registry").is_none(),
        "nothing was checked: {again}"
    );

    assert_eq!(registry.asked().len(), 1, "the registry was asked once");
    let recorded = audit_actions(&client, &id)
        .await
        .iter()
        .filter(|a| *a == "registry_handle_recorded")
        .count();
    assert_eq!(recorded, 1, "and the trail says it once");
}

/// 🚨 Whatever the registry says short of "this is the passport's", the row is
/// left exactly as it was and the trail says nothing. A handle that cannot be
/// checked is not recorded.
#[tokio::test(flavor = "multi_thread")]
async fn a_handle_the_registry_does_not_confirm_is_not_recorded() {
    let pg = start_postgres().await;
    seed_operator_config(&pg.dal).await;

    let cases: [(SubmissionConfirmation, &str); 6] = [
        (
            SubmissionConfirmation::Mismatch {
                reported: vec!["https://id.example.com/01/09506000134369".into()],
            },
            "https://id.example.com/01/09506000134369",
        ),
        (
            SubmissionConfirmation::Mismatch { reported: vec![] },
            "reports no passport",
        ),
        (
            SubmissionConfirmation::StillChecking,
            "not finished checking",
        ),
        (
            SubmissionConfirmation::Unlisted { exhaustive: true },
            "lists no submission",
        ),
        (
            SubmissionConfirmation::Unlisted { exhaustive: false },
            "may be further on",
        ),
        (
            SubmissionConfirmation::Unsupported,
            "cannot read a submission",
        ),
    ];

    let registry = ScriptedRegistry::new(SubmissionConfirmation::StillChecking);
    let url = start_vault_with_registry(pg.dal.clone(), registry.clone()).await;
    let client = TestClient::new(&url, make_jwt(&op()));
    let id = published(&client).await;
    outbox(&pg.dal)
        .mark_submitted_noting(pid(&id), "waiting".into())
        .await
        .unwrap();
    let before = registration(&client, &id).await;

    for (answer, says) in cases {
        registry.say(answer.clone());

        let resp = record(&client, &id, serde_json::json!({ "correlationId": HANDLE })).await;
        assert_eq!(resp.status(), 422, "{answer:?}");
        let problem: serde_json::Value = resp.json().await.unwrap();
        let detail = problem["detail"].as_str().expect("a detail").to_owned();
        assert!(detail.contains(says), "{answer:?} → {detail}");
        assert!(
            detail.contains("not recorded") || detail.contains("was not recorded"),
            "the refusal says the handle was not recorded: {detail}"
        );

        assert_eq!(
            registration(&client, &id).await,
            before,
            "{answer:?}: the row is untouched"
        );
        assert!(
            !audit_actions(&client, &id)
                .await
                .contains(&"registry_handle_recorded".to_owned()),
            "{answer:?}: nothing is written to the trail"
        );
    }
}

/// The three states that look alike and are told apart: no registration at all is
/// `404`; a registration that exists and is the wrong state is `409`; a registration
/// that takes a handle the registry does not show to be right is `422`.
#[tokio::test(flavor = "multi_thread")]
async fn no_registration_a_wrong_state_and_an_unconfirmed_handle_are_told_apart() {
    let pg = start_postgres().await;
    seed_operator_config(&pg.dal).await;
    let registry = ScriptedRegistry::new(SubmissionConfirmation::Confirmed {
        report: SubmissionReport::Processing,
    });
    let url = start_vault_with_registry(pg.dal.clone(), registry.clone()).await;
    let client = TestClient::new(&url, make_jwt(&op()));
    let published_id = published(&client).await;
    let body = serde_json::json!({ "correlationId": HANDLE });

    // A draft owes no registration, and so has no row: `404`, nothing to correct.
    let draft = created(&client).await;
    assert_eq!(record(&client, &draft, body.clone()).await.status(), 404);
    // …and a passport that does not exist is the same answer.
    assert_eq!(
        record(
            &client,
            "00000000-0000-0000-0000-0000000000ff",
            body.clone()
        )
        .await
        .status(),
        404
    );

    // Pending: the registry has not accepted the submission, so there is no handle
    // to record yet. `409`, and the registry was not asked.
    let resp = record(&client, &published_id, body.clone()).await;
    assert_eq!(resp.status(), 409);
    let problem: serde_json::Value = resp.json().await.unwrap();
    assert!(
        problem["detail"].as_str().unwrap().contains("not accepted"),
        "{problem}"
    );
    assert!(registry.asked().is_empty());

    // Ruled on: no longer needs one.
    let repo = outbox(&pg.dal);
    repo.mark_registered(pid(&published_id), "EUDPP-2026-0001".into())
        .await
        .unwrap();
    let resp = record(&client, &published_id, body.clone()).await;
    assert_eq!(resp.status(), 409);
    let problem: serde_json::Value = resp.json().await.unwrap();
    assert!(
        problem["detail"]
            .as_str()
            .unwrap()
            .contains("already ruled"),
        "{problem}"
    );
    assert!(registry.asked().is_empty(), "still not asked");
}

/// 🚨 A handle the registry gave is never replaced by one a person typed.
#[tokio::test(flavor = "multi_thread")]
async fn a_handle_the_row_already_holds_is_never_overwritten() {
    let pg = start_postgres().await;
    seed_operator_config(&pg.dal).await;
    let registry = ScriptedRegistry::new(SubmissionConfirmation::Confirmed {
        report: SubmissionReport::Processing,
    });
    let url = start_vault_with_registry(pg.dal.clone(), registry.clone()).await;
    let client = TestClient::new(&url, make_jwt(&op()));
    let id = published(&client).await;
    outbox(&pg.dal)
        .mark_submitted(pid(&id), "CORR-FROM-THE-REGISTRY".into())
        .await
        .unwrap();

    let resp = record(&client, &id, serde_json::json!({ "correlationId": HANDLE })).await;
    assert_eq!(resp.status(), 409);
    assert_eq!(
        registration(&client, &id).await["registryId"],
        "CORR-FROM-THE-REGISTRY"
    );
    assert!(registry.asked().is_empty(), "refused before asking");
}

/// An unreadable registry is a `502` and nothing is recorded, so the same request
/// can simply be sent again.
#[tokio::test(flavor = "multi_thread")]
async fn an_unreadable_registry_records_nothing_and_can_be_retried() {
    let pg = start_postgres().await;
    seed_operator_config(&pg.dal).await;
    let registry = ScriptedRegistry::unreachable();
    let url = start_vault_with_registry(pg.dal.clone(), registry.clone()).await;
    let client = TestClient::new(&url, make_jwt(&op()));
    let id = published(&client).await;
    outbox(&pg.dal)
        .mark_submitted(pid(&id), String::new())
        .await
        .unwrap();

    let resp = record(&client, &id, serde_json::json!({ "correlationId": HANDLE })).await;
    assert_eq!(resp.status(), 502);
    assert!(
        registration(&client, &id).await.get("registryId").is_none(),
        "nothing was recorded"
    );
}

/// Recording a handle overrides the drain's own judgement, so it is an admin's act:
/// a write-scoped credential is refused before the registry is asked.
#[tokio::test(flavor = "multi_thread")]
async fn only_an_admin_can_record_a_handle() {
    let pg = start_postgres().await;
    seed_operator_config(&pg.dal).await;
    let registry = ScriptedRegistry::new(SubmissionConfirmation::Confirmed {
        report: SubmissionReport::Processing,
    });
    let url = start_vault_with_registry(pg.dal.clone(), registry.clone()).await;
    let admin = TestClient::new(&url, make_jwt(&op()));
    let id = published(&admin).await;
    outbox(&pg.dal)
        .mark_submitted(pid(&id), String::new())
        .await
        .unwrap();

    for scope in ["write", "read"] {
        let client = TestClient::new(&url, make_jwt_scoped(&op(), scope));
        let resp = record(&client, &id, serde_json::json!({ "correlationId": HANDLE })).await;
        assert_eq!(resp.status(), 403, "{scope}");
    }
    assert!(registry.asked().is_empty());
    assert!(registration(&admin, &id).await.get("registryId").is_none());
}

/// What could not be a registry identifier is refused before anything is read.
#[tokio::test(flavor = "multi_thread")]
async fn what_could_not_be_a_correlation_identifier_is_refused_up_front() {
    let pg = start_postgres().await;
    seed_operator_config(&pg.dal).await;
    let registry = ScriptedRegistry::new(SubmissionConfirmation::Confirmed {
        report: SubmissionReport::Processing,
    });
    let url = start_vault_with_registry(pg.dal.clone(), registry.clone()).await;
    let client = TestClient::new(&url, make_jwt(&op()));
    let id = published(&client).await;
    outbox(&pg.dal)
        .mark_submitted(pid(&id), String::new())
        .await
        .unwrap();

    for bad in [
        serde_json::json!({ "correlationId": "" }),
        serde_json::json!({ "correlationId": "   " }),
        serde_json::json!({ "correlationId": "two words" }),
        serde_json::json!({ "correlationId": "x".repeat(201) }),
        serde_json::json!({}),
        serde_json::json!({ "correlationId": HANDLE, "force": true }),
    ] {
        let resp = record(&client, &id, bad.clone()).await;
        assert_eq!(resp.status(), 422, "{bad}");
    }
    assert!(registry.asked().is_empty());
}

/// The ghost registry holds no submission, so no handle is ever shown to be a
/// passport's, and a node that is not enrolled cannot be talked into recording one.
#[tokio::test(flavor = "multi_thread")]
async fn a_node_with_no_registry_connection_records_nothing() {
    let pg = start_postgres().await;
    seed_operator_config(&pg.dal).await;
    let url = start_vault(pg.dal.clone()).await;
    let client = TestClient::new(&url, make_jwt(&op()));
    let id = published(&client).await;
    outbox(&pg.dal)
        .mark_submitted(pid(&id), String::new())
        .await
        .unwrap();

    let resp = record(&client, &id, serde_json::json!({ "correlationId": HANDLE })).await;
    assert_eq!(resp.status(), 422);
    assert!(registration(&client, &id).await.get("registryId").is_none());
}

/// 🚨 A node with no registry queues has no registration to record a handle on,
/// and says so with the status the route documents for it: `501`, which is a
/// feature that is absent, and not `404`, which would say this passport has none.
///
/// The one documented status no other test constructs, because every other
/// harness wires the queues. It is not a quieter `422` either: a client that
/// treats `422` as "the registry did not confirm" would retry a request that can
/// never succeed on this node.
#[tokio::test(flavor = "multi_thread")]
async fn a_node_with_no_registry_queues_cannot_record_a_handle() {
    let pg = start_postgres().await;
    seed_operator_config(&pg.dal).await;
    let url = start_vault_without_registry_queues(pg.dal.clone()).await;
    let client = TestClient::new(&url, make_jwt(&op()));

    // The surface says what it is before anything is asked of it.
    let rollup: serde_json::Value = client.get("/api/v1/registry").await.json().await.unwrap();
    assert_eq!(rollup["configured"], false, "{rollup}");

    // A passport that exists and one that does not get the same answer: the
    // missing thing is the node's queues, not either passport's row.
    let id = created(&client).await;
    for dpp in [id.as_str(), "00000000-0000-0000-0000-0000000000ff"] {
        let resp = record(&client, dpp, serde_json::json!({ "correlationId": HANDLE })).await;
        assert_eq!(resp.status(), 501, "{dpp}");
        let problem: serde_json::Value = resp.json().await.unwrap();
        assert!(
            problem["detail"]
                .as_str()
                .is_some_and(|d| d.contains("no registry queues")),
            "{problem}"
        );
    }

    // And the per-passport view agrees with the rollup rather than reporting a
    // registration that cannot exist.
    let view: serde_json::Value = client
        .get(&format!("/api/v1/dpp/{id}/registry"))
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(view["configured"], false, "{view}");
    assert!(view.get("registration").is_none(), "{view}");
}

/// The scope gate comes first: a write-scoped credential is told `403` on a node
/// that could not have done the work anyway, so the answer never leaks whether the
/// queues are wired to someone who may not ask.
#[tokio::test(flavor = "multi_thread")]
async fn the_scope_is_checked_before_the_queues_are() {
    let pg = start_postgres().await;
    seed_operator_config(&pg.dal).await;
    let url = start_vault_without_registry_queues(pg.dal.clone()).await;
    let client = TestClient::new(&url, make_jwt_scoped(&op(), "write"));

    let resp = record(
        &client,
        "00000000-0000-0000-0000-0000000000ff",
        serde_json::json!({ "correlationId": HANDLE }),
    )
    .await;

    assert_eq!(resp.status(), 403);
}
