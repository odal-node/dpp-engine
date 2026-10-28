//! `PgStateChangeLog`: a state change commits whole or not at all.
//!
//! Webhook deliveries used to be enqueued after the passport write, best
//! effort, so a node killed in between had changed a passport and told no
//! subscriber. These pin that the delivery rows, the archived version and the
//! audit entry now land in the change's own transaction, and that a failure
//! anywhere in it leaves none of them behind.

#![cfg(feature = "integration-tests")]

use chrono::Utc;

use dpp_dal::pg::{
    PgAuditRepo, PgPassportRepo, PgPassportVersionRepo, PgRegistrySyncRepo, PgStateChangeLog,
    PgWebhookRepo,
};
use dpp_dal::test_harness::{TestPg, start_pg};
use dpp_domain::passport::{ManufacturerInfo, Passport, PassportId};
use dpp_domain::ports::passport_repo::PassportRepository;
use dpp_domain::product_group::ProductGroup;
use dpp_domain::status::PassportStatus;
use dpp_types::audit::{AuditRepository, PassportAuditEntry, PassportVersionStore};
use dpp_types::registry_sync::{RegistryStatusIntent, RegistrySyncOutbox};
use dpp_types::state_change::{PassportWrite, StateChange, StateChangeLog, WebhookEvent};
use dpp_types::webhook::{CreateWebhookRequest, WebhookOutbox, WebhookSubscriptionStore};

fn passport(status: PassportStatus) -> Passport {
    Passport {
        id: PassportId::new(),
        batch_id: None,
        serial_number: None,
        product_name: "State Change Battery".into(),
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
        status: status.clone(),
        qr_code_url: None,
        jws_signature: None,
        public_jws_signature: None,
        disclosure_signatures: Default::default(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        published_at: matches!(status, PassportStatus::Published).then(Utc::now),
        placed_on_market_date: None,
        schema_version: "2.0.0".into(),
        retention_locked: false,
        version: 1,
        supersedes_id: None,
        derived_from: Vec::new(),
        component_refs: Vec::new(),
        life_status: None,
        personal_data: Default::default(),
        retention_until: None,
        product_id: None,
        commodity_code: None,
        operator_identifier: None,
        responsible_operator: None,
        facility: None,
        seal: None,
        carrier_serial: None,
    }
}

const SUSPENDED: &str = "dpp.passport.suspended";

/// A subscriber to `dpp.passport.suspended`, so a suspension owes a delivery.
async fn subscribe(pg: &TestPg) {
    PgWebhookRepo::new(pg.dal.clone())
        .create(
            &CreateWebhookRequest {
                url: "https://receiver.example/hook".into(),
                events: vec![SUSPENDED.into()],
                description: None,
            },
            "a-signing-secret",
        )
        .await
        .expect("create subscription");
}

async fn pending_deliveries(pg: &TestPg) -> usize {
    PgWebhookRepo::new(pg.dal.clone())
        .due(100)
        .await
        .expect("read due deliveries")
        .len()
}

fn suspension(id: PassportId) -> StateChange {
    StateChange::new(PassportAuditEntry::new(
        &id.to_string(),
        "suspended",
        "state-change-test",
        Some("active"),
        Some("suspended"),
    ))
    .with_passport(PassportWrite::Status(id, PassportStatus::Suspended))
    .with_webhook(WebhookEvent {
        event_type: SUSPENDED.into(),
        body: r#"{"eventType":"dpp.passport.suspended"}"#.into(),
    })
}

/// Every part of a change is there once it commits: the passport, the version
/// it replaced, the audit entry and the delivery.
#[tokio::test]
async fn a_committed_change_writes_every_part() {
    let pg = start_pg().await;
    subscribe(&pg).await;
    let repo = PgPassportRepo::new(pg.dal.clone());
    let p = repo
        .create(passport(PassportStatus::Published))
        .await
        .expect("create");

    let written = PgStateChangeLog::new(pg.dal.clone())
        .commit(suspension(p.id))
        .await
        .expect("commit")
        .expect("a status change returns the passport");
    assert_eq!(written.status, PassportStatus::Suspended);

    let stored = repo.find_by_id(p.id).await.expect("read").expect("exists");
    assert_eq!(stored.status, PassportStatus::Suspended);

    let versions = PgPassportVersionRepo::new(pg.dal.clone())
        .versions(&p.id.to_string())
        .await
        .expect("versions");
    assert_eq!(versions.len(), 1, "the change archives what it replaced");
    assert_eq!(versions[0].doc["status"], "active");

    let audit = PgAuditRepo::new(pg.dal.clone())
        .list_by_passport(&p.id.to_string())
        .await
        .expect("audit");
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0].action, "suspended");

    assert_eq!(pending_deliveries(&pg).await, 1);
}

/// Successive changes to one passport keep its audit chain verifiable: each
/// committed entry links to the one the change before it wrote.
#[tokio::test]
async fn successive_changes_keep_the_audit_chain_intact() {
    let pg = start_pg().await;
    let repo = PgPassportRepo::new(pg.dal.clone());
    let p = repo
        .create(passport(PassportStatus::Published))
        .await
        .expect("create");
    let log = PgStateChangeLog::new(pg.dal.clone());

    log.commit(suspension(p.id)).await.expect("suspend");
    let retirement = StateChange::new(PassportAuditEntry::new(
        &p.id.to_string(),
        "retired",
        "state-change-test",
        Some("suspended"),
        Some("retired"),
    ))
    .with_passport(PassportWrite::Status(p.id, PassportStatus::Retired));
    log.commit(retirement).await.expect("retire");

    let audit = PgAuditRepo::new(pg.dal.clone());
    let entries = audit
        .list_by_passport(&p.id.to_string())
        .await
        .expect("audit");
    assert_eq!(entries.len(), 2);
    assert_eq!(
        audit.verify_chain(&p.id.to_string()).await.expect("verify"),
        None
    );
}

/// A failure after the passport write rolls the whole change back.
///
/// A transfer notice with no chain to accept it is refused after the passport
/// row, its archived version and nothing else have been written. Every one of
/// them must be gone: the passport keeps its status, no version, no audit
/// entry, no delivery.
#[tokio::test]
async fn a_change_that_fails_part_way_leaves_nothing_behind() {
    let pg = start_pg().await;
    subscribe(&pg).await;
    let repo = PgPassportRepo::new(pg.dal.clone());
    let p = repo
        .create(passport(PassportStatus::Published))
        .await
        .expect("create");

    let refused =
        suspension(p.id).with_transfer_notice(uuid::Uuid::now_v7(), serde_json::json!({}));
    let result = PgStateChangeLog::new(pg.dal.clone()).commit(refused).await;
    assert!(result.is_err(), "a notice without a chain is refused");

    let stored = repo.find_by_id(p.id).await.expect("read").expect("exists");
    assert_eq!(stored.status, PassportStatus::Published);
    assert!(
        PgPassportVersionRepo::new(pg.dal.clone())
            .versions(&p.id.to_string())
            .await
            .expect("versions")
            .is_empty(),
        "no version for a change that did not happen"
    );
    assert!(
        PgAuditRepo::new(pg.dal.clone())
            .list_by_passport(&p.id.to_string())
            .await
            .expect("audit")
            .is_empty()
    );
    assert_eq!(pending_deliveries(&pg).await, 0);
}

/// A create archives nothing, as the archiving decorator's `create` does not:
/// archiving starts at the first change.
#[tokio::test]
async fn a_create_archives_nothing() {
    let pg = start_pg().await;
    let p = passport(PassportStatus::Draft);
    let id = p.id;
    let change = StateChange::new(PassportAuditEntry::new(
        &id.to_string(),
        "created",
        "state-change-test",
        None,
        Some("draft"),
    ))
    .with_passport(PassportWrite::Insert(p));

    PgStateChangeLog::new(pg.dal.clone())
        .commit(change)
        .await
        .expect("commit");

    assert!(
        PgPassportRepo::new(pg.dal.clone())
            .find_by_id(id)
            .await
            .expect("read")
            .is_some()
    );
    assert!(
        PgPassportVersionRepo::new(pg.dal.clone())
            .versions(&id.to_string())
            .await
            .expect("versions")
            .is_empty()
    );
}

/// A published passport with a pending registration, for the registry tests.
async fn published_and_registered(pg: &TestPg) -> PassportId {
    let draft = PgPassportRepo::new(pg.dal.clone())
        .create(passport(PassportStatus::Draft))
        .await
        .expect("create");
    let mut published = draft.clone();
    published.status = PassportStatus::Published;
    published.published_at = Some(Utc::now());
    PgStateChangeLog::new(pg.dal.clone())
        .commit(
            StateChange::new(PassportAuditEntry::new(
                &draft.id.to_string(),
                "published",
                "state-change-test",
                None,
                Some("active"),
            ))
            .with_passport(PassportWrite::Replace(published))
            .with_registration(serde_json::json!({ "registration": "payload" })),
        )
        .await
        .expect("publish");
    draft.id
}

async fn registry_intent(pg: &TestPg, id: PassportId) -> Option<RegistryStatusIntent> {
    PgRegistrySyncRepo::new(pg.dal.clone())
        .pending_for(id)
        .await
        .expect("read the registry row")
        .expect("the registration is still pending")
        .status_intent
}

/// The status a suspension owes the registry commits with the suspension.
///
/// It used to be recorded after the commit as "non-fatal", so a node killed in
/// between left the registry believing a suspended passport was live, with
/// nothing to re-queue it.
#[tokio::test]
async fn a_suspension_records_the_registry_status_it_owes() {
    let pg = start_pg().await;
    let id = published_and_registered(&pg).await;

    PgStateChangeLog::new(pg.dal.clone())
        .commit(suspension(id).with_registry_intent(RegistryStatusIntent::Suspended))
        .await
        .expect("suspend");

    assert_eq!(
        registry_intent(&pg, id).await,
        Some(RegistryStatusIntent::Suspended)
    );
}

/// A refused change records no registry status either.
#[tokio::test]
async fn a_refused_change_records_no_registry_status() {
    let pg = start_pg().await;
    let id = published_and_registered(&pg).await;

    let refused = suspension(id)
        .with_registry_intent(RegistryStatusIntent::Suspended)
        .with_transfer_notice(uuid::Uuid::now_v7(), serde_json::json!({}));
    assert!(
        PgStateChangeLog::new(pg.dal.clone())
            .commit(refused)
            .await
            .is_err()
    );

    assert_eq!(registry_intent(&pg, id).await, None);
}
