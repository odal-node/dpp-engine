//! `PgStateChangeLog`: a state change commits whole or not at all.
//!
//! Webhook deliveries used to be enqueued after the passport write, best
//! effort, so a node killed in between had changed a passport and told no
//! subscriber. These pin that the delivery rows, the archived version and the
//! audit entry now land in the change's own transaction, and that a failure
//! anywhere in it leaves none of them behind.

#![cfg(feature = "integration-tests")]

use std::time::{Duration, Instant};

use chrono::Utc;
use uuid::Uuid;

use dpp_dal::pg::sqlx::Row;
use dpp_dal::pg::{
    PgAuditRepo, PgPassportRepo, PgPassportVersionRepo, PgRegistrySyncRepo, PgStateChangeLog,
    PgTransferRepo, PgWebhookRepo, sqlx,
};
use dpp_dal::test_harness::{TestPg, sessions_waiting_for_a_lock, start_pg};
use dpp_domain::DppError;
use dpp_domain::compliance::{ComplianceResult, ComplianceStatus};
use dpp_domain::operator::{OperatorRole, ResponsibleOperator};
use dpp_domain::passport::{ManufacturerInfo, Passport, PassportId};
use dpp_domain::ports::passport_repo::PassportRepository;
use dpp_domain::product_group::ProductGroup;
use dpp_domain::status::PassportStatus;
use dpp_domain::transfer::{TransferChain, TransferReason, TransferRecord, TransferStatus};
use dpp_types::TransferStore;
use dpp_types::audit::{AuditRepository, PassportAuditEntry, PassportVersionStore};
use dpp_types::registry_sync::{RegistryStatusIntent, RegistrySyncOutbox};
use dpp_types::state_change::{PassportWrite, StateChange, StateChangeLog, WebhookEvent};
use dpp_types::transfer::VersionedChain;
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
const RETIRED: &str = "dpp.passport.retired";

/// A subscriber to `events`. The signing secret is made per run: nothing here
/// reads it back, and a literal would be a secret written into source.
async fn subscribe(pg: &TestPg, events: &[&str]) -> Uuid {
    PgWebhookRepo::new(pg.dal.clone())
        .create(
            &CreateWebhookRequest {
                url: "https://receiver.example/hook".into(),
                events: events.iter().map(|event| (*event).into()).collect(),
                description: None,
            },
            &Uuid::new_v4().to_string(),
        )
        .await
        .expect("create subscription")
        .id
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
/// it replaced, the audit entry and the delivery, which goes to the one active
/// subscription that asked for the event and to no other.
#[tokio::test]
async fn a_committed_change_writes_every_part() {
    let pg = start_pg().await;
    subscribe(&pg, &[SUSPENDED]).await;
    subscribe(&pg, &[RETIRED]).await;
    let removed = subscribe(&pg, &[SUSPENDED]).await;
    PgWebhookRepo::new(pg.dal.clone())
        .deactivate(removed)
        .await
        .expect("deactivate");
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

/// A status write is checked against the passport as it stands under the lock,
/// not as the caller last read it. A suspension decided while the passport was
/// published is refused once a supersession has committed in between, and
/// leaves nothing behind.
#[tokio::test]
async fn a_status_write_is_checked_against_the_locked_passport() {
    let pg = start_pg().await;
    subscribe(&pg, &[SUSPENDED]).await;
    let repo = PgPassportRepo::new(pg.dal.clone());
    let p = repo
        .create(passport(PassportStatus::Published))
        .await
        .expect("create");
    let log = PgStateChangeLog::new(pg.dal.clone());

    let supersession = StateChange::new(PassportAuditEntry::new(
        &p.id.to_string(),
        "superseded",
        "state-change-test",
        Some("active"),
        Some("superseded"),
    ))
    .with_passport(PassportWrite::Status(p.id, PassportStatus::Superseded));
    log.commit(supersession).await.expect("supersede");

    let refused = log.commit(suspension(p.id)).await;
    assert!(
        matches!(refused, Err(DppError::InvalidTransition { .. })),
        "a superseded passport cannot be suspended: {refused:?}"
    );

    let stored = repo.find_by_id(p.id).await.expect("read").expect("exists");
    assert_eq!(stored.status, PassportStatus::Superseded);
    let versions = PgPassportVersionRepo::new(pg.dal.clone())
        .versions(&p.id.to_string())
        .await
        .expect("versions");
    assert_eq!(
        versions.len(),
        1,
        "only the supersession archived a version"
    );
    let audit = PgAuditRepo::new(pg.dal.clone())
        .list_by_passport(&p.id.to_string())
        .await
        .expect("audit");
    assert_eq!(audit.len(), 1, "only the supersession was recorded");
    assert_eq!(pending_deliveries(&pg).await, 0);
}

/// Two changes that append to one passport's audit trail at once still leave
/// one chain. A status change locks the passport row, but a change that writes
/// no passport, a transfer for one, does not, so without a lock of their own
/// both read the same head and each appends a successor to it.
///
/// Change A is held after its append, in the delivery fan-out, by a lock on
/// the subscription table. Change B, an append and nothing else, then has to
/// wait for A instead of reading the head A has not committed.
#[tokio::test]
async fn concurrent_appends_to_one_passport_keep_one_chain() {
    let pg = start_pg().await;
    subscribe(&pg, &[SUSPENDED]).await;
    let p = PgPassportRepo::new(pg.dal.clone())
        .create(passport(PassportStatus::Published))
        .await
        .expect("create");
    // A transfer's entry, as the change that takes no passport row lock.
    let entry = || {
        PassportAuditEntry::new(
            &p.id.to_string(),
            "transferred",
            "state-change-test",
            None,
            None,
        )
    };
    let patience = Duration::from_secs(10);

    let mut hold = pg.dal.pool().begin().await.expect("begin");
    sqlx::query("LOCK TABLE odal.webhook_subscription IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *hold)
        .await
        .expect("lock the subscriptions");

    let a = tokio::spawn({
        let log = PgStateChangeLog::new(pg.dal.clone());
        let change = StateChange::new(entry()).with_webhook(WebhookEvent {
            event_type: SUSPENDED.into(),
            body: "{}".into(),
        });
        async move { log.commit(change).await }
    });
    let started = Instant::now();
    while !a.is_finished() && sessions_waiting_for_a_lock(&pg).await < 1 {
        assert!(
            started.elapsed() < patience,
            "change A never reached the fan-out"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    if a.is_finished() {
        panic!("change A was not held in its fan-out: {:?}", a.await);
    }

    let b = tokio::spawn({
        let log = PgStateChangeLog::new(pg.dal.clone());
        let change = StateChange::new(entry());
        async move { log.commit(change).await }
    });
    // B either waits for A, or has nothing to wait on and finishes first.
    let started = Instant::now();
    while !b.is_finished() && sessions_waiting_for_a_lock(&pg).await < 2 {
        assert!(
            started.elapsed() < patience,
            "change B neither waited nor finished"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    hold.commit().await.expect("release the subscriptions");
    a.await.expect("join A").expect("change A");
    b.await.expect("join B").expect("change B");

    let audit = PgAuditRepo::new(pg.dal.clone());
    let entries = audit
        .list_by_passport(&p.id.to_string())
        .await
        .expect("audit");
    assert_eq!(entries.len(), 2);
    assert_eq!(
        audit.verify_chain(&p.id.to_string()).await.expect("verify"),
        None,
        "two appends read the same head and forked the chain"
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
    subscribe(&pg, &[SUSPENDED]).await;
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

fn operator(did: &str) -> ResponsibleOperator {
    ResponsibleOperator {
        did: did.to_owned(),
        name: "Operator".to_owned(),
        role: OperatorRole::Manufacturer,
        eu_operator_id: None,
        eu_operator_id_scheme: None,
        registered_trade_name: None,
        postal_address: None,
        electronic_address: None,
        country: "DE".to_owned(),
        identifier: None,
    }
}

/// A handover to `to`, pending, as an initiation builds it.
fn handover(id: PassportId, to: &str) -> TransferRecord {
    TransferRecord {
        transfer_id: Uuid::now_v7(),
        passport_id: id,
        from_operator: operator("did:web:acme.example"),
        to_operator: operator(to),
        reason: TransferReason::Sale,
        from_signature: Some("from-jws".to_owned()),
        node_acceptance_attestation: None,
        initiated_at: Utc::now(),
        completed_at: None,
        rejected_at: None,
        cancelled_at: None,
        notes: None,
    }
}

/// A chain holding one pending handover to `to`.
fn pending_to(id: PassportId, to: &str) -> TransferChain {
    let mut chain = TransferChain::new(id, operator("did:web:acme.example"));
    chain
        .initiate_transfer(handover(id, to))
        .expect("the first handover");
    chain
}

/// A change that writes only `chain`, as a transfer step does.
fn chain_change(id: PassportId, chain: VersionedChain) -> StateChange {
    StateChange::new(PassportAuditEntry::new(
        &id.to_string(),
        "transferred",
        "state-change-test",
        None,
        None,
    ))
    .with_transfer_chain(chain)
}

async fn audit_entries(pg: &TestPg, id: PassportId) -> usize {
    PgAuditRepo::new(pg.dal.clone())
        .list_by_passport(&id.to_string())
        .await
        .expect("audit")
        .len()
}

/// Two initiations that both read "no chain yet": the second to write is
/// refused rather than replacing the first, and its audit entry goes with it.
///
/// The upsert behind this had no `WHERE`, so the second chain overwrote the
/// first and the first caller's handover had an audit entry and no place in the
/// chain.
#[tokio::test]
async fn a_chain_first_written_after_this_one_was_read_is_not_replaced() {
    let pg = start_pg().await;
    let p = PgPassportRepo::new(pg.dal.clone())
        .create(passport(PassportStatus::Published))
        .await
        .expect("create");
    let log = PgStateChangeLog::new(pg.dal.clone());
    let store = PgTransferRepo::new(pg.dal.clone());
    assert!(store.get_chain(p.id).await.expect("read").is_none());

    log.commit(chain_change(
        p.id,
        VersionedChain::unstored(pending_to(p.id, "did:web:a.example")),
    ))
    .await
    .expect("the first initiation");
    let refused = log
        .commit(chain_change(
            p.id,
            VersionedChain::unstored(pending_to(p.id, "did:web:b.example")),
        ))
        .await
        .expect_err("the second read no chain either");
    assert!(matches!(refused, DppError::Validation(_)), "{refused:?}");

    let stored = store.get_chain(p.id).await.expect("read").expect("a chain");
    assert_eq!(stored.chain.transfers.len(), 1);
    assert_eq!(
        stored.chain.transfers[0].to_operator.did,
        "did:web:a.example"
    );
    assert_eq!(
        audit_entries(&pg, p.id).await,
        1,
        "the refused entry stayed"
    );
}

/// Two steps that both read a pending handover: whichever writes second is
/// refused, and the chain says what the first did.
#[tokio::test]
async fn a_chain_changed_after_it_was_read_is_not_overwritten() {
    let pg = start_pg().await;
    let p = PgPassportRepo::new(pg.dal.clone())
        .create(passport(PassportStatus::Published))
        .await
        .expect("create");
    let log = PgStateChangeLog::new(pg.dal.clone());
    let store = PgTransferRepo::new(pg.dal.clone());
    log.commit(chain_change(
        p.id,
        VersionedChain::unstored(pending_to(p.id, "did:web:a.example")),
    ))
    .await
    .expect("initiate");

    let mut cancel = store.get_chain(p.id).await.expect("read").expect("chain");
    let mut reject = store.get_chain(p.id).await.expect("read").expect("chain");
    assert_eq!(cancel.revision, reject.revision);
    cancel.chain.transfers[0].cancel().expect("cancel");
    reject.chain.transfers[0].reject().expect("reject");

    log.commit(chain_change(p.id, cancel))
        .await
        .expect("the first step");
    let refused = log
        .commit(chain_change(p.id, reject))
        .await
        .expect_err("the second step read the chain before the first wrote it");
    assert!(matches!(refused, DppError::Validation(_)), "{refused:?}");

    let stored = store.get_chain(p.id).await.expect("read").expect("chain");
    assert_eq!(
        stored.chain.transfers[0].status(),
        TransferStatus::Cancelled
    );

    // A step that reads again is over the revision the first one left.
    let mut again = stored;
    again
        .chain
        .initiate_transfer(handover(p.id, "did:web:c.example"))
        .expect("a cancelled handover frees the chain");
    log.commit(chain_change(p.id, again))
        .await
        .expect("a step over the current revision");
    assert_eq!(audit_entries(&pg, p.id).await, 3);
}

/// `save_chain` writes whatever is stored, but it moves the revision all the
/// same: a step that read the chain before it is refused, not left to write over
/// it.
#[tokio::test]
async fn an_unconditional_save_still_moves_the_revision() {
    let pg = start_pg().await;
    let p = PgPassportRepo::new(pg.dal.clone())
        .create(passport(PassportStatus::Published))
        .await
        .expect("create");
    let log = PgStateChangeLog::new(pg.dal.clone());
    let store = PgTransferRepo::new(pg.dal.clone());
    log.commit(chain_change(
        p.id,
        VersionedChain::unstored(pending_to(p.id, "did:web:a.example")),
    ))
    .await
    .expect("initiate");

    let read = store.get_chain(p.id).await.expect("read").expect("chain");
    store.save_chain(&read.chain).await.expect("save");

    let refused = log
        .commit(chain_change(p.id, read))
        .await
        .expect_err("the save came after the read");
    assert!(matches!(refused, DppError::Validation(_)), "{refused:?}");
}

/// The upsert the previous release ran never names the revision, and a node
/// still running it beside this one must not be able to write a chain under a
/// step that read the old one: the table moves the revision, not the writer.
#[tokio::test]
async fn a_write_that_never_names_the_revision_still_moves_it() {
    let pg = start_pg().await;
    let p = PgPassportRepo::new(pg.dal.clone())
        .create(passport(PassportStatus::Published))
        .await
        .expect("create");
    let log = PgStateChangeLog::new(pg.dal.clone());
    let store = PgTransferRepo::new(pg.dal.clone());
    log.commit(chain_change(
        p.id,
        VersionedChain::unstored(pending_to(p.id, "did:web:a.example")),
    ))
    .await
    .expect("initiate");
    let read = store.get_chain(p.id).await.expect("read").expect("chain");

    sqlx::query(
        r#"INSERT INTO odal.passport_transfer (passport_id, chain, updated_at)
           VALUES ($1, $2, now())
           ON CONFLICT (passport_id)
           DO UPDATE SET chain = EXCLUDED.chain, updated_at = now()"#,
    )
    .bind(p.id.0)
    .bind(serde_json::to_value(&read.chain).expect("serialise"))
    .execute(pg.dal.pool())
    .await
    .expect("the previous release's upsert");

    let moved = store.get_chain(p.id).await.expect("read").expect("chain");
    assert_ne!(moved.revision, read.revision);
    let refused = log
        .commit(chain_change(p.id, read))
        .await
        .expect_err("the upsert came after the read");
    assert!(matches!(refused, DppError::Validation(_)), "{refused:?}");
}

/// Several first initiations committed at once: exactly one stands.
///
/// The sequential tests above fix what a stale write is; this one is the
/// database arbitrating between writers that are really in flight, the insert
/// racing on the unique key. Without the check every writer succeeds.
#[tokio::test(flavor = "multi_thread")]
async fn of_several_first_initiations_written_together_exactly_one_stands() {
    let pg = start_pg().await;
    let p = PgPassportRepo::new(pg.dal.clone())
        .create(passport(PassportStatus::Published))
        .await
        .expect("create");

    let writers: Vec<_> = (0..6)
        .map(|n| {
            let log = PgStateChangeLog::new(pg.dal.clone());
            let change = chain_change(
                p.id,
                VersionedChain::unstored(pending_to(p.id, &format!("did:web:to{n}.example"))),
            );
            tokio::spawn(async move { log.commit(change).await })
        })
        .collect();
    let mut won = Vec::new();
    for (n, writer) in writers.into_iter().enumerate() {
        match writer.await.expect("join") {
            Ok(_) => won.push(n),
            Err(e) => assert!(matches!(e, DppError::Validation(_)), "{e:?}"),
        }
    }
    assert_eq!(won.len(), 1, "writers that succeeded: {won:?}");

    let stored = PgTransferRepo::new(pg.dal.clone())
        .get_chain(p.id)
        .await
        .expect("read")
        .expect("chain");
    assert_eq!(stored.chain.transfers.len(), 1);
    assert_eq!(
        stored.chain.transfers[0].to_operator.did,
        format!("did:web:to{}.example", won[0])
    );
    assert_eq!(audit_entries(&pg, p.id).await, 1);
}

// ── The compliance determination ─────────────────────────────────────────────
//
// A stored `complianceResult` is the determination of the content stored beside
// it, and `assessed_at` and `ruleset_version` are projections of it. These read
// the row itself, not the passport read back from it: the document merge omits a
// determination a passport no longer carries, so a stored one would survive and
// a struct read would show the same `None` either way.

fn determination(co2e: f64, ruleset: Option<&str>) -> ComplianceResult {
    use chrono::SubsecRound;
    ComplianceResult {
        co2e_score: Some(co2e),
        compliance_status: ComplianceStatus::PassthroughNoValidation,
        ruleset_version: ruleset.map(str::to_owned),
        // To the microsecond, which is what the column keeps.
        assessed_at: Some(Utc::now().trunc_subsecs(6)),
        ..ComplianceResult::default()
    }
}

fn determined(status: PassportStatus, result: ComplianceResult) -> Passport {
    let mut p = passport(status);
    p.compliance_result = Some(result);
    p
}

/// What the row says about its determination.
struct Stored {
    /// Whether the document has a `complianceResult` key at all.
    in_doc: bool,
    co2e: Option<f64>,
    assessed_at: Option<chrono::DateTime<Utc>>,
    ruleset_version: Option<String>,
}

async fn stored(pg: &TestPg, id: PassportId) -> Stored {
    let row = sqlx::query(
        r#"SELECT jsonb_exists(doc, 'complianceResult') AS in_doc,
                  (doc->'complianceResult'->>'co2eScore')::float8 AS co2e,
                  assessed_at, ruleset_version
           FROM odal.passport WHERE id = $1"#,
    )
    .bind(id.0)
    .fetch_one(pg.dal.pool())
    .await
    .expect("read the row");
    Stored {
        in_doc: row.get("in_doc"),
        co2e: row.get("co2e"),
        assessed_at: row.get("assessed_at"),
        ruleset_version: row.get("ruleset_version"),
    }
}

fn change_to(write: PassportWrite, id: PassportId) -> StateChange {
    StateChange::new(PassportAuditEntry::new(
        &id.to_string(),
        "updated",
        "state-change-test",
        None,
        None,
    ))
    .with_passport(write)
}

/// 🚨 The `||` trap. `Passport` omits a `None` field and the update merges the
/// document over the stored one, so a determination a publish could not make
/// used to leave the earlier one in the row, to be signed. The columns kept
/// their values too, being `COALESCE`d onto them.
#[tokio::test]
async fn a_replace_that_carries_no_determination_removes_the_stored_one() {
    let pg = start_pg().await;
    let draft = PgPassportRepo::new(pg.dal.clone())
        .create(determined(
            PassportStatus::Draft,
            determination(12.5, Some("ruleset@1")),
        ))
        .await
        .expect("create");
    let before = stored(&pg, draft.id).await;
    assert!(before.in_doc && before.assessed_at.is_some() && before.ruleset_version.is_some());

    let mut next = draft.clone();
    next.compliance_result = None;
    PgStateChangeLog::new(pg.dal.clone())
        .commit(change_to(PassportWrite::Replace(next), draft.id))
        .await
        .expect("replace");

    let after = stored(&pg, draft.id).await;
    assert!(!after.in_doc, "the key leaves the document");
    assert_eq!(after.co2e, None);
    assert_eq!(after.assessed_at, None);
    assert_eq!(after.ruleset_version, None);
}

/// The registry outbox's publish and the repository's own `update` write the
/// passport through the same statement, so the removal holds on each of the
/// three ways a publish reaches the database.
#[tokio::test]
async fn the_removal_holds_through_the_outbox_and_the_repository_alike() {
    let pg = start_pg().await;
    let repo = PgPassportRepo::new(pg.dal.clone());

    let through_outbox = repo
        .create(determined(
            PassportStatus::Draft,
            determination(1.0, Some("ruleset@1")),
        ))
        .await
        .expect("create");
    let mut none = through_outbox.clone();
    none.compliance_result = None;
    PgRegistrySyncRepo::new(pg.dal.clone())
        .commit_publish(&none, serde_json::json!({ "registration": "payload" }))
        .await
        .expect("commit publish");
    let after = stored(&pg, through_outbox.id).await;
    assert!(!after.in_doc && after.assessed_at.is_none() && after.ruleset_version.is_none());

    let through_repo = repo
        .create(determined(
            PassportStatus::Draft,
            determination(2.0, Some("ruleset@1")),
        ))
        .await
        .expect("create");
    let mut none = through_repo.clone();
    none.compliance_result = None;
    repo.update(none).await.expect("update");
    let after = stored(&pg, through_repo.id).await;
    assert!(!after.in_doc && after.assessed_at.is_none() && after.ruleset_version.is_none());
}

/// A determination with no ruleset version is stored as having none. The column
/// was `COALESCE`d onto the stored one, so it kept the version of the
/// determination before it.
#[tokio::test]
async fn a_replace_stores_the_determination_it_carries_and_no_other_columns() {
    let pg = start_pg().await;
    let draft = PgPassportRepo::new(pg.dal.clone())
        .create(determined(
            PassportStatus::Draft,
            determination(1.0, Some("ruleset@1")),
        ))
        .await
        .expect("create");

    let next = determination(9.5, None);
    let at = next.assessed_at;
    let mut replaced = draft.clone();
    replaced.compliance_result = Some(next);
    PgStateChangeLog::new(pg.dal.clone())
        .commit(change_to(PassportWrite::Replace(replaced), draft.id))
        .await
        .expect("replace");

    let after = stored(&pg, draft.id).await;
    assert!(after.in_doc);
    assert_eq!(after.co2e, Some(9.5));
    assert_eq!(after.ruleset_version, None, "not the version before it");
    assert_eq!(after.assessed_at, at);
}

/// A draft edit stores the determination of the edited content in the same
/// statement as the delta, and the version it archives is the record as it was:
/// the determination before the edit, not the one the edit brings.
#[tokio::test]
async fn a_patch_stores_the_determination_beside_the_delta_and_archives_the_old_one() {
    let pg = start_pg().await;
    let draft = PgPassportRepo::new(pg.dal.clone())
        .create(determined(
            PassportStatus::Draft,
            determination(1.0, Some("ruleset@1")),
        ))
        .await
        .expect("create");

    let written = PgStateChangeLog::new(pg.dal.clone())
        .commit(change_to(
            PassportWrite::Patch {
                id: draft.id,
                delta: serde_json::json!({ "productName": "Renamed" }),
                determination: Some(determination(2.0, Some("ruleset@2"))),
            },
            draft.id,
        ))
        .await
        .expect("patch")
        .expect("a patch returns the passport");
    assert_eq!(written.product_name, "Renamed");
    assert_eq!(
        written
            .compliance_result
            .as_ref()
            .and_then(|r| r.co2e_score),
        Some(2.0)
    );

    let after = stored(&pg, draft.id).await;
    assert_eq!(after.co2e, Some(2.0));
    assert_eq!(after.ruleset_version.as_deref(), Some("ruleset@2"));
    assert!(after.assessed_at.is_some());

    let versions = PgPassportVersionRepo::new(pg.dal.clone())
        .versions(&draft.id.to_string())
        .await
        .expect("versions");
    assert_eq!(versions.len(), 1, "one change, one archived version");
    assert_eq!(
        versions[0].doc["complianceResult"]["co2eScore"],
        serde_json::json!(1.0),
        "the version is the record as it was stored"
    );
}

/// An edit that leaves nothing to assess removes the stored determination, and
/// with it both columns.
#[tokio::test]
async fn a_patch_with_no_determination_removes_the_stored_one() {
    let pg = start_pg().await;
    let draft = PgPassportRepo::new(pg.dal.clone())
        .create(determined(
            PassportStatus::Draft,
            determination(1.0, Some("ruleset@1")),
        ))
        .await
        .expect("create");

    let written = PgStateChangeLog::new(pg.dal.clone())
        .commit(change_to(
            PassportWrite::Patch {
                id: draft.id,
                delta: serde_json::json!({ "productName": "Renamed" }),
                determination: None,
            },
            draft.id,
        ))
        .await
        .expect("patch")
        .expect("a patch returns the passport");
    assert!(written.compliance_result.is_none());

    let after = stored(&pg, draft.id).await;
    assert!(!after.in_doc && after.assessed_at.is_none() && after.ruleset_version.is_none());
}

/// A status-only write through the repository reads the passport under the lock
/// it writes with. Read before it, the write stores what the passport carried
/// then, and an edit that stored a determination while the write waited would
/// have it removed by a change that is about the status.
#[tokio::test]
async fn a_status_write_keeps_a_determination_stored_while_it_waited() {
    let pg = start_pg().await;
    let repo = PgPassportRepo::new(pg.dal.clone());
    let draft = repo
        .create(passport(PassportStatus::Draft))
        .await
        .expect("create");
    assert!(!stored(&pg, draft.id).await.in_doc);
    let patience = Duration::from_secs(10);

    let mut hold = pg.dal.pool().begin().await.expect("begin");
    sqlx::query("SELECT 1 FROM odal.passport WHERE id = $1 FOR UPDATE")
        .bind(draft.id.0)
        .execute(&mut *hold)
        .await
        .expect("lock the row");

    let status = tokio::spawn({
        let repo = PgPassportRepo::new(pg.dal.clone());
        let id = draft.id;
        async move { repo.update_status(id, PassportStatus::Retired).await }
    });
    let started = Instant::now();
    while !status.is_finished() && sessions_waiting_for_a_lock(&pg).await < 1 {
        assert!(
            started.elapsed() < patience,
            "the status write never waited"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(!status.is_finished(), "the status write was not held");

    // An edit stores its determination while the status write waits.
    let result = determination(7.5, Some("ruleset@1"));
    sqlx::query(
        r#"UPDATE odal.passport SET
             doc = jsonb_set(doc, '{complianceResult}', $2),
             assessed_at = NULLIF($2->>'assessedAt','')::timestamptz,
             ruleset_version = $2->>'rulesetVersion'
           WHERE id = $1"#,
    )
    .bind(draft.id.0)
    .bind(serde_json::to_value(&result).expect("serialise"))
    .execute(&mut *hold)
    .await
    .expect("store the determination");
    hold.commit().await.expect("release the row");

    let written = status
        .await
        .expect("join")
        .expect("the status write succeeds");
    assert_eq!(written.status, PassportStatus::Retired);
    assert_eq!(
        written
            .compliance_result
            .as_ref()
            .and_then(|r| r.co2e_score),
        Some(7.5),
        "it wrote the passport as it stood once the lock was its own"
    );
    let after = stored(&pg, draft.id).await;
    assert!(after.in_doc && after.assessed_at.is_some());
    assert_eq!(after.co2e, Some(7.5));
    assert_eq!(after.ruleset_version.as_deref(), Some("ruleset@1"));
}

/// A published passport's determination is frozen with the rest of its content,
/// and the retention guard does not list it among the mutable keys. A status
/// change carries the stored one and writes nothing of it; a write that carries a
/// different one, or none, is refused and leaves the row as it was. This is why a
/// re-publish keeps the determination it was first published with.
#[tokio::test]
async fn a_locked_row_keeps_its_determination() {
    let pg = start_pg().await;
    let mut locked = determined(
        PassportStatus::Published,
        determination(5.0, Some("ruleset@1")),
    );
    locked.retention_locked = true;
    locked.retention_until = Some(Utc::now() + chrono::Duration::days(3650));
    let repo = PgPassportRepo::new(pg.dal.clone());
    let locked = repo.create(locked).await.expect("create");
    let before = stored(&pg, locked.id).await;
    let log = PgStateChangeLog::new(pg.dal.clone());

    log.commit(suspension(locked.id))
        .await
        .expect("a status change leaves the determination as it is");
    let after = stored(&pg, locked.id).await;
    assert!(after.in_doc);
    assert_eq!(after.co2e, before.co2e);
    assert_eq!(after.ruleset_version, before.ruleset_version);
    assert_eq!(
        after.assessed_at.map(|t| t.timestamp_micros()),
        before.assessed_at.map(|t| t.timestamp_micros())
    );

    let current = repo
        .find_by_id_any_status(locked.id)
        .await
        .expect("read")
        .expect("exists");
    for compliance_result in [Some(determination(6.0, Some("ruleset@2"))), None] {
        let mut replaced = current.clone();
        replaced.compliance_result = compliance_result;
        let refused = log
            .commit(change_to(PassportWrite::Replace(replaced), locked.id))
            .await
            .expect_err("a published passport's determination is frozen");
        assert!(matches!(refused, DppError::RetentionLocked), "{refused:?}");
    }
    let unchanged = stored(&pg, locked.id).await;
    assert!(unchanged.in_doc);
    assert_eq!(unchanged.co2e, before.co2e);
}
