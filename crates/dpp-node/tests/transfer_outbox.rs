//! Integration test: the registry transfer-notification **outbox**.
//!
//! Proves the sentence in `ops/pg/0029_registry_transfer.sql` — "written in the
//! accept transaction; drained with backoff" — is true in code:
//!
//!   (a) accepting a transfer persists the chain and enqueues the notification
//!       atomically, so a killed node cannot lose a handover the registry is owed;
//!   (b) **a passport transferred twice produces two rows** — the reason the key
//!       is `transfer_id` and not `passport_id`. Keying by passport would let the
//!       second handover overwrite the first, and the registry would only ever
//!       hear about the last one;
//!   (c) re-accepting the same transfer is idempotent and never re-notifies;
//!   (d) a transient failure backs off and keeps the row drainable;
//!   (e) a terminal rejection is recorded, never dropped.
//!
//! Run: `cargo test -p dpp-node --features integration-tests --test transfer_outbox`

#![cfg(feature = "integration-tests")]

use std::sync::Arc;

use chrono::Utc;
use testcontainers::{
    GenericImage, ImageExt,
    core::{WaitFor, ports::ContainerPort},
    runners::AsyncRunner,
};
use uuid::Uuid;

use dpp_dal::pg::{PgDal, PgPassportRepo, PgRegistryTransferRepo, sqlx};
use dpp_domain::{
    domain::{
        passport::{ManufacturerInfo, Passport, PassportId},
        sector::Sector,
        status::PassportStatus,
        transfer::{
            OperatorRole, ResponsibleOperator, TransferChain, TransferReason, TransferRecord,
        },
    },
    ports::passport_repo::PassportRepository,
};
use dpp_types::{RegistryTransferOutbox, RegistryTransferStatus};

// ─── Harness ────────────────────────────────────────────────────────────────

async fn start_pg() -> (PgDal, testcontainers::ContainerAsync<GenericImage>) {
    let image = GenericImage::new("postgres", "17")
        .with_exposed_port(ContainerPort::Tcp(5432))
        .with_wait_for(WaitFor::message_on_stderr(
            "database system is ready to accept connections",
        ))
        .with_env_var("POSTGRES_USER", "postgres")
        .with_env_var("POSTGRES_PASSWORD", "test")
        .with_env_var("POSTGRES_DB", "odal");

    let container = image.start().await.expect("start postgres container");
    let port = container
        .get_host_port_ipv4(5432)
        .await
        .expect("mapped port");
    let admin_url = format!("postgres://postgres:test@127.0.0.1:{port}/odal");

    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;

    let admin = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&admin_url)
        .await
        .expect("admin connect");
    sqlx::query("CREATE ROLE odal_app LOGIN PASSWORD 'test'")
        .execute(&admin)
        .await
        .expect("create app role");
    PgDal::migrate(&admin_url).await.expect("apply migrations");

    let app_url = format!("postgres://odal_app:test@127.0.0.1:{port}/odal");
    let dal = PgDal::connect(&app_url).await.expect("app connect");
    (dal, container)
}

fn published_passport() -> Passport {
    Passport {
        id: PassportId::new(),
        batch_id: None,
        product_name: "Transferred Battery".into(),
        sector: Sector::Battery,
        product_category: None,
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
        jws_signature: None,
        public_jws_signature: None,
        disclosure_signatures: Default::default(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        published_at: Some(Utc::now()),
        schema_version: "2.0.0".into(),
        retention_locked: false,
        version: 1,
        supersedes_id: None,
        parent_passport_ref: None,
        component_refs: Vec::new(),
        retention_until: None,
        product_id: None,
        operator_identifier: Some("did:web:test.example".into()),
        facility: None,
        seal: None,
    }
}

fn operator(did: &str, name: &str) -> ResponsibleOperator {
    ResponsibleOperator {
        did: did.to_owned(),
        name: name.to_owned(),
        role: OperatorRole::Manufacturer,
        eu_operator_id: None,
        country: "DE".to_owned(),
    }
}

fn completed_record(passport_id: PassportId, from: &str, to: &str) -> TransferRecord {
    TransferRecord {
        transfer_id: Uuid::now_v7(),
        passport_id,
        from_operator: operator(&format!("did:web:{from}.example"), from),
        to_operator: operator(&format!("did:web:{to}.example"), to),
        reason: TransferReason::Sale,
        from_signature: Some(format!("jws-from-{from}")),
        to_signature: Some(format!("jws-to-{to}")),
        initiated_at: Utc::now(),
        completed_at: Some(Utc::now()),
        rejected_at: None,
        cancelled_at: None,
        notes: None,
    }
}

/// Persist a published passport and return an outbox handle over the same pool.
async fn setup(dal: &PgDal) -> (PassportId, Arc<dyn RegistryTransferOutbox>) {
    let repo = PgPassportRepo::new(dal.clone());
    let p = published_passport();
    repo.create(p.clone()).await.expect("create passport");
    let outbox: Arc<dyn RegistryTransferOutbox> =
        Arc::new(PgRegistryTransferRepo::new(dal.clone()));
    (p.id, outbox)
}

async fn accept(
    outbox: &Arc<dyn RegistryTransferOutbox>,
    chain: &mut TransferChain,
    record: TransferRecord,
) -> Uuid {
    let id = record.transfer_id;
    chain.transfers.push(record.clone());
    let payload = serde_json::to_value(&record).expect("serialise record");
    outbox
        .commit_accept(chain, id, payload)
        .await
        .expect("commit_accept must persist chain + enqueue atomically");
    id
}

// ─── Tests ──────────────────────────────────────────────────────────────────

/// Accepting a transfer writes the chain and enqueues the notification in one
/// transaction: the row exists, carries the signed record, and is drainable.
#[tokio::test]
async fn accepting_a_transfer_enqueues_a_pending_notification() {
    let (dal, _c) = start_pg().await;
    let (passport_id, outbox) = setup(&dal).await;

    let mut chain = TransferChain::new(passport_id, operator("did:web:acme.example", "Acme"));
    let record = completed_record(passport_id, "Acme", "Beta");
    let transfer_id = accept(&outbox, &mut chain, record).await;

    let due = outbox.due(10).await.expect("due query");
    assert_eq!(due.len(), 1, "the accepted transfer must be queued");
    assert_eq!(due[0].transfer_id, transfer_id);
    assert_eq!(due[0].passport_id, passport_id);
    assert_eq!(due[0].status, RegistryTransferStatus::Pending);

    // The signed record survives the round trip — signatures are the evidence
    // the handover was authorised, and they are what the registry is owed.
    let stored: TransferRecord =
        serde_json::from_value(due[0].payload.clone()).expect("payload is a TransferRecord");
    assert_eq!(stored.from_signature.as_deref(), Some("jws-from-Acme"));
    assert_eq!(stored.to_signature.as_deref(), Some("jws-to-Beta"));

    // And the chain was written in the same transaction.
    let chain_rows: i64 =
        sqlx::query_scalar("SELECT count(*) FROM odal.passport_transfer WHERE passport_id = $1")
            .bind(passport_id.0)
            .fetch_one(dal.pool())
            .await
            .expect("chain count");
    assert_eq!(
        chain_rows, 1,
        "the chain must be persisted alongside the row"
    );
}

/// **The reason the key is `transfer_id`.** A passport changes hands repeatedly;
/// each handover is its own notification. Keyed by passport, the second accept
/// would overwrite the first and the registry would never hear about it.
#[tokio::test]
async fn a_passport_transferred_twice_owes_two_notifications() {
    let (dal, _c) = start_pg().await;
    let (passport_id, outbox) = setup(&dal).await;

    let mut chain = TransferChain::new(passport_id, operator("did:web:acme.example", "Acme"));
    let first = accept(
        &outbox,
        &mut chain,
        completed_record(passport_id, "Acme", "Beta"),
    )
    .await;
    let second = accept(
        &outbox,
        &mut chain,
        completed_record(passport_id, "Beta", "Gamma"),
    )
    .await;

    let due = outbox.due(10).await.expect("due query");
    assert_eq!(
        due.len(),
        2,
        "both handovers must be queued — one row per transfer, not per passport"
    );
    let mut ids: Vec<Uuid> = due.iter().map(|r| r.transfer_id).collect();
    ids.sort();
    let mut expected = vec![first, second];
    expected.sort();
    assert_eq!(ids, expected);

    let rows = outbox.rows_for(passport_id).await.expect("rows_for");
    assert_eq!(rows.len(), 2, "both stay inspectable for this passport");
}

/// Re-accepting the same transfer must not re-queue it — and in particular must
/// not reset an already-notified row, which would notify the registry twice for
/// one handover.
#[tokio::test]
async fn re_accepting_the_same_transfer_never_re_notifies() {
    let (dal, _c) = start_pg().await;
    let (passport_id, outbox) = setup(&dal).await;

    let mut chain = TransferChain::new(passport_id, operator("did:web:acme.example", "Acme"));
    let record = completed_record(passport_id, "Acme", "Beta");
    let transfer_id = accept(&outbox, &mut chain, record.clone()).await;

    outbox
        .mark_notified(transfer_id, "EU-REG-T1".into())
        .await
        .expect("mark notified");

    // The same transfer is committed again (a retry of the accept path).
    let payload = serde_json::to_value(&record).unwrap();
    outbox
        .commit_accept(&chain, transfer_id, payload)
        .await
        .expect("a repeated accept must not error");

    assert!(
        outbox.due(10).await.expect("due query").is_empty(),
        "an already-notified transfer must not become drainable again"
    );
    let rows = outbox.rows_for(passport_id).await.expect("rows_for");
    assert_eq!(rows.len(), 1, "no duplicate row");
    assert_eq!(rows[0].status, RegistryTransferStatus::Notified);
    assert_eq!(rows[0].registry_id.as_deref(), Some("EU-REG-T1"));
}

/// A transient failure keeps the row, increments attempts, and pushes the next
/// attempt into the future — the notification is never lost, just deferred.
#[tokio::test]
async fn a_transient_failure_backs_off_without_losing_the_row() {
    let (dal, _c) = start_pg().await;
    let (passport_id, outbox) = setup(&dal).await;

    let mut chain = TransferChain::new(passport_id, operator("did:web:acme.example", "Acme"));
    let transfer_id = accept(
        &outbox,
        &mut chain,
        completed_record(passport_id, "Acme", "Beta"),
    )
    .await;

    outbox
        .mark_attempt_failed(transfer_id, "registry unreachable".into())
        .await
        .expect("mark attempt failed");

    assert!(
        outbox.due(10).await.expect("due query").is_empty(),
        "a backed-off row must not be immediately due again"
    );
    let rows = outbox.rows_for(passport_id).await.expect("rows_for");
    assert_eq!(
        rows[0].status,
        RegistryTransferStatus::Pending,
        "row stays pending"
    );
    assert_eq!(rows[0].attempts, 1);
    assert!(
        rows[0].next_attempt_at > Utc::now(),
        "backed off into the future"
    );
}

/// A terminal rejection stops the row draining but keeps it for audit.
#[tokio::test]
async fn a_rejected_notification_is_kept_for_audit() {
    let (dal, _c) = start_pg().await;
    let (passport_id, outbox) = setup(&dal).await;

    let mut chain = TransferChain::new(passport_id, operator("did:web:acme.example", "Acme"));
    let transfer_id = accept(
        &outbox,
        &mut chain,
        completed_record(passport_id, "Acme", "Beta"),
    )
    .await;

    outbox
        .mark_rejected(
            transfer_id,
            "registry rejected transfer notification".into(),
        )
        .await
        .expect("mark rejected");

    assert!(outbox.due(10).await.expect("due query").is_empty());
    let rows = outbox.rows_for(passport_id).await.expect("rows_for");
    assert_eq!(rows.len(), 1, "a rejected row is never deleted");
    assert_eq!(rows[0].status, RegistryTransferStatus::Rejected);

    let counts = outbox.status_counts(5).await.expect("status counts");
    assert_eq!(counts.rejected, 1);
    assert_eq!(counts.pending, 0);
}
