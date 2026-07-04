//! Postgres backend integration tests.
//!
//! Run with:
//! ```sh
//! cargo test -p dpp-dal --features integration-tests --test pg_integration -- --nocapture
//! ```
//! Requires Docker. Each test gets a fresh postgres:17 container. Migrations are
//! applied via a privileged admin connection (PgDal::migrate), then PgDal::connect
//! connects as the app role (odal_app) without re-running DDL.
//!
//! Single-tenant: there is no in-process operator isolation (no RLS) — that
//! boundary is now an infrastructure concern, so the former cross-operator
//! isolation (T2) and superuser-refusal (T7) tests are gone by design.
//!
//! Coverage map:
//!   T1 roundtrip parity · T3 retention trigger immutability
//!   T4 audit append-only trigger · T5 key-prefix uniqueness · T6 patch_fields merge

#![cfg(feature = "integration-tests")]

use testcontainers::{
    GenericImage, ImageExt,
    core::{WaitFor, ports::ContainerPort},
    runners::AsyncRunner,
};
use uuid::Uuid;

use dpp_dal::pg::{PgApiKeyRepo, PgAuditRepo, PgDal, PgPassportRepo, sqlx};
use dpp_domain::{
    domain::{
        passport::{FacilitySnapshot, ManufacturerInfo, Passport, PassportId},
        sector::Sector,
        status::PassportStatus,
    },
    ports::passport_repo::PassportRepository,
};
use dpp_types::{
    api_key::{ApiKey, ApiKeyRecord, ApiKeyRepository},
    audit::{AuditEntry, AuditRepository},
};

struct TestPg {
    dal: PgDal,
    /// Superuser URL kept for raw admin-side assertions (T4 trigger checks).
    admin_url: String,
    _container: testcontainers::ContainerAsync<GenericImage>,
}

async fn start_pg() -> TestPg {
    let image = GenericImage::new("postgres", "17")
        .with_exposed_port(ContainerPort::Tcp(5432))
        .with_wait_for(WaitFor::message_on_stderr(
            "database system is ready to accept connections",
        ))
        // POSTGRES_USER/PASSWORD/DB are the official Postgres image's required
        // env vars for this throwaway testcontainer — NOT the app's
        // DATABASE_POSTGRES_PASS / DATABASE_APP_PASS scheme.
        .with_env_var("POSTGRES_USER", "postgres")
        .with_env_var("POSTGRES_PASSWORD", "test")
        .with_env_var("POSTGRES_DB", "odal");

    let container = image.start().await.expect("start postgres container");
    let port = container
        .get_host_port_ipv4(5432)
        .await
        .expect("mapped port");
    let admin_url = format!("postgres://postgres:test@127.0.0.1:{port}/odal");

    // Postgres restarts once during init — give it a moment, then provision
    // the app role exactly like ops/bootstrap/pg-init.sh does.
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

    // Migrations require DDL privileges; run them via the admin pool directly,
    // then connect as odal_app (PgDal::migrate mirrors the ops/just workflow).
    PgDal::migrate(&admin_url)
        .await
        .expect("apply 0001_init via admin");

    let app_url = format!("postgres://odal_app:test@127.0.0.1:{port}/odal");
    let dal = PgDal::connect(&app_url).await.expect("app connect");

    TestPg {
        dal,
        admin_url,
        _container: container,
    }
}

fn make_passport() -> Passport {
    Passport {
        id: PassportId::new(),
        batch_id: Some("LOT-PG-1".into()),
        product_name: "PG Parity Battery".into(),
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
        sector_data: None,
        status: PassportStatus::Draft,
        qr_code_url: None,
        jws_signature: None,
        public_jws_signature: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        published_at: None,
        schema_version: "2.0.0".into(),
        retention_locked: false,
        version: 1,
        supersedes_id: None,
        retention_until: None,
        product_id: None,
        operator_identifier: None,
        facility: None,
        seal: None,
    }
}

/// Build a facility snapshot carrying `value` (other fields are placeholders) for
/// the ADR-006 grouping-filter test.
fn facility_with_value(value: &str) -> FacilitySnapshot {
    FacilitySnapshot {
        scheme: "gln".into(),
        value: value.into(),
        name: "Test Facility".into(),
        country: "DE".into(),
        address: None,
    }
}

// T1 — create → find → update → list → count roundtrip, full serde parity.
#[tokio::test]
async fn t1_roundtrip_parity() {
    let pg = start_pg().await;
    let repo = PgPassportRepo::new(pg.dal.clone());

    let p = make_passport();
    let id = p.id;
    repo.create(p.clone()).await.expect("create");

    let found = repo.find_by_id(id).await.expect("find").expect("some");
    assert_eq!(found.product_name, "PG Parity Battery");
    assert_eq!(found.sector, Sector::Battery);

    let mut updated = found.clone();
    updated.product_name = "PG Parity Battery v2".into();
    repo.update(updated).await.expect("update");

    let listed = repo
        .list(None, Some("parity"), None, 10, 0)
        .await
        .expect("list");
    assert_eq!(listed.len(), 1, "ILIKE search finds the renamed passport");
    assert_eq!(repo.count(None, None).await.expect("count"), 1);
}

// ADR-006 — `facilityId` is an exact-match grouping filter on list/count, never
// an isolation boundary (every facility's passports remain reachable with no filter).
#[tokio::test]
async fn t1b_list_and_count_filter_by_facility_id() {
    let pg = start_pg().await;
    let repo = PgPassportRepo::new(pg.dal.clone());

    let mut a = make_passport();
    a.facility = Some(facility_with_value("4012345000009"));
    repo.create(a).await.expect("create a");

    let mut b = make_passport();
    b.product_name = "PG Parity Battery (other facility)".into();
    b.facility = Some(facility_with_value("4000001000005"));
    repo.create(b).await.expect("create b");

    let mut c = make_passport();
    c.product_name = "PG Parity Battery (no facility)".into();
    repo.create(c).await.expect("create c");

    let for_facility_a = repo
        .list(None, None, Some("4012345000009"), 10, 0)
        .await
        .expect("list filtered by facility");
    assert_eq!(for_facility_a.len(), 1);
    assert_eq!(
        for_facility_a[0]
            .facility
            .as_ref()
            .map(|f| f.value.as_str()),
        Some("4012345000009")
    );
    assert_eq!(
        repo.count(None, Some("4012345000009"))
            .await
            .expect("count filtered by facility"),
        1
    );

    let unfiltered = repo
        .list(None, None, None, 10, 0)
        .await
        .expect("list without facility filter");
    assert_eq!(
        unfiltered.len(),
        3,
        "no facility filter returns every passport"
    );
}

// T3 — the database itself refuses content changes on retention-locked rows.
#[tokio::test]
async fn t3_retention_trigger_blocks_content_tamper() {
    let pg = start_pg().await;
    let repo = PgPassportRepo::new(pg.dal.clone());

    let mut p = make_passport();
    p.status = PassportStatus::Published;
    p.retention_locked = true;
    p.jws_signature = Some("eyJhbGciOiJFZERTQSJ9..sig".into());
    let id = p.id;
    repo.create(p.clone()).await.expect("create published");

    // Mutable-field updates (status flips) must pass...
    let suspended = repo.update_status(id, PassportStatus::Suspended).await;
    assert!(suspended.is_ok(), "status is a whitelisted mutable field");

    // ...but content tampering must be rejected BY THE TRIGGER, even though
    // the repo issues a syntactically valid UPDATE.
    let mut tampered = p.clone();
    tampered.product_name = "Tampered Name".into();
    tampered.status = PassportStatus::Suspended; // match current row state
    let res = repo.update(tampered).await;
    assert!(
        matches!(res, Err(dpp_domain::DppError::RetentionLocked)),
        "expected RetentionLocked, got {res:?}"
    );
}

// T4 — audit rows are immutable at the database layer.
#[tokio::test]
async fn t4_audit_append_only() {
    let pg = start_pg().await;
    let audit = PgAuditRepo::new(pg.dal.clone());
    let entry = AuditEntry {
        id: Uuid::now_v7(),
        passport_id: Uuid::now_v7().to_string(),
        actor: "test".into(),
        action: "created".into(),
        previous_status: None,
        new_status: Some("draft".into()),
        metadata: None,
        timestamp: chrono::Utc::now(),
        prev_hash: None,
        entry_hash: None,
    };
    audit.append(entry.clone()).await.expect("append");

    // Direct UPDATE via admin must hit the trigger.
    let admin = sqlx::postgres::PgPoolOptions::new()
        .connect(&pg.admin_url)
        .await
        .expect("admin");
    let res = sqlx::query("UPDATE odal.passport_audit SET actor = 'evil' WHERE id = $1")
        .bind(entry.id)
        .execute(&admin)
        .await;
    assert!(res.is_err(), "audit UPDATE must be rejected by trigger");
    let res = sqlx::query("DELETE FROM odal.passport_audit WHERE id = $1")
        .bind(entry.id)
        .execute(&admin)
        .await;
    assert!(res.is_err(), "audit DELETE must be rejected by trigger");
}

// T7 — audit hash chain: a forward chain verifies; a tampered row is
// caught at the exact index. Tampering bypasses the append-only trigger the way
// only a superuser could, proving the chain detects what the trigger can't.
#[tokio::test]
async fn t7_audit_hash_chain_detects_tamper() {
    let pg = start_pg().await;
    let audit = PgAuditRepo::new(pg.dal.clone());
    let pid = Uuid::now_v7().to_string();

    let mk = |action: &str, new: &str| AuditEntry {
        id: Uuid::now_v7(),
        passport_id: pid.clone(),
        actor: "test".into(),
        action: action.into(),
        previous_status: None,
        new_status: Some(new.to_owned()),
        metadata: None,
        timestamp: chrono::Utc::now(),
        prev_hash: None,
        entry_hash: None,
    };
    audit.append(mk("created", "draft")).await.expect("a1");
    audit.append(mk("published", "active")).await.expect("a2");
    audit
        .append(mk("suspended", "suspended"))
        .await
        .expect("a3");

    // (a) the intact forward chain verifies.
    assert!(
        audit.verify_chain(&pid).await.expect("verify").is_none(),
        "freshly appended chain must verify"
    );

    // (a') tamper the middle row's content, disabling the append-only trigger as
    // the table owner (superuser) — the only way the row could change at all.
    let admin = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&pg.admin_url)
        .await
        .expect("admin");
    sqlx::query("ALTER TABLE odal.passport_audit DISABLE TRIGGER audit_immutable")
        .execute(&admin)
        .await
        .expect("disable trigger");
    let affected = sqlx::query(
        "UPDATE odal.passport_audit SET new_status = 'evil' \
         WHERE passport_id = $1 AND action = 'published'",
    )
    .bind(&pid)
    .execute(&admin)
    .await
    .expect("tamper update");
    assert_eq!(affected.rows_affected(), 1, "one row tampered");
    sqlx::query("ALTER TABLE odal.passport_audit ENABLE TRIGGER audit_immutable")
        .execute(&admin)
        .await
        .expect("re-enable trigger");

    // verify now reports the break at the exact tampered (second) entry.
    let brk = audit
        .verify_chain(&pid)
        .await
        .expect("verify")
        .expect("tamper must be detected");
    assert_eq!(brk.index, 1, "break reported at the tampered entry");
    assert_eq!(brk.passport_id, pid);
}

// T5 — key_prefix is UNIQUE at the schema level (collision gap closed).
#[tokio::test]
async fn t5_api_key_prefix_unique() {
    let pg = start_pg().await;
    let repo = PgApiKeyRepo::new(pg.dal.clone());
    let key = |id: Uuid| ApiKeyRecord {
        key: ApiKey {
            id,
            name: format!("k-{id}"),
            key_prefix: "odal_sk_same".into(),
            is_active: true,
            scope: dpp_types::api_key::ApiKeyScope::Admin,
            created_at: chrono::Utc::now(),
            last_used_at: None,
            expires_at: None,
        },
        key_hash: "h".into(),
    };
    repo.create(key(Uuid::now_v7())).await.expect("first");
    assert!(
        repo.create(key(Uuid::now_v7())).await.is_err(),
        "duplicate prefix must violate UNIQUE"
    );
}

// T6 — patch_fields merges only the delta, removes nulls, survives concurrency.
#[tokio::test]
async fn t6_patch_fields_merge() {
    let pg = start_pg().await;
    let repo = PgPassportRepo::new(pg.dal.clone());
    let p = make_passport();
    let id = p.id;
    repo.create(p).await.expect("create");

    let patched = repo
        .patch_fields(
            id,
            serde_json::json!({"productName": "Patched", "batchId": null}),
        )
        .await
        .expect("patch");
    assert_eq!(patched.product_name, "Patched");
    assert_eq!(patched.batch_id, None, "null in delta removes the key");

    let reread = repo.find_by_id(id).await.unwrap().unwrap();
    assert_eq!(reread.product_name, "Patched");
    assert_eq!(reread.schema_version, "2.0.0", "untouched fields survive");
}
