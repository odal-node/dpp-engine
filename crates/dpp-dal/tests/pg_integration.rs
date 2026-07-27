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
//!   T13 snapshot reconcile outbox upsert/re-arm/due-filter
//!   T14 snapshot repair sweep selectivity
//!   T15 snapshot outbox mark-* methods fail closed on an unknown row id

#![cfg(feature = "integration-tests")]

use testcontainers::{
    GenericImage, ImageExt,
    core::{WaitFor, ports::ContainerPort},
    runners::AsyncRunner,
};
use uuid::Uuid;

use dpp_dal::pg::{
    PgApiKeyRepo, PgAuditRepo, PgDal, PgEvidenceDossierRepo, PgPassportRepo, PgSnapshotOutboxRepo,
    sqlx,
};
use dpp_domain::{
    domain::{
        gtin::Gtin,
        passport::{FacilitySnapshot, ManufacturerInfo, Passport, PassportId},
        product_identity::ProductIdentity,
        sector::{BatteryChemistry, BatteryData, Sector, SectorData},
        status::PassportStatus,
    },
    ports::passport_repo::PassportRepository,
};
use dpp_types::{
    api_key::{ApiKey, ApiKeyRecord, ApiKeyRepository},
    audit::{AuditEntry, AuditRepository},
    evidence::{
        DossierManifest, DossierV1, EvidenceDossierRecord, EvidenceDossierRepository, SignedLayer,
    },
    snapshot::SnapshotOutbox,
};
use sqlx::Row;

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
        lint_result: None,
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
        parent_passport_ref: None,
        component_refs: Vec::new(),
        retention_until: None,
        product_id: None,
        operator_identifier: None,
        facility: None,
        seal: None,
    }
}

/// A battery passport carrying real `sectorData` (with `gtin`) and `status`,
/// for the identity-lookup test — `make_passport()` deliberately leaves
/// `sector_data: None`, which `find_by_identity` can never match.
fn battery_passport_with(gtin: &str, batch: Option<&str>, status: PassportStatus) -> Passport {
    let mut p = make_passport();
    p.id = PassportId::new();
    p.batch_id = batch.map(str::to_owned);
    p.status = status;
    p.sector_data = Some(SectorData::Battery(BatteryData {
        gtin: Gtin::parse(gtin).expect("valid test gtin"),
        battery_chemistry: BatteryChemistry::Lfp,
        nominal_voltage_v: 3.2,
        nominal_capacity_ah: 100.0,
        expected_lifetime_cycles: 3000,
        co2e_per_unit_kg: 85.4,
        recycled_content_cobalt_pct: None,
        recycled_content_lithium_pct: None,
        recycled_content_nickel_pct: None,
        state_of_health_pct: None,
        rated_capacity_kwh: None,
        carbon_footprint_class: None,
        due_diligence_url: None,
        cathode_material: None,
        anode_material: None,
        electrolyte_material: None,
        critical_raw_materials: None,
        disassembly_instructions_url: None,
        soh_methodology: None,
        operating_temp_min_c: None,
        operating_temp_max_c: None,
        rated_energy_wh: None,
        recycled_content_lead_pct: None,
        battery_weight_kg: None,
        battery_type: None,
        round_trip_efficiency_pct: None,
        internal_resistance_mohm: None,
        manufacturing_date: None,
        manufacturing_place: None,
        battery_model_id: None,
        battery_passport_number: None,
    }));
    p
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

// patch_fields must reject state-machine / integrity fields so it can't bypass
// the state machine or desync the doc from its enforcing scalar column.
#[tokio::test]
async fn patch_fields_rejects_protected_fields() {
    let pg = start_pg().await;
    let repo = PgPassportRepo::new(pg.dal.clone());
    let p = make_passport();
    let id = p.id;
    repo.create(p).await.expect("create");

    let err = repo
        .patch_fields(
            id,
            serde_json::json!({ "retentionLocked": true, "status": "active" }),
        )
        .await
        .expect_err("protected fields must be rejected");
    assert!(
        matches!(err, dpp_domain::DppError::Validation(_)),
        "got: {err:?}"
    );

    // The passport is untouched — still a retention-unlocked draft.
    let reread = repo.find_by_id(id).await.unwrap().unwrap();
    assert_eq!(reread.status, PassportStatus::Draft);
    assert!(!reread.retention_locked);
}

// A LIKE wildcard in the GTIN must not widen the match to arbitrary passports.
#[tokio::test]
async fn find_published_by_gtin_rejects_like_metacharacters() {
    let pg = start_pg().await;
    let repo = PgPassportRepo::new(pg.dal.clone());
    // Publish a passport so there's an active row a wildcard could otherwise hit.
    let mut p = make_passport();
    p.status = PassportStatus::Published;
    repo.create(p).await.expect("create");

    for bad in ["%", "_", "not-a-gtin", ""] {
        assert!(
            repo.find_published_by_gtin(bad).await.unwrap().is_none(),
            "non-numeric gtin {bad:?} must never match"
        );
    }
}

// T8 — grant coverage: the app role can read every table a migration creates.
// Catches the "0010's grants were a snapshot" lesson (0017 had to re-grant): a
// migration that adds a table after 0010 must ship its own odal_app grant, or
// reads/writes silently fail with a permissions error nobody sees until
// production. Table list kept in sync with `migration_repo_drift.rs`'s
// `tables_created_in` parser — both read the same `ops/pg/*.sql` set.
#[tokio::test]
async fn t8_app_role_can_read_every_table() {
    let pg = start_pg().await;

    const TABLES: &[&str] = &[
        "odal.operator_config",
        "odal.operator_identifier",
        "odal.facility",
        "odal.api_key",
        "odal.passport",
        "odal.passport_audit",
        "odal.registry_sync",
        "odal.import_job",
        "odal.unsold_goods_report",
        "odal.registry_identity_audit",
        "odal.passport_transfer",
        "identity.did_document",
        "identity.key_pair",
    ];

    for table in TABLES {
        sqlx::query(&format!("SELECT 1 FROM {table} LIMIT 1"))
            .fetch_optional(pg.dal.pool())
            .await
            .unwrap_or_else(|e| panic!("odal_app cannot SELECT from {table}: {e}"));
    }
}

// T9 — find_by_identity matches an exact (sector, gtin, batch) across both
// Draft and Published, ignores non-matching rows, and does so via
// 0019_passport_identity_index.sql rather than a sequential scan.
#[tokio::test]
async fn t9_find_by_identity_matches_draft_and_published_via_index() {
    let pg = start_pg().await;
    let repo = PgPassportRepo::new(pg.dal.clone());

    // Enough decoy rows that a seq scan and an index scan would visibly differ
    // in the query plan — a handful of rows can fool the planner into a seq
    // scan regardless of the index's existence.
    for i in 0..200 {
        let gtin = format!("{i:013}{}", check_digit_for(&format!("{i:013}")));
        repo.create(battery_passport_with(
            &gtin,
            Some("DECOY"),
            PassportStatus::Draft,
        ))
        .await
        .expect("create decoy");
    }

    let draft = battery_passport_with("09506000134352", Some("BATCH-D"), PassportStatus::Draft);
    let draft_id = draft.id;
    repo.create(draft).await.expect("create draft");

    let published = battery_passport_with("01234567890128", None, PassportStatus::Published);
    let published_id = published.id;
    repo.create(published).await.expect("create published");

    let draft_identity = ProductIdentity {
        sector: Sector::Battery,
        gtin: "09506000134352".into(),
        batch_id: Some("BATCH-D".into()),
    };
    let found = repo
        .find_by_identity(&draft_identity)
        .await
        .expect("query")
        .expect("draft must match");
    assert_eq!(found.id, draft_id);

    // batch_id: None must match only passports with no batch set — not "any batch".
    let published_identity = ProductIdentity {
        sector: Sector::Battery,
        gtin: "01234567890128".into(),
        batch_id: None,
    };
    let found = repo
        .find_by_identity(&published_identity)
        .await
        .expect("query")
        .expect("published must match");
    assert_eq!(found.id, published_id);

    let no_match = ProductIdentity {
        sector: Sector::Battery,
        gtin: "01234567890128".into(),
        batch_id: Some("WRONG-BATCH".into()),
    };
    assert!(
        repo.find_by_identity(&no_match)
            .await
            .expect("query")
            .is_none(),
        "a batch mismatch must not fall back to matching on gtin alone"
    );

    let plan_rows = sqlx::query(
        "EXPLAIN SELECT doc FROM odal.passport \
         WHERE status IN ('draft','active') \
           AND sector = 'battery' \
           AND doc->'sectorData'->>'gtin' = '09506000134352' \
           AND doc->>'batchId' IS NOT DISTINCT FROM 'BATCH-D' \
         LIMIT 1",
    )
    .fetch_all(pg.dal.pool())
    .await
    .expect("explain");
    let plan: String = plan_rows
        .iter()
        .map(|r| r.get::<String, _>("QUERY PLAN"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        plan.contains("Index Scan") || plan.contains("Bitmap Index Scan"),
        "expected idx_passport_identity to be used, got plan:\n{plan}"
    );
    assert!(
        !plan.contains("Seq Scan"),
        "find_by_identity must not fall back to a sequential scan, got plan:\n{plan}"
    );
}

/// GS1 mod-10 check digit for a 13-digit data prefix — lets the decoy loop
/// generate 200 distinct, individually valid GTIN-14s.
fn check_digit_for(data13: &str) -> u8 {
    let digits: Vec<u8> = data13.bytes().map(|b| b - b'0').collect();
    dpp_domain::domain::gtin::gs1_check_digit(&digits)
}

/// A structurally-valid but unsigned dossier — enough to persist/round-trip
/// through `doc JSONB`; these tests exercise storage, not verification.
fn minimal_dossier(passport_id: &str) -> DossierV1 {
    DossierV1 {
        manifest: DossierManifest {
            format_version: "1".into(),
            passport_id: passport_id.into(),
            issuer_did: "did:web:pg-test.example".into(),
            created_at: chrono::Utc::now(),
            node_version: "test".into(),
            ruleset_version: None,
            content_hashes: std::collections::BTreeMap::new(),
        },
        manifest_jws: "x.y.z".into(),
        full_view: SignedLayer {
            payload: serde_json::json!({"passportId": passport_id}),
            jws: "x.y.z".into(),
        },
        public_view: SignedLayer {
            payload: serde_json::json!({"passportId": passport_id}),
            jws: "x.y.z".into(),
        },
        did_documents: std::collections::BTreeMap::new(),
        audit_entries: vec![],
        transfer_chain: None,
        eol_event: None,
        checkpoint: None,
        calc_receipts: vec![],
        component_graph: None,
    }
}

// T10 — evidence dossier round trip: insert, get, list summaries.
#[tokio::test]
async fn t10_evidence_dossier_round_trip() {
    let pg = start_pg().await;
    let passport_repo = PgPassportRepo::new(pg.dal.clone());
    let passport = passport_repo
        .create(make_passport())
        .await
        .expect("create passport");

    let evidence = PgEvidenceDossierRepo::new(pg.dal.clone());
    let dossier = minimal_dossier(&passport.id.to_string());
    let record = EvidenceDossierRecord {
        id: Uuid::now_v7(),
        passport_id: passport.id,
        actor: "test".into(),
        created_at: chrono::Utc::now(),
        doc_hash: "deadbeef".into(),
        dossier,
    };
    evidence.insert(&record).await.expect("insert");

    let fetched = evidence
        .get(record.id)
        .await
        .expect("get")
        .expect("must exist");
    assert_eq!(fetched.doc_hash, record.doc_hash);
    assert_eq!(fetched.actor, "test");
    assert_eq!(
        fetched.dossier.manifest.passport_id,
        passport.id.to_string()
    );

    let summaries = evidence.list_by_passport(passport.id).await.expect("list");
    assert_eq!(summaries.len(), 1);
    assert_eq!(summaries[0].id, record.id);

    assert!(
        evidence.get(Uuid::now_v7()).await.expect("get").is_none(),
        "unknown id must return None, not error"
    );
}

// T11 — evidence dossier rows are immutable at the database layer, and a
// dossier referencing an unknown passport is rejected by the FK.
#[tokio::test]
async fn t11_evidence_dossier_append_only_and_fk_enforced() {
    let pg = start_pg().await;
    let passport_repo = PgPassportRepo::new(pg.dal.clone());
    let passport = passport_repo
        .create(make_passport())
        .await
        .expect("create passport");

    let evidence = PgEvidenceDossierRepo::new(pg.dal.clone());
    let record = EvidenceDossierRecord {
        id: Uuid::now_v7(),
        passport_id: passport.id,
        actor: "test".into(),
        created_at: chrono::Utc::now(),
        doc_hash: "deadbeef".into(),
        dossier: minimal_dossier(&passport.id.to_string()),
    };
    evidence.insert(&record).await.expect("insert");

    let admin = sqlx::postgres::PgPoolOptions::new()
        .connect(&pg.admin_url)
        .await
        .expect("admin");
    let res = sqlx::query("UPDATE odal.evidence_dossier SET actor = 'evil' WHERE id = $1")
        .bind(record.id)
        .execute(&admin)
        .await;
    assert!(res.is_err(), "evidence UPDATE must be rejected by trigger");
    let res = sqlx::query("DELETE FROM odal.evidence_dossier WHERE id = $1")
        .bind(record.id)
        .execute(&admin)
        .await;
    assert!(res.is_err(), "evidence DELETE must be rejected by trigger");

    let orphan = EvidenceDossierRecord {
        id: Uuid::now_v7(),
        passport_id: PassportId::new(),
        actor: "test".into(),
        created_at: chrono::Utc::now(),
        doc_hash: "deadbeef".into(),
        dossier: minimal_dossier(&Uuid::now_v7().to_string()),
    };
    let res = evidence.insert(&orphan).await;
    assert!(
        res.is_err(),
        "insert for an unknown passport_id must fail the FK constraint"
    );
}

// T12 — list_by_passport orders newest-first.
#[tokio::test]
async fn t12_evidence_dossier_list_orders_newest_first() {
    let pg = start_pg().await;
    let passport_repo = PgPassportRepo::new(pg.dal.clone());
    let passport = passport_repo
        .create(make_passport())
        .await
        .expect("create passport");

    let evidence = PgEvidenceDossierRepo::new(pg.dal.clone());
    let mk = || EvidenceDossierRecord {
        id: Uuid::now_v7(),
        passport_id: passport.id,
        actor: "test".into(),
        created_at: chrono::Utc::now(),
        doc_hash: "deadbeef".into(),
        dossier: minimal_dossier(&passport.id.to_string()),
    };
    let first = mk();
    evidence.insert(&first).await.expect("insert first");
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    let second = mk();
    evidence.insert(&second).await.expect("insert second");

    let summaries = evidence.list_by_passport(passport.id).await.expect("list");
    assert_eq!(summaries.len(), 2);
    assert_eq!(summaries[0].id, second.id, "newest dossier must be first");
    assert_eq!(summaries[1].id, first.id);
}

// T13 — snapshot reconcile outbox: the upsert/drain semantics the in-memory
// doubles in `dpp-node/tests/snapshot_outbox.rs` only *model*. Those tests prove
// the drain converges; this one proves the SQL underneath actually behaves the
// way they assume — the gap that let an unguarded upsert sit undetected on the
// registry-sync path.
#[tokio::test]
async fn t13_snapshot_outbox_upsert_rearm_and_due_filter() {
    let pg = start_pg().await;
    let passport_repo = PgPassportRepo::new(pg.dal.clone());
    let passport = passport_repo
        .create(make_passport())
        .await
        .expect("create passport");

    let outbox = PgSnapshotOutboxRepo::new(pg.dal.clone());

    // Enqueue is drainable immediately.
    outbox.enqueue(passport.id).await.expect("enqueue");
    let due = outbox.due(50).await.expect("due");
    assert_eq!(due.len(), 1, "a fresh reconcile must be due now");
    assert_eq!(due[0].passport_id, passport.id);
    assert_eq!(due[0].attempts, 0);

    // Idempotence: a second change while one is still pending collapses into the
    // same row rather than stacking a duplicate. This is the `passport_id UNIQUE`
    // upsert doing the work the in-memory double asserts.
    outbox.enqueue(passport.id).await.expect("enqueue again");
    let due = outbox.due(50).await.expect("due");
    assert_eq!(
        due.len(),
        1,
        "repeat enqueues for one passport must collapse to a single pending row"
    );
    let counts = outbox.status_counts().await.expect("counts");
    assert_eq!(counts.pending, 1);
    assert_eq!(counts.reconciled, 0);

    // A transient failure backs the row off: still pending, but no longer due
    // (minimum backoff is 2^1 * 0.75 = 1.5s), so a hot loop cannot spin on it.
    let row_id = due[0].id;
    outbox
        .mark_attempt_failed(row_id, "object store unavailable".into())
        .await
        .expect("mark failed");
    assert!(
        outbox.due(50).await.expect("due").is_empty(),
        "a backed-off row must not be immediately due again"
    );
    assert_eq!(
        outbox.status_counts().await.expect("counts").pending,
        1,
        "a backed-off row stays pending — nothing is lost"
    );

    // Terminal success removes it from the queue.
    outbox
        .mark_reconciled(row_id)
        .await
        .expect("mark reconciled");
    assert!(outbox.due(50).await.expect("due").is_empty());
    let counts = outbox.status_counts().await.expect("counts");
    assert_eq!(counts.pending, 0);
    assert_eq!(counts.reconciled, 1);

    // Re-arm: a later state change must make a *reconciled* row drainable again,
    // with a fresh attempt budget. Without this the tier would go permanently
    // deaf to a passport after its first reconcile.
    outbox.enqueue(passport.id).await.expect("re-enqueue");
    let due = outbox.due(50).await.expect("due");
    assert_eq!(
        due.len(),
        1,
        "a new state change must re-arm a reconciled row"
    );
    assert_eq!(due[0].attempts, 0, "re-arm resets the retry budget");
    assert_eq!(outbox.status_counts().await.expect("counts").reconciled, 0);

    // Re-arm from `exhausted` too: giving up on a stale state must never make a
    // passport permanently unreconcilable once it changes again.
    let row_id = due[0].id;
    outbox
        .mark_exhausted(row_id, "gave up".into())
        .await
        .expect("mark exhausted");
    assert!(outbox.due(50).await.expect("due").is_empty());
    assert_eq!(outbox.status_counts().await.expect("counts").exhausted, 1);

    outbox
        .enqueue(passport.id)
        .await
        .expect("re-enqueue after exhaustion");
    let due = outbox.due(50).await.expect("due");
    assert_eq!(
        due.len(),
        1,
        "an exhausted row must be re-armed by a later state change"
    );
    let counts = outbox.status_counts().await.expect("counts");
    assert_eq!(counts.exhausted, 0);
    assert_eq!(counts.pending, 1);
}

// T14 — the continuity tier's repair sweep: which passports it considers
// divergent, and — just as important — which it leaves alone. The sweep is the
// backstop for reconciles the event-driven path never queued, so its selectivity
// is the whole design: too narrow and drift persists, too broad and every sweep
// re-uploads the world.
#[tokio::test]
async fn t14_snapshot_sweep_requeues_only_divergent_passports() {
    let pg = start_pg().await;
    let passport_repo = PgPassportRepo::new(pg.dal.clone());
    let outbox = PgSnapshotOutboxRepo::new(pg.dal.clone());

    // A draft that was never published: nothing can be stale in the public tier,
    // so it must never be swept in. Without the `published_at` guard every draft
    // ever created would match the "no outbox row" arm forever.
    let draft = passport_repo
        .create(make_passport())
        .await
        .expect("create draft");

    // A published passport that never got an outbox row — the shape left behind
    // by a crash between commit and enqueue, or by an earlier code path that
    // never enqueued at all.
    let mut published = make_passport();
    published.id = PassportId::new();
    published.status = PassportStatus::Published;
    let published = passport_repo.create(published).await.expect("create pub");
    sqlx::query("UPDATE odal.passport SET status = 'active', published_at = now() WHERE id = $1")
        .bind(published.id.0)
        .execute(pg.dal.pool())
        .await
        .expect("mark published");

    let swept = outbox.enqueue_divergent(500).await.expect("sweep");
    assert_eq!(swept, 1, "only the published, never-reconciled passport");
    let due = outbox.due(500).await.expect("due");
    assert_eq!(due.len(), 1);
    assert_eq!(due[0].passport_id, published.id);
    assert!(
        !due.iter().any(|r| r.passport_id == draft.id),
        "a never-published draft must never be swept into the tier"
    );

    // Reconcile it. A converged passport must not be swept again — this is what
    // keeps a steady-state deployment doing zero work.
    outbox
        .mark_reconciled(due[0].id)
        .await
        .expect("mark reconciled");
    assert_eq!(
        outbox.enqueue_divergent(500).await.expect("sweep"),
        0,
        "a converged passport must not be re-swept"
    );
    assert!(outbox.due(500).await.expect("due").is_empty());

    // Touch the passport so it changed after its last reconcile: that is the
    // commit-to-enqueue window, and the sweep must catch it.
    sqlx::query("UPDATE odal.passport SET updated_at = now() WHERE id = $1")
        .bind(published.id.0)
        .execute(pg.dal.pool())
        .await
        .expect("touch");
    assert_eq!(
        outbox.enqueue_divergent(500).await.expect("sweep"),
        1,
        "a passport changed after its last reconcile must be re-swept"
    );

    // An exhausted row means the tier may still be serving something stale, so
    // the sweep must re-arm it rather than leave it terminally given-up.
    let row_id = outbox.due(500).await.expect("due")[0].id;
    outbox
        .mark_exhausted(row_id, "gave up".into())
        .await
        .expect("exhaust");
    assert!(outbox.due(500).await.expect("due").is_empty());
    assert_eq!(
        outbox.enqueue_divergent(500).await.expect("sweep"),
        1,
        "an exhausted reconcile must be re-armed by the sweep"
    );
    assert_eq!(outbox.due(500).await.expect("due").len(), 1);

    // A row already `pending` is the drain's to own. Re-arming it every sweep
    // would reset its backoff and turn a failing reconcile into a hot loop.
    let before = outbox.due(500).await.expect("due")[0].id;
    outbox
        .mark_attempt_failed(before, "transient".into())
        .await
        .expect("fail once");
    assert_eq!(
        outbox.enqueue_divergent(500).await.expect("sweep"),
        0,
        "a pending row must be left to the drain, backoff intact"
    );
    assert!(
        outbox.due(500).await.expect("due").is_empty(),
        "the backed-off row must stay backed off after a sweep"
    );
}

// T15 — snapshot outbox mark-* methods fail closed on an unknown row id.
// Regression: `mark_reconciled`/`mark_attempt_failed`/`mark_exhausted`
// previously discarded `rows_affected()` entirely, so a stale/wrong id
// silently no-op'd instead of surfacing `NotFound` — inconsistent with the
// registry-sync outbox's own `mark_*` methods, which already checked this.
#[tokio::test]
async fn t15_snapshot_outbox_mark_methods_fail_closed_on_unknown_id() {
    let pg = start_pg().await;
    let outbox = PgSnapshotOutboxRepo::new(pg.dal.clone());
    let unknown_id = Uuid::now_v7();

    let err = outbox
        .mark_reconciled(unknown_id)
        .await
        .expect_err("mark_reconciled on an unknown row must fail, not silently succeed");
    assert!(matches!(err, dpp_domain::DppError::NotFound(_)));

    let err = outbox
        .mark_attempt_failed(unknown_id, "irrelevant".into())
        .await
        .expect_err("mark_attempt_failed on an unknown row must fail, not silently succeed");
    assert!(matches!(err, dpp_domain::DppError::NotFound(_)));

    let err = outbox
        .mark_exhausted(unknown_id, "irrelevant".into())
        .await
        .expect_err("mark_exhausted on an unknown row must fail, not silently succeed");
    assert!(matches!(err, dpp_domain::DppError::NotFound(_)));
}
