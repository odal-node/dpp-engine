//! The Postgres repositories under every request, against a real server.
//!
//! The vault reads or writes a passport, appends an audit entry and looks an API
//! key up on nearly every call, so these are the floor under each route's latency.
//! The in-memory benches cannot see them: what a query costs depends on its plan,
//! and a plan changes with the migrations, the indexes and the table's size.
//!
//! `list`, `count` and `find_by_identity` therefore run at 100, 1,000 and 10,000
//! passports, in one database that grows between sizes. The point operations (an
//! insert, a primary-key read) do not depend on the table's size and run once.
//!
//! Every passport here is the same product, one GTIN, and differs only in its
//! batch: one model with many lots. That is the shape a lookup by identity finds
//! hardest, since the index is keyed by product first. A node holding many products
//! with a few lots each is a different table, and these figures are not its.
//!
//! Needs Docker. With `ODAL_TEST_PG_ADMIN_URL` set the shared harness clones a
//! database on that server; unset, it starts a `postgres:17` container of its own.
//! Run with:
//! ```sh
//! just bench-infra
//! cargo bench -p dpp-dal --features integration-tests --bench pg_repo
//! ```

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use criterion::{BatchSize, BenchmarkId, Criterion, criterion_group, criterion_main};
use dpp_dal::pg::{PgApiKeyRepo, PgAuditRepo, PgPassportRepo};
use dpp_dal::test_harness::start_pg;
use dpp_domain::{
    passport::{Passport, PassportId},
    ports::passport_repo::PassportRepository,
    product::ProductIdentity,
    status::PassportStatus,
};
use dpp_types::{
    api_key::{ApiKey, ApiKeyRecord, ApiKeyRepository, ApiKeyScope},
    audit::{AuditRepository, PassportAuditEntry},
};
use tokio::runtime::Runtime;
use tokio::task::JoinSet;
use uuid::Uuid;

/// A real published battery passport, the one the stored-document guard freezes.
/// Read from there rather than restated, so the bench stores what a node stores.
const DOC: &str = include_str!("../tests/fixtures/passport_docs/battery/v2.8.0.json");

const SIZES: [u64; 3] = [100, 1_000, 10_000];

/// Inserts in flight while a table is grown; the timed operations run one at a time.
const SEED_CONCURRENCY: usize = 16;

/// API keys in the table the lookup runs against.
const API_KEYS: u64 = 100;

static NEXT: AtomicU64 = AtomicU64::new(0);

fn fixture() -> Passport {
    serde_json::from_str(DOC).expect("the frozen document reads as a current passport")
}

/// A draft that differs from every other in its id and batch, so none collides with
/// another on identity.
fn draft() -> Passport {
    let mut p = fixture();
    p.id = PassportId::new();
    p.batch_id = Some(format!("LOT-{:08}", NEXT.fetch_add(1, Ordering::Relaxed)));
    p.status = PassportStatus::Draft;
    p.retention_locked = false;
    p.published_at = None;
    p.qr_code_url = None;
    p.jws_signature = None;
    p.public_jws_signature = None;
    p.disclosure_signatures = Default::default();
    p
}

/// The frozen document as stored: published, signed and retention-locked.
fn published_doc() -> Passport {
    let mut p = fixture();
    p.id = PassportId::new();
    p.batch_id = Some(format!("LOT-{:08}", NEXT.fetch_add(1, Ordering::Relaxed)));
    p
}

/// Insert drafts until the table holds `want` rows, `SEED_CONCURRENCY` at a time.
async fn grow(repo: &Arc<PgPassportRepo>, have: &mut u64, want: u64) {
    let mut inserts = JoinSet::new();
    while *have < want {
        while inserts.len() < SEED_CONCURRENCY && *have < want {
            let repo = Arc::clone(repo);
            inserts.spawn(async move { repo.create(draft()).await.expect("seed a passport") });
            *have += 1;
        }
        inserts.join_next().await;
    }
    while inserts.join_next().await.is_some() {}
}

fn audit_entry(passport_id: &str) -> PassportAuditEntry {
    PassportAuditEntry {
        id: Uuid::now_v7(),
        passport_id: passport_id.to_owned(),
        actor: "bench".into(),
        action: "updated".into(),
        previous_status: Some("draft".into()),
        new_status: Some("draft".into()),
        metadata: None,
        timestamp: chrono::Utc::now(),
        request_id: None,
        prev_hash: None,
        entry_hash: None,
    }
}

fn api_key(n: u64) -> ApiKeyRecord {
    ApiKeyRecord {
        key: ApiKey {
            id: Uuid::now_v7(),
            name: format!("bench-{n}"),
            key_prefix: format!("odal_sk_{n:08}"),
            is_active: true,
            scope: ApiKeyScope::Admin,
            created_at: chrono::Utc::now(),
            last_used_at: None,
            expires_at: None,
        },
        key_hash: "0".repeat(64),
    }
}

fn pg_repo(c: &mut Criterion) {
    let rt = Runtime::new().expect("a tokio runtime");
    let pg = rt.block_on(start_pg());
    let passports = Arc::new(PgPassportRepo::new(pg.dal.clone()));
    let audit = PgAuditRepo::new(pg.dal.clone());
    let keys = PgApiKeyRepo::new(pg.dal.clone());

    // --- Sweeps over table size -------------------------------------------------
    //
    // These come first: the point operations below insert thousands of rows while
    // they are measured, which would move every size after them.
    //
    // A benchmark that times a refusal or an empty page still prints a figure, so
    // each fixture is checked to reach the path it is named for.

    let mut have = 0;
    for size in SIZES {
        rt.block_on(grow(&passports, &mut have, size));

        // The row last inserted is the one a sequential scan reaches last, so a
        // lookup for it is the case a missing index makes slow.
        let probe = rt
            .block_on(passports.create(draft()))
            .expect("store the probe");
        have += 1;
        let hit = ProductIdentity::from_passport(&probe).expect("a battery has an identity");
        let mut miss = hit.clone();
        miss.batch_id = Some("LOT-NO-SUCH-BATCH".into());

        let found = rt
            .block_on(passports.find_by_identity(&hit))
            .expect("look up");
        assert_eq!(found.map(|p| p.id), Some(probe.id), "the probe is found");
        assert!(
            rt.block_on(passports.find_by_identity(&miss))
                .expect("look up")
                .is_none(),
            "an unknown batch is not found"
        );
        assert_eq!(
            rt.block_on(passports.count(None, None)).expect("count"),
            have,
            "the table holds what was inserted"
        );
        let page = rt
            .block_on(passports.list(None, None, None, 20, 0))
            .expect("list");
        assert_eq!(page.len(), 20, "a full page");

        let mut list = c.benchmark_group("pg_passport_list");
        list.bench_with_input(BenchmarkId::new("first_page", size), &size, |b, _| {
            b.iter(|| {
                rt.block_on(passports.list(None, None, None, 20, 0))
                    .expect("list")
            });
        });
        list.bench_with_input(BenchmarkId::new("draft_page", size), &size, |b, _| {
            b.iter(|| {
                rt.block_on(passports.list(Some(PassportStatus::Draft), None, None, 20, 0))
                    .expect("list")
            });
        });
        // The offset the last page of the table sits at.
        list.bench_with_input(BenchmarkId::new("last_page", size), &size, |b, _| {
            let offset = (have - 20) as u32;
            b.iter(|| {
                rt.block_on(passports.list(None, None, None, 20, offset))
                    .expect("list")
            });
        });
        // A search that matches nothing reads every row.
        list.bench_with_input(BenchmarkId::new("search_miss", size), &size, |b, _| {
            b.iter(|| {
                rt.block_on(passports.list(None, Some("no-such-product"), None, 20, 0))
                    .expect("list")
            });
        });
        list.finish();

        let mut count = c.benchmark_group("pg_passport_count");
        count.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, _| {
            b.iter(|| rt.block_on(passports.count(None, None)).expect("count"));
        });
        count.finish();

        let mut identity = c.benchmark_group("pg_passport_find_by_identity");
        identity.bench_with_input(BenchmarkId::new("hit", size), &size, |b, _| {
            b.iter(|| {
                rt.block_on(passports.find_by_identity(&hit))
                    .expect("look up")
            });
        });
        identity.bench_with_input(BenchmarkId::new("miss", size), &size, |b, _| {
            b.iter(|| {
                rt.block_on(passports.find_by_identity(&miss))
                    .expect("look up")
            });
        });
        identity.finish();
    }

    // --- Point operations -------------------------------------------------------

    let published = rt
        .block_on(passports.create(published_doc()))
        .expect("store a published passport");
    assert!(
        rt.block_on(passports.find_published_by_id(published.id))
            .expect("read it back")
            .is_some(),
        "the published passport is found as published"
    );
    let stored = rt
        .block_on(passports.create(draft()))
        .expect("store a draft");

    let mut point = c.benchmark_group("pg_passport");
    point.bench_function("create", |b| {
        b.iter_batched(
            draft,
            |p| rt.block_on(passports.create(p)).expect("create"),
            BatchSize::SmallInput,
        );
    });
    point.bench_function("find_by_id", |b| {
        b.iter(|| rt.block_on(passports.find_by_id(stored.id)).expect("read"));
    });
    point.bench_function("find_published_by_id", |b| {
        b.iter(|| {
            rt.block_on(passports.find_published_by_id(published.id))
                .expect("read")
        });
    });
    point.bench_function("update", |b| {
        b.iter_batched(
            || {
                let mut p = stored.clone();
                p.product_name = format!("GridCell {}", NEXT.fetch_add(1, Ordering::Relaxed));
                p
            },
            |p| rt.block_on(passports.update(p)).expect("update"),
            BatchSize::SmallInput,
        );
    });
    point.finish();

    // --- Audit trail ------------------------------------------------------------

    // Each entry is chained to the one before it, so an append reads the chain's
    // head before it writes. One passport's chain grows; a new passport starts one.
    let chained = Uuid::now_v7().to_string();
    rt.block_on(audit.append(audit_entry(&chained)))
        .expect("start the chain");
    let mut trail = c.benchmark_group("pg_audit");
    trail.bench_function("append_to_chain", |b| {
        b.iter_batched(
            || audit_entry(&chained),
            |e| rt.block_on(audit.append(e)).expect("append"),
            BatchSize::SmallInput,
        );
    });
    trail.bench_function("append_first_entry", |b| {
        b.iter_batched(
            || audit_entry(&Uuid::now_v7().to_string()),
            |e| rt.block_on(audit.append(e)).expect("append"),
            BatchSize::SmallInput,
        );
    });
    trail.finish();

    // --- API key lookup ---------------------------------------------------------

    // Every authenticated request starts with this read.
    for n in 0..API_KEYS {
        rt.block_on(keys.create(api_key(n))).expect("seed a key");
    }
    let present = format!("odal_sk_{:08}", API_KEYS / 2);
    assert!(
        rt.block_on(keys.find_active_by_prefix(&present))
            .expect("look up")
            .is_some(),
        "a seeded key is found"
    );
    assert!(
        rt.block_on(keys.find_active_by_prefix("odal_sk_unknown0"))
            .expect("look up")
            .is_none(),
        "an unknown prefix is not found"
    );
    let mut lookup = c.benchmark_group("pg_api_key");
    lookup.bench_function("find_active_by_prefix_hit", |b| {
        b.iter(|| {
            rt.block_on(keys.find_active_by_prefix(&present))
                .expect("look up")
        });
    });
    lookup.bench_function("find_active_by_prefix_miss", |b| {
        b.iter(|| {
            rt.block_on(keys.find_active_by_prefix("odal_sk_unknown0"))
                .expect("look up")
        });
    });
    lookup.finish();

    // Dropped inside the runtime: stopping a container needs a reactor.
    rt.block_on(async move { drop(pg) });
}

criterion_group!(benches, pg_repo);
criterion_main!(benches);
