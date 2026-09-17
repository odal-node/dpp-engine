//! Postgres-backed tests for the successor lookup.
//!
//! ✅ COMPLIANCE-PIN: ESPR Art. 9(1) — a data carrier links to *the* passport for
//! its product. The carrier is printed once, so the lookup that keeps it landing
//! on the current record is load-bearing for the life of the product.
//!
//! Three claims, and the middle one is the reason this is a Postgres test rather
//! than a unit test: it is about a `WHERE` clause.

#![cfg(feature = "integration-tests")]

use chrono::Utc;

use dpp_dal::pg::{PgPassportRepo, PgSuccessorRepo};
use dpp_dal::test_harness::start_pg;
use dpp_domain::passport::{ManufacturerInfo, Passport, PassportId};
use dpp_domain::ports::passport_repo::PassportRepository;
use dpp_domain::product_group::ProductGroup;
use dpp_domain::status::PassportStatus;
use dpp_types::successor::SuccessorLookup;

fn passport(status: PassportStatus, supersedes: Option<PassportId>) -> Passport {
    Passport {
        id: PassportId::new(),
        batch_id: None,
        serial_number: None,
        product_name: "Carrier Test Battery".into(),
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
        supersedes_id: supersedes,
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
    }
}

/// The published record that names a passport as its predecessor is the answer.
#[tokio::test]
async fn the_published_successor_is_found_by_what_it_supersedes() {
    let pg = start_pg().await;
    let repo = PgPassportRepo::new(pg.dal.clone());
    let successors = PgSuccessorRepo::new(pg.dal.clone());

    let old = repo
        .create(passport(PassportStatus::Superseded, None))
        .await
        .expect("create predecessor");
    let new = repo
        .create(passport(PassportStatus::Published, Some(old.id)))
        .await
        .expect("create successor");

    let found = successors
        .successor_of(old.id)
        .await
        .expect("lookup")
        .expect("the successor is published and names this passport");
    assert_eq!(found.id, new.id);
    assert_eq!(found.supersedes_id, Some(old.id));
}

/// 🚨 A successor that has not been published yet is **not** an answer.
///
/// This is the `status = 'active'` filter, and it is not an optimisation. The
/// public read sends a scanned carrier to whatever this returns, and an
/// unpublished passport has no public view — so answering with one would move
/// the `404` a step further along and make the carrier fail in a way that looks
/// like the successor is broken rather than unfinished.
///
/// Until it publishes, the predecessor's own frozen view is the best thing there
/// is, and returning `None` is what leaves the route serving it.
#[tokio::test]
async fn a_successor_that_is_not_published_yet_is_not_served_to_a_carrier() {
    let pg = start_pg().await;
    let repo = PgPassportRepo::new(pg.dal.clone());
    let successors = PgSuccessorRepo::new(pg.dal.clone());

    let old = repo
        .create(passport(PassportStatus::Superseded, None))
        .await
        .expect("create predecessor");
    repo.create(passport(PassportStatus::Draft, Some(old.id)))
        .await
        .expect("create an unpublished successor");

    assert!(
        successors
            .successor_of(old.id)
            .await
            .expect("lookup")
            .is_none(),
        "a draft successor has no public view, so it is not somewhere to send a scan"
    );
}

/// A passport nothing replaced has no successor, and that is not an error.
///
/// The ordinary state for a passport retired at end of life or at the end of its
/// retention: there is no replacement, and the route keeps serving the record
/// itself rather than failing.
#[tokio::test]
async fn a_passport_nothing_replaced_has_no_successor() {
    let pg = start_pg().await;
    let repo = PgPassportRepo::new(pg.dal.clone());
    let successors = PgSuccessorRepo::new(pg.dal.clone());

    let lonely = repo
        .create(passport(PassportStatus::Archived, None))
        .await
        .expect("create");

    assert!(
        successors
            .successor_of(lonely.id)
            .await
            .expect("lookup")
            .is_none()
    );
}

/// 🚨 A product amended twice still resolves, and this is the case a single hop
/// misses.
///
/// `A → B → C`: by the time `C` exists, `B` is itself `superseded`. A lookup
/// that asked only for the **active** row naming `A` would find nothing — `B` is
/// not active — and `A`'s printed carrier would go back to serving `A`. That is
/// the original defect one amendment further along, and the reason the walk
/// follows the chain rather than taking one step.
#[tokio::test]
async fn a_twice_amended_passport_resolves_all_the_way_to_the_live_record() {
    let pg = start_pg().await;
    let repo = PgPassportRepo::new(pg.dal.clone());
    let successors = PgSuccessorRepo::new(pg.dal.clone());

    let a = repo
        .create(passport(PassportStatus::Superseded, None))
        .await
        .expect("create A");
    let b = repo
        .create(passport(PassportStatus::Superseded, Some(a.id)))
        .await
        .expect("create B");
    let c = repo
        .create(passport(PassportStatus::Published, Some(b.id)))
        .await
        .expect("create C");

    assert_eq!(
        successors
            .successor_of(a.id)
            .await
            .expect("lookup")
            .expect("the chain reaches a published record")
            .id,
        c.id,
        "a carrier printed for A lands on C, not on B and not on nothing"
    );
    assert_eq!(
        successors
            .successor_of(b.id)
            .await
            .expect("lookup")
            .expect("one hop from C")
            .id,
        c.id,
        "and B's own carrier lands there too"
    );
}

/// A chain that reaches no published record answers `None`.
///
/// `A → B`, both retired, nothing live. The walk runs out rather than returning
/// the unpublished link — which has no public view, so sending a scan there
/// would move the `404` one step along.
#[tokio::test]
async fn a_chain_that_reaches_nothing_published_answers_none() {
    let pg = start_pg().await;
    let repo = PgPassportRepo::new(pg.dal.clone());
    let successors = PgSuccessorRepo::new(pg.dal.clone());

    let a = repo
        .create(passport(PassportStatus::Superseded, None))
        .await
        .expect("create A");
    repo.create(passport(PassportStatus::Superseded, Some(a.id)))
        .await
        .expect("create B");

    assert!(
        successors
            .successor_of(a.id)
            .await
            .expect("lookup")
            .is_none(),
        "nothing published on this chain, so the caller keeps serving A's own view"
    );
}

/// 🚨 A cycle does not hang the public read.
///
/// Two rows naming each other is not a state the write paths produce, but this
/// runs inside an **unauthenticated** route and a walk with no bound is a walk
/// somebody can make spin. The cap ends it and the caller serves the record that
/// was asked for.
#[tokio::test]
async fn a_cycle_in_the_chain_ends_at_the_hop_cap() {
    let pg = start_pg().await;
    let repo = PgPassportRepo::new(pg.dal.clone());
    let successors = PgSuccessorRepo::new(pg.dal.clone());

    let a = repo
        .create(passport(PassportStatus::Superseded, None))
        .await
        .expect("create A");
    let b = repo
        .create(passport(PassportStatus::Superseded, Some(a.id)))
        .await
        .expect("create B");

    // Point A back at B, so the walk loops. Written directly because no write
    // path will build this.
    sqlx::query("UPDATE odal.passport SET supersedes_id = $2 WHERE id = $1")
        .bind(a.id.0)
        .bind(b.id.0)
        .execute(pg.dal.pool())
        .await
        .expect("close the cycle");

    assert!(
        successors
            .successor_of(a.id)
            .await
            .expect("the walk must end, not hang")
            .is_none(),
        "a cycle reaches no published record, so the caller serves what it was asked for"
    );
}

/// Two successors sharing a `published_at` resolve to the same one every time.
///
/// Nothing in the schema stops two active rows sharing a `supersedes_id` — two
/// concurrent amendments can each read the predecessor as published, mint a
/// successor, and retire it afterwards. With `published_at` tied and no
/// tie-breaker the answer is whatever the planner chose, so a carrier could land
/// on a different passport between two scans. `id DESC` makes the choice
/// arbitrary but stable, which is the part that matters.
#[tokio::test]
async fn two_successors_with_the_same_publish_time_resolve_the_same_way_every_time() {
    let pg = start_pg().await;
    let repo = PgPassportRepo::new(pg.dal.clone());
    let successors = PgSuccessorRepo::new(pg.dal.clone());

    let a = repo
        .create(passport(PassportStatus::Superseded, None))
        .await
        .expect("create A");
    let one = repo
        .create(passport(PassportStatus::Published, Some(a.id)))
        .await
        .expect("create one successor");
    let two = repo
        .create(passport(PassportStatus::Published, Some(a.id)))
        .await
        .expect("create another");

    let at = Utc::now();
    for id in [one.id, two.id] {
        sqlx::query("UPDATE odal.passport SET published_at = $2 WHERE id = $1")
            .bind(id.0)
            .bind(at)
            .execute(pg.dal.pool())
            .await
            .expect("tie the publish times");
    }

    let expected = std::cmp::max(one.id.0, two.id.0);
    for _ in 0..5 {
        assert_eq!(
            successors
                .successor_of(a.id)
                .await
                .expect("lookup")
                .expect("one of them is published")
                .id
                .0,
            expected,
            "the tie resolves to the higher id, and to the same one on every read"
        );
    }
}
