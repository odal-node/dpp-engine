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
