#![cfg(feature = "integration-tests")]
//! Discard records and evidence files in PostgreSQL (`ops/pg/0051`, `0052`).
//!
//! These run against a real database, as the app role unless a test says
//! otherwise. The append-only guarantees are proved twice: the app role's grants
//! refuse a DELETE, and the superuser is refused by the trigger, which is the
//! guarantee that holds even where a grant is later widened by mistake.

use chrono::NaiveDate;
use dpp_dal::pg::{PgDiscardRecordRepo, PgEvidenceFileRepo};
use dpp_dal::test_harness::start_pg;
use dpp_domain::{
    DppError,
    unsold_goods::{DiscardRecord, EvidenceKind, FinancialYear},
};
use dpp_types::{DiscardRecordStore, EvidenceStore};
use uuid::Uuid;

/// A discard on `day`, in the shape core's discard-record schema admits.
fn record_on(day: &str) -> DiscardRecord {
    serde_json::from_value(serde_json::json!({
        "discardedOn": day,
        "cnCodes": ["420300"],
        "description": "Jackets, unsold season stock",
        "units": { "value": 1240 },
        "weight": { "grams": 860500 },
        "packagingIncluded": false,
        "treatment": "recycling",
        "receiver": { "name": "Nord Recycling GmbH" }
    }))
    .expect("the fixture record reads")
}

/// A passport row this node holds, for a discard to name.
async fn held_passport(dal: &dpp_dal::pg::PgDal) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO odal.passport (id, product_group, schema_version, doc)
         VALUES ($1, 'textile', '1.0.0', '{}'::jsonb)",
    )
    .bind(id)
    .execute(dal.pool())
    .await
    .expect("a passport row");
    id
}

fn year(start: &str, end: &str) -> FinancialYear {
    FinancialYear {
        start: NaiveDate::parse_from_str(start, "%Y-%m-%d").expect("a date"),
        end: NaiveDate::parse_from_str(end, "%Y-%m-%d").expect("a date"),
    }
}

#[tokio::test]
async fn a_record_reads_back_with_its_passports_and_schema_version() {
    let pg = start_pg().await;
    let repo = PgDiscardRecordRepo::new(pg.dal.clone());
    let passport = held_passport(&pg.dal).await;

    let stored = repo
        .create(&record_on("2026-08-01"), "1.0.0", &[passport])
        .await
        .expect("a discard naming a held passport is stored");

    let read = repo
        .get(stored.id)
        .await
        .expect("a read")
        .expect("the stored record is found");
    assert_eq!(read.schema_version, "1.0.0");
    assert_eq!(read.passport_ids, vec![passport]);
    assert_eq!(read.record, record_on("2026-08-01"));
}

/// The year is inclusive at both ends, so a discard on its first or last day is
/// in it, and one the day after its end is not.
#[tokio::test]
async fn a_year_lists_the_discards_on_its_first_and_last_days() {
    let pg = start_pg().await;
    let repo = PgDiscardRecordRepo::new(pg.dal.clone());
    for day in [
        "2025-12-31",
        "2026-01-01",
        "2026-06-15",
        "2026-12-31",
        "2027-01-01",
    ] {
        repo.create(&record_on(day), "1.0.0", &[])
            .await
            .expect("stored");
    }

    let listed = repo
        .list_for_year(year("2026-01-01", "2026-12-31"))
        .await
        .expect("a listing");
    let days: Vec<String> = listed
        .iter()
        .map(|r| r.record.discarded_on.to_string())
        .collect();
    assert_eq!(days, vec!["2026-01-01", "2026-06-15", "2026-12-31"]);
}

/// A year whose start is after its end is not refused by the store; it lists
/// nothing, since no day is both after the start and before the end.
#[tokio::test]
async fn a_year_whose_start_is_after_its_end_lists_nothing() {
    let pg = start_pg().await;
    let repo = PgDiscardRecordRepo::new(pg.dal.clone());
    repo.create(&record_on("2026-06-15"), "1.0.0", &[])
        .await
        .expect("stored");

    let listed = repo
        .list_for_year(year("2026-12-31", "2026-01-01"))
        .await
        .expect("a listing");
    assert!(listed.is_empty());
}

/// A discard naming a passport this node does not hold is refused, and the
/// refusal stores nothing: the record and the passports are one transaction.
#[tokio::test]
async fn a_record_naming_an_unheld_passport_is_refused_and_stores_nothing() {
    let pg = start_pg().await;
    let repo = PgDiscardRecordRepo::new(pg.dal.clone());
    let unheld = Uuid::now_v7();

    let refused = repo
        .create(&record_on("2026-08-01"), "1.0.0", &[unheld])
        .await
        .expect_err("a passport this node does not hold is refused");
    match refused {
        DppError::Validation(errors) => {
            assert!(
                errors.errors[0].message.contains(&unheld.to_string()),
                "the refusal names the passport: {errors}"
            );
        }
        other => panic!("expected a validation refusal, got {other:?}"),
    }
    assert!(
        repo.list_for_year(year("2026-01-01", "2026-12-31"))
            .await
            .expect("a listing")
            .is_empty(),
        "nothing was stored"
    );
}

/// A passport named twice is one join row, not two.
#[tokio::test]
async fn a_passport_named_twice_is_joined_once() {
    let pg = start_pg().await;
    let repo = PgDiscardRecordRepo::new(pg.dal.clone());
    let passport = held_passport(&pg.dal).await;

    let stored = repo
        .create(&record_on("2026-08-01"), "1.0.0", &[passport, passport])
        .await
        .expect("stored");
    assert_eq!(stored.passport_ids, vec![passport]);
}

/// A document cited by two records is one stored file: the second put writes
/// nothing, and both records cite the same row.
#[tokio::test]
async fn a_document_cited_by_two_records_is_stored_once() {
    let pg = start_pg().await;
    let records = PgDiscardRecordRepo::new(pg.dal.clone());
    let files = PgEvidenceFileRepo::new(pg.dal.clone());
    let bytes = b"delivery note, shared by two discards";
    let sha = "b".repeat(64);

    let first = records
        .create(&record_on("2026-08-01"), "1.0.0", &[])
        .await
        .expect("stored");
    let second = records
        .create(&record_on("2026-08-02"), "1.0.0", &[])
        .await
        .expect("stored");

    assert!(files.put(&sha, bytes).await.expect("a put"), "new file");
    assert!(
        !files.put(&sha, bytes).await.expect("a second put"),
        "a file already held is not stored again"
    );
    assert!(
        records
            .attach(first.id, EvidenceKind::DeliveryDocumentation, &sha)
            .await
            .expect("attach")
    );
    assert!(
        records
            .attach(second.id, EvidenceKind::DeliveryDocumentation, &sha)
            .await
            .expect("attach")
    );

    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM odal.evidence_file WHERE sha256 = $1")
        .bind(&sha)
        .fetch_one(pg.dal.pool())
        .await
        .expect("a count");
    assert_eq!(rows, 1, "one stored file, however many records cite it");
    let citations: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM odal.discard_record_evidence WHERE evidence_sha256 = $1",
    )
    .bind(&sha)
    .fetch_one(pg.dal.pool())
    .await
    .expect("a count");
    assert_eq!(citations, 2, "two records cite the one file");
}

/// The same document under the same kind is attached to a record once.
#[tokio::test]
async fn a_document_attaches_once_under_each_kind() {
    let pg = start_pg().await;
    let repo = PgDiscardRecordRepo::new(pg.dal.clone());
    let stored = repo
        .create(&record_on("2026-08-01"), "1.0.0", &[])
        .await
        .expect("stored");
    let sha = "c".repeat(64);
    PgEvidenceFileRepo::new(pg.dal.clone())
        .put(&sha, b"x")
        .await
        .expect("a put");

    assert!(
        repo.attach(stored.id, EvidenceKind::DeliveryDocumentation, &sha)
            .await
            .expect("attach")
    );
    assert!(
        !repo
            .attach(stored.id, EvidenceKind::DeliveryDocumentation, &sha)
            .await
            .expect("attach again"),
        "the same document under the same kind is not attached twice"
    );
    assert!(
        repo.attach(stored.id, EvidenceKind::TreatmentStatement, &sha)
            .await
            .expect("another kind"),
        "a different kind is a different attachment"
    );
}

/// Every kind core names is stored under its wire name and read back as the
/// same kind, so a kind mapped wrongly on either side fails here.
#[tokio::test]
async fn every_evidence_kind_reads_back_as_the_kind_stored() {
    let pg = start_pg().await;
    let repo = PgDiscardRecordRepo::new(pg.dal.clone());
    let files = PgEvidenceFileRepo::new(pg.dal.clone());
    let stored = repo
        .create(&record_on("2026-08-01"), "1.0.0", &[])
        .await
        .expect("stored");
    let sha = "d".repeat(64);
    files.put(&sha, b"x").await.expect("a put");

    let kinds = [
        EvidenceKind::SafetyAssessment,
        EvidenceKind::ChemicalsTestReport,
        EvidenceKind::NonComplianceSelfAssessment,
        EvidenceKind::InfringementDecision,
        EvidenceKind::InfringementNotification,
        EvidenceKind::InternalInvestigation,
        EvidenceKind::IpLicenceOrContract,
        EvidenceKind::DestructionJustification,
        EvidenceKind::ReuseFeasibilityAssessment,
        EvidenceKind::QualityAssessmentEvidence,
        EvidenceKind::InspectionRecord,
        EvidenceKind::DonationOfferEvidence,
        EvidenceKind::DonationReceiptDeclaration,
        EvidenceKind::WasteOperatorSourceDocumentation,
        EvidenceKind::DeliveryDocumentation,
        EvidenceKind::TreatmentStatement,
        EvidenceKind::DerogationStatement,
    ];
    for kind in kinds {
        repo.attach(stored.id, kind, &sha).await.expect("attach");
    }
    let mut held = repo.held_kinds(stored.id).await.expect("held kinds");
    let mut expected = kinds.to_vec();
    held.sort_by_key(|k| format!("{k:?}"));
    expected.sort_by_key(|k| format!("{k:?}"));
    assert_eq!(held, expected);
}

/// The app role has no DELETE on a discard record, so a delete is refused by
/// the grants before any trigger is reached.
#[tokio::test]
async fn the_app_role_cannot_delete_a_discard_record() {
    let pg = start_pg().await;
    let repo = PgDiscardRecordRepo::new(pg.dal.clone());
    let stored = repo
        .create(&record_on("2026-08-01"), "1.0.0", &[])
        .await
        .expect("stored");

    let result = sqlx::query("DELETE FROM odal.discard_record WHERE id = $1")
        .bind(stored.id)
        .execute(pg.dal.pool())
        .await;
    assert!(
        result.is_err(),
        "the app role may not delete a discard record"
    );
}

/// The superuser is refused by the trigger: an update or delete changes nothing
/// the record says, even when the grant would allow it.
#[tokio::test]
async fn the_trigger_refuses_an_update_or_delete_even_by_the_superuser() {
    let pg = start_pg().await;
    let repo = PgDiscardRecordRepo::new(pg.dal.clone());
    let stored = repo
        .create(&record_on("2026-08-01"), "1.0.0", &[])
        .await
        .expect("stored");
    let admin = sqlx::PgPool::connect(&pg.admin_url)
        .await
        .expect("admin connect");

    let update = sqlx::query("UPDATE odal.discard_record SET schema_version = 'x' WHERE id = $1")
        .bind(stored.id)
        .execute(&admin)
        .await
        .expect_err("an update is refused");
    assert!(update.to_string().contains("append-only"), "{update}");

    let delete = sqlx::query("DELETE FROM odal.discard_record WHERE id = $1")
        .bind(stored.id)
        .execute(&admin)
        .await
        .expect_err("a delete is refused");
    assert!(delete.to_string().contains("append-only"), "{delete}");

    assert!(repo.get(stored.id).await.expect("a read").is_some());
}
