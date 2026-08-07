//! Postgres-backed tests for the qualified-seal outbox (`ops/pg/0028`).
//!
//! These cover the claims that unit tests structurally cannot, because they are
//! claims about the *database*, not about Rust:
//!
//! 1. **The retention guard permits the seal write.** This is the one most likely
//!    to be silently wrong. The drain writes `seal` onto a passport that is
//!    already published and already `retention_locked`, so if `seal` is not in
//!    the guard's `mutable_keys` every seal in production fails with
//!    `ODAL_RETENTION` — and nothing else in the suite would notice.
//! 2. **The guard still refuses everything else.** Adding a key to that array is
//!    exactly the kind of change that can widen it by accident.
//! 3. **`(passport_id, payload_hash)` behaves as designed** — a retried enqueue
//!    of the same digest is free; a re-publish's new digest is a new row. Each
//!    drained row is a paid QTSP call, so this key is a billing control.
//! 4. **`mark_sealed` is atomic** and lands the envelope on the right passport.
//! 5. **The `payload_hash` CHECK** refuses anything that is not a SHA-256 digest.

#![cfg(feature = "integration-tests")]

use chrono::Utc;
use dpp_dal::pg::{PgDal, PgPassportRepo, PgSealOutboxRepo};
use dpp_domain::domain::passport::{ManufacturerInfo, Passport, PassportId};
use dpp_domain::domain::sector::Sector;
use dpp_domain::domain::status::PassportStatus;
use dpp_domain::ports::passport_repo::PassportRepository;
use dpp_domain::ports::seal::{SealFormat, SealedEnvelope};
use dpp_types::SealOutbox;
use testcontainers::core::{ContainerPort, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{GenericImage, ImageExt};

struct TestPg {
    dal: PgDal,
    _container: testcontainers::ContainerAsync<GenericImage>,
}

async fn start_pg() -> TestPg {
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

    // Applying the whole migration set is itself part of what this file checks:
    // 0028 has never run against a real Postgres before these tests.
    PgDal::migrate(&admin_url)
        .await
        .expect("migrations apply, including 0028_seal_outbox");

    let app_url = format!("postgres://odal_app:test@127.0.0.1:{port}/odal");
    let dal = PgDal::connect(&app_url).await.expect("app connect");

    TestPg {
        dal,
        _container: container,
    }
}

/// A passport in the state the drain actually finds one in: published, signed,
/// and retention-locked. The lock is the whole point — an unlocked row would
/// slip past the guard and prove nothing.
fn published_passport(jws: &str) -> Passport {
    Passport {
        id: PassportId::new(),
        batch_id: None,
        product_name: "Seal Test Battery".into(),
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
        jws_signature: Some(jws.to_owned()),
        public_jws_signature: None,
        disclosure_signatures: Default::default(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        published_at: Some(Utc::now()),
        schema_version: "2.0.0".into(),
        retention_locked: true,
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

fn digest_of(jws: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(jws.as_bytes()))
}

fn envelope(seal_value: &str) -> SealedEnvelope {
    SealedEnvelope {
        format: SealFormat::Cades,
        seal_value: seal_value.to_owned(),
        signing_cert_ref: None,
        sealed_at: Utc::now(),
        placeholder: false,
    }
}

/// The load-bearing one: publish → enqueue → drain → seal on the passport, with
/// the retention guard armed the whole way.
#[tokio::test]
async fn a_seal_lands_on_a_retention_locked_published_passport() {
    let pg = start_pg().await;
    let repo = PgPassportRepo::new(pg.dal.clone());
    let outbox = PgSealOutboxRepo::new(pg.dal.clone());

    // Deliberately not JWT-shaped: the seal digest is `SHA-256` over these bytes
    // whatever they are, so a realistic-looking compact JWS here would buy
    // nothing and trips secret scanners on a literal that is not a credential.
    let jws = "header.payload.signature";
    let passport = published_passport(jws);
    let id = passport.id;
    repo.create(passport.clone())
        .await
        .expect("insert passport");

    let hash = digest_of(jws);
    outbox.enqueue(id, &hash).await.expect("enqueue");

    let due = outbox.due(10).await.expect("due");
    assert_eq!(due.len(), 1, "the enqueued digest should be drainable");
    assert_eq!(due[0].payload_hash, hash);
    assert_eq!(due[0].passport_id, id);

    // This is the call the retention guard would reject if `seal` were missing
    // from `mutable_keys`.
    outbox
        .mark_sealed(due[0].id, &envelope("BASE64-CADES-P7S"))
        .await
        .expect("the retention guard must permit writing `seal` onto a locked row");

    let sealed = repo
        .find_by_id(id)
        .await
        .expect("read back")
        .expect("passport still exists");
    let seal = sealed.seal.expect("seal was written onto the passport");
    assert_eq!(seal.seal_value, "BASE64-CADES-P7S");
    assert_eq!(seal.format, SealFormat::Cades);
    assert!(!seal.placeholder);

    // And the row is closed, so the next pass does not buy a second seal.
    assert!(
        outbox.due(10).await.expect("due").is_empty(),
        "a sealed row must not be drained again — every drain costs money"
    );
    let counts = outbox.status_counts().await.expect("counts");
    assert_eq!(counts.sealed, 1);
    assert_eq!(counts.pending, 0);
}

/// Widening `mutable_keys` must not have widened it for anything else.
#[tokio::test]
async fn the_retention_guard_still_refuses_content_changes() {
    let pg = start_pg().await;
    let repo = PgPassportRepo::new(pg.dal.clone());

    let mut passport = published_passport("a.b.c");
    let id = passport.id;
    repo.create(passport.clone())
        .await
        .expect("insert passport");

    passport.product_name = "Renamed After Lock".into();
    let err = repo
        .update(passport)
        .await
        .expect_err("a locked passport's content must stay immutable");
    // The DAL maps the trigger's `ODAL_RETENTION` to this variant, so match the
    // variant rather than the raw SQL string — the mapping is what callers see.
    assert!(
        matches!(err, dpp_domain::DppError::RetentionLocked),
        "expected the retention guard to fire, got: {err:?}"
    );

    let unchanged = repo.find_by_id(id).await.unwrap().unwrap();
    assert_eq!(unchanged.product_name, "Seal Test Battery");
}

/// The key is a billing control: the same digest twice is one row, so a retried
/// publish of unchanged content cannot buy two seals for one attestation.
#[tokio::test]
async fn enqueueing_the_same_digest_twice_is_one_row() {
    let pg = start_pg().await;
    let repo = PgPassportRepo::new(pg.dal.clone());
    let outbox = PgSealOutboxRepo::new(pg.dal.clone());

    let jws = "a.b.c";
    let passport = published_passport(jws);
    let id = passport.id;
    repo.create(passport.clone())
        .await
        .expect("insert passport");

    let hash = digest_of(jws);
    outbox.enqueue(id, &hash).await.expect("first enqueue");
    outbox.enqueue(id, &hash).await.expect("second enqueue");

    assert_eq!(
        outbox.due(10).await.expect("due").len(),
        1,
        "a duplicate enqueue must not stack a second billable row"
    );
}

/// A re-publish re-signs, so the new signature is a new statement and needs its
/// own attestation — the one case where a second row is correct.
#[tokio::test]
async fn a_republish_digest_is_a_separate_row() {
    let pg = start_pg().await;
    let repo = PgPassportRepo::new(pg.dal.clone());
    let outbox = PgSealOutboxRepo::new(pg.dal.clone());

    let passport = published_passport("a.b.first");
    let id = passport.id;
    repo.create(passport.clone())
        .await
        .expect("insert passport");

    outbox
        .enqueue(id, &digest_of("a.b.first"))
        .await
        .expect("first publish");
    outbox
        .enqueue(id, &digest_of("a.b.second"))
        .await
        .expect("re-publish");

    let due = outbox.due(10).await.expect("due");
    assert_eq!(
        due.len(),
        2,
        "a re-published passport's new signature needs its own seal"
    );
}

/// The CHECK constraint is the last line before a malformed digest reaches a
/// paid endpoint.
#[tokio::test]
async fn a_non_digest_payload_hash_is_refused_by_the_database() {
    let pg = start_pg().await;
    let repo = PgPassportRepo::new(pg.dal.clone());
    let outbox = PgSealOutboxRepo::new(pg.dal.clone());

    let passport = published_passport("a.b.c");
    let id = passport.id;
    repo.create(passport.clone())
        .await
        .expect("insert passport");

    for bad in [
        "not-a-digest",
        "ABCDEF",         // uppercase
        &"ab".repeat(31), // too short
        &"ab".repeat(33), // too long
    ] {
        assert!(
            outbox.enqueue(id, bad).await.is_err(),
            "the payload_hash CHECK accepted {bad:?}"
        );
    }
}

/// The recovery path. A passport whose seal exhausted its retries during a
/// provider outage must be sealable again — otherwise it is published and
/// permanently unsealed, with no way back except re-publishing, which changes
/// the very signature the seal attests to.
#[tokio::test]
async fn an_exhausted_row_is_re_armed_by_a_later_enqueue() {
    let pg = start_pg().await;
    let repo = PgPassportRepo::new(pg.dal.clone());
    let outbox = PgSealOutboxRepo::new(pg.dal.clone());

    let jws = "a.b.c";
    let passport = published_passport(jws);
    let id = passport.id;
    repo.create(passport.clone())
        .await
        .expect("insert passport");

    let hash = digest_of(jws);
    outbox.enqueue(id, &hash).await.expect("enqueue");
    let row = outbox.due(10).await.expect("due").remove(0);
    outbox
        .mark_exhausted(row.id, "provider unreachable for 8 attempts".into())
        .await
        .expect("exhaust");
    assert_eq!(outbox.status_counts().await.unwrap().exhausted, 1);
    assert!(outbox.due(10).await.unwrap().is_empty());

    // Re-enqueueing the same digest revives it.
    outbox.enqueue(id, &hash).await.expect("re-enqueue");
    let revived = outbox.due(10).await.expect("due");
    assert_eq!(revived.len(), 1, "an exhausted row must be recoverable");
    assert_eq!(revived[0].payload_hash, hash);
    assert_eq!(revived[0].attempts, 0, "the retry budget is reset");

    let counts = outbox.status_counts().await.unwrap();
    assert_eq!(counts.pending, 1);
    assert_eq!(counts.exhausted, 0);
}

/// The other half of that clause: a row that already has a paid-for seal must
/// never be revived, or the same attestation gets bought twice.
#[tokio::test]
async fn a_sealed_row_is_never_re_armed() {
    let pg = start_pg().await;
    let repo = PgPassportRepo::new(pg.dal.clone());
    let outbox = PgSealOutboxRepo::new(pg.dal.clone());

    let jws = "a.b.c";
    let passport = published_passport(jws);
    let id = passport.id;
    repo.create(passport.clone())
        .await
        .expect("insert passport");

    let hash = digest_of(jws);
    outbox.enqueue(id, &hash).await.expect("enqueue");
    let row = outbox.due(10).await.expect("due").remove(0);
    outbox
        .mark_sealed(row.id, &envelope("PAID-FOR-P7S"))
        .await
        .expect("seal");

    // A duplicated publish, a replayed event, an operator retry — none may
    // re-queue an attestation that has already been bought.
    outbox
        .enqueue(id, &hash)
        .await
        .expect("re-enqueue is a no-op");
    assert!(
        outbox.due(10).await.expect("due").is_empty(),
        "a sealed row was re-queued — this buys the same seal twice"
    );

    let counts = outbox.status_counts().await.unwrap();
    assert_eq!(counts.sealed, 1);
    assert_eq!(counts.pending, 0);
}

/// Hole one: publish committed, the after-commit enqueue never ran. Without the
/// sweep this passport is published and unsealed with no row, and nothing would
/// ever notice.
#[tokio::test]
async fn the_sweep_queues_a_passport_whose_enqueue_was_lost() {
    let pg = start_pg().await;
    let repo = PgPassportRepo::new(pg.dal.clone());
    let outbox = PgSealOutboxRepo::new(pg.dal.clone());

    let jws = "a.b.lost-enqueue";
    let passport = published_passport(jws);
    let id = passport.id;
    repo.create(passport.clone())
        .await
        .expect("insert passport");
    // Note: no enqueue — that is the crash being simulated.
    assert!(outbox.due(10).await.unwrap().is_empty());

    let queued = outbox.enqueue_unsealed(100, 0).await.expect("sweep");
    assert_eq!(queued, 1);

    let due = outbox.due(10).await.expect("due");
    assert_eq!(due.len(), 1);
    assert_eq!(
        due[0].payload_hash,
        digest_of(jws),
        "the sweep must derive the same digest the vault would have"
    );
    assert_eq!(due[0].passport_id, id);
}

/// Hole two: the row gave up during a provider outage. The cooldown holds it
/// back while the outage is fresh, then the sweep revives it.
#[tokio::test]
async fn the_sweep_revives_an_exhausted_row_after_the_cooldown() {
    let pg = start_pg().await;
    let repo = PgPassportRepo::new(pg.dal.clone());
    let outbox = PgSealOutboxRepo::new(pg.dal.clone());

    let jws = "a.b.exhausted";
    let passport = published_passport(jws);
    let id = passport.id;
    repo.create(passport.clone())
        .await
        .expect("insert passport");
    outbox.enqueue(id, &digest_of(jws)).await.expect("enqueue");
    let row = outbox.due(10).await.expect("due").remove(0);
    outbox
        .mark_exhausted(row.id, "provider down".into())
        .await
        .expect("exhaust");

    // A long cooldown means "the failure is still fresh" — leave it alone.
    assert_eq!(
        outbox.enqueue_unsealed(100, 3600).await.expect("sweep"),
        0,
        "a recently-failed row must not be retried immediately"
    );
    assert!(outbox.due(10).await.unwrap().is_empty());

    // Past the cooldown, it comes back.
    assert_eq!(outbox.enqueue_unsealed(100, 0).await.expect("sweep"), 1);
    assert_eq!(outbox.due(10).await.unwrap().len(), 1);
}

/// The sweep must be free on a converged deployment, and must never re-buy a
/// seal that exists.
#[tokio::test]
async fn the_sweep_ignores_sealed_and_pending_passports() {
    let pg = start_pg().await;
    let repo = PgPassportRepo::new(pg.dal.clone());
    let outbox = PgSealOutboxRepo::new(pg.dal.clone());

    // One already sealed.
    let sealed_jws = "a.b.sealed";
    let sealed = published_passport(sealed_jws);
    let sealed_id = sealed.id;
    repo.create(sealed.clone()).await.expect("insert");
    outbox
        .enqueue(sealed_id, &digest_of(sealed_jws))
        .await
        .expect("enqueue");
    let row = outbox.due(10).await.expect("due").remove(0);
    outbox
        .mark_sealed(row.id, &envelope("ALREADY-PAID-FOR"))
        .await
        .expect("seal");

    // One still queued.
    let pending_jws = "a.b.pending";
    let pending = published_passport(pending_jws);
    let pending_id = pending.id;
    repo.create(pending.clone()).await.expect("insert");
    outbox
        .enqueue(pending_id, &digest_of(pending_jws))
        .await
        .expect("enqueue");

    assert_eq!(
        outbox.enqueue_unsealed(100, 0).await.expect("sweep"),
        0,
        "a converged deployment must sweep to zero work and buy nothing"
    );
    assert_eq!(outbox.status_counts().await.unwrap().sealed, 1);
}

/// A draft has no signature to countersign, so it must never be swept in.
#[tokio::test]
async fn the_sweep_ignores_unpublished_passports() {
    let pg = start_pg().await;
    let repo = PgPassportRepo::new(pg.dal.clone());
    let outbox = PgSealOutboxRepo::new(pg.dal.clone());

    let mut draft = published_passport("a.b.c");
    draft.status = PassportStatus::Draft;
    draft.published_at = None;
    draft.jws_signature = None;
    draft.retention_locked = false;
    repo.create(draft).await.expect("insert draft");

    assert_eq!(outbox.enqueue_unsealed(100, 0).await.expect("sweep"), 0);
}

/// A transient failure keeps the row drainable rather than dropping a passport's
/// seal on the floor.
#[tokio::test]
async fn a_failed_attempt_backs_off_and_stays_pending() {
    let pg = start_pg().await;
    let repo = PgPassportRepo::new(pg.dal.clone());
    let outbox = PgSealOutboxRepo::new(pg.dal.clone());

    let jws = "a.b.c";
    let passport = published_passport(jws);
    let id = passport.id;
    repo.create(passport.clone())
        .await
        .expect("insert passport");
    outbox.enqueue(id, &digest_of(jws)).await.expect("enqueue");

    let row = outbox.due(10).await.expect("due").remove(0);
    outbox
        .mark_attempt_failed(row.id, "qtsp unreachable".into())
        .await
        .expect("mark failed");

    let counts = outbox.status_counts().await.expect("counts");
    assert_eq!(counts.pending, 1, "the row must stay pending for retry");
    assert_eq!(counts.sealed, 0);
    // Backed off, so not immediately due again.
    assert!(
        outbox.due(10).await.expect("due").is_empty(),
        "backoff must actually delay the next attempt"
    );
}
