//! Integration test: `S3ArchiveAdapter` against a real MinIO instance.
//!
//! Run: `cargo test -p dpp-node --features integration-tests`

#![cfg(feature = "integration-tests")]

use testcontainers::{
    GenericImage, ImageExt,
    core::{WaitFor, ports::ContainerPort},
    runners::AsyncRunner,
};

use chrono::Utc;
use dpp_domain::{
    passport::{ManufacturerInfo, Passport, PassportId},
    ports::archive::ArchivePort,
    product_group::ProductGroup,
    status::PassportStatus,
};
use dpp_node::infra::s3_archive::{S3ArchiveAdapter, S3ArchiveConfig};

/// The MinIO build every path here tests against.
///
/// One constant so the shared server CI starts and the container this file
/// starts locally cannot drift onto different releases. A suite that runs
/// against one MinIO in CI and a different one on a developer machine proves
/// less than it looks like it does.
const MINIO_IMAGE: (&str, &str) = ("minio/minio", "RELEASE.2025-09-07T16-13-09Z");

/// Point this at a running MinIO and the suite uses it instead of starting a
/// container per test.
///
/// # Why this exists
///
/// Each of these four tests booted its own MinIO — around ten seconds apiece,
/// nearly all of it container startup, which is not something the test body
/// controls. That left them sitting within a second of CI's slow-test budget,
/// so they crossed it whenever the runner was busy, in a different combination
/// each run.
///
/// The suites already exempted from that budget were surveyed by counting
/// `start_nats` and `start_pg_before` call sites. This is a third way to start a
/// container and was missed, so the exemption never reached it — and an
/// exemption would have been the wrong answer here anyway. The NATS suite
/// genuinely cannot share a server, because `NatsEventBus::connect` hard-codes
/// the `DPP_EVENTS` stream and four tests against one server would consume each
/// other's messages. **Nothing equivalent constrains these four.** The only name
/// they shared was the bucket, and that is now per-test.
///
/// Sharing in-process is not available: nextest runs each test in its own
/// process, so a `OnceLock` holding a container is one container per test again.
/// The server therefore has to outlive the test process and be found through the
/// environment — the same arrangement `ODAL_TEST_PG_ADMIN_URL` already uses for
/// Postgres, followed deliberately rather than inventing a second shape for the
/// same problem.
///
/// Unset, every test starts its own container exactly as before, so a bare
/// `cargo test` needs no orchestration.
const SHARED_ENDPOINT_ENV: &str = "ODAL_TEST_S3_ENDPOINT";

/// A MinIO to talk to, and the bucket this test owns on it.
struct Minio {
    /// Held only on the container path — dropping it stops the container.
    /// `None` when the endpoint came from the environment, where the server
    /// outlives every test process and is not this test's to stop.
    _container: Option<testcontainers::ContainerAsync<GenericImage>>,
    endpoint: String,
    bucket: String,
}

async fn start_minio() -> Minio {
    // A bucket per test, so one shared server gives the same isolation a
    // container per test gave. `ensure_bucket` creates it, buckets are cheap,
    // and simple lowercase hex keeps the name inside S3's naming rules.
    let bucket = format!("test-archive-{}", uuid::Uuid::new_v4().simple());

    if let Some(endpoint) = std::env::var(SHARED_ENDPOINT_ENV)
        .ok()
        .filter(|s| !s.is_empty())
    {
        return Minio {
            _container: None,
            endpoint,
            bucket,
        };
    }

    // `with_wait_for` is a `GenericImage` method; the `ImageExt` builders
    // (`with_env_var`/`with_cmd`) convert to `ContainerRequest`, which has no
    // `with_wait_for`. So set the wait condition before those calls.
    // Pinned (not `latest`) for reproducibility — `latest` drifts its startup
    // log (this release emits the `API:` banner on stderr).
    let image = GenericImage::new(MINIO_IMAGE.0, MINIO_IMAGE.1)
        .with_exposed_port(ContainerPort::Tcp(9000))
        .with_wait_for(WaitFor::message_on_stderr("API:"))
        .with_env_var("MINIO_ROOT_USER", "minioadmin")
        .with_env_var("MINIO_ROOT_PASSWORD", "minioadmin")
        .with_cmd(vec!["server", "/data", "--console-address", ":9001"]);

    let container = image.start().await.expect("start minio container");
    let port = container
        .get_host_port_ipv4(9000)
        .await
        .expect("minio mapped port");

    Minio {
        _container: Some(container),
        endpoint: format!("http://127.0.0.1:{port}"),
        bucket,
    }
}

fn build_adapter(minio: &Minio) -> S3ArchiveAdapter {
    S3ArchiveAdapter::new(S3ArchiveConfig {
        endpoint: Some(minio.endpoint.clone()),
        bucket: minio.bucket.clone(),
        access_key_id: "minioadmin".into(),
        secret_access_key: "minioadmin".into(),
        region: "us-east-1".into(),
    })
}

fn make_passport() -> Passport {
    Passport {
        id: PassportId::new(),
        batch_id: None,
        product_name: "Test Battery".into(),
        product_group: ProductGroup::Battery,
        applicable_instruments: Vec::new(),
        granularity: None,
        manufacturer: ManufacturerInfo {
            name: "Test Co".into(),
            address: "Berlin, DE".into(),
            did_web_url: None,
        },
        materials: vec![],
        co2e_per_unit: None,
        repairability_score: None,
        compliance_result: None,
        lint_result: None,
        product_group_data: None,
        status: PassportStatus::Published,
        qr_code_url: None,
        jws_signature: Some("test.jws.sig".into()),
        public_jws_signature: None,
        disclosure_signatures: Default::default(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        published_at: Some(Utc::now()),
        placed_on_market_date: None,
        schema_version: "1.0.0".into(),
        retention_locked: true,
        version: 1,
        supersedes_id: None,
        parent_passport_ref: None,
        component_refs: Vec::new(),
        retention_until: None,
        product_id: None,
        commodity_code: None,
        operator_identifier: None,
        facility: None,
        seal: None,
    }
}

#[tokio::test]
async fn archive_then_verify_integrity() {
    let minio = start_minio().await;
    let adapter = build_adapter(&minio);
    adapter.ensure_bucket().await.expect("create bucket");

    let passport = make_passport();
    let receipt = adapter.archive(&passport, 10).await.expect("archive");

    assert!(!receipt.content_hash.is_empty());
    assert!(receipt.archive_id.starts_with("passports/"));

    let verification = adapter
        .verify(passport.id, &receipt.content_hash)
        .await
        .expect("verify");

    assert!(verification.integrity_ok);
    assert!(verification.accessible);
}

#[tokio::test]
async fn verify_wrong_hash_returns_not_ok() {
    let minio = start_minio().await;
    let adapter = build_adapter(&minio);
    adapter.ensure_bucket().await.expect("create bucket");

    let passport = make_passport();
    adapter.archive(&passport, 10).await.expect("archive");

    let v = adapter
        .verify(passport.id, "deadbeefdeadbeef")
        .await
        .expect("verify");
    assert!(!v.integrity_ok);
}

#[tokio::test]
async fn retrieve_returns_original_passport() {
    let minio = start_minio().await;
    let adapter = build_adapter(&minio);
    adapter.ensure_bucket().await.expect("create bucket");

    let passport = make_passport();
    adapter.archive(&passport, 10).await.expect("archive");

    let retrieved = adapter
        .retrieve(passport.id)
        .await
        .expect("retrieve")
        .expect("should be Some");

    assert_eq!(retrieved.id, passport.id);
    assert_eq!(retrieved.product_name, passport.product_name);
}

#[tokio::test]
async fn retrieve_unknown_passport_returns_none() {
    let minio = start_minio().await;
    let adapter = build_adapter(&minio);
    adapter.ensure_bucket().await.expect("create bucket");

    let result = adapter.retrieve(PassportId::new()).await.expect("retrieve");
    assert!(result.is_none());
}
