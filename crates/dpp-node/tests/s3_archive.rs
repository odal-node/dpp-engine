//! Integration test: `S3ArchiveAdapter` against a real S3-compatible server.
//!
//! Run: `cargo test -p dpp-node --features integration-tests`

#![cfg(feature = "integration-tests")]

use testcontainers::{
    GenericImage, ImageExt,
    core::{Host, ports::ContainerPort},
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

/// The S3 server build every path here tests against.
///
/// One constant so the shared server CI starts and the container this file
/// starts locally cannot drift onto different releases. A suite that runs
/// against one server in CI and a different one on a developer machine proves
/// less than it looks like it does. The CI workflow and `snapshot_static_tier.rs`
/// pin the same pair; the three must move together.
///
/// **RustFS, because MinIO can no longer be pulled.** `docker.io/minio/minio` was
/// removed, and on 2026-09-24 `quay.io/minio/minio` stopped granting anonymous
/// pulls: the registry hands out a token whose `access` carries no actions,
/// while a control repository on the same registry grants `pull`. RustFS is an
/// Apache-2.0 S3 server configured the way MinIO was, and it enforces bucket
/// policies — which `snapshot_static_tier.rs` depends on, and a mock that
/// ignored them would pass while proving nothing.
const S3_IMAGE: (&str, &str) = ("rustfs/rustfs", "1.0.0");

/// Point this at a running S3 server and the suite uses it instead of starting a
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

/// The shared server's key pair, read beside [`SHARED_ENDPOINT_ENV`]. Whoever
/// starts that server generates the pair; none is written into this file.
const SHARED_ACCESS_KEY_ENV: &str = "ODAL_TEST_S3_ACCESS_KEY";
const SHARED_SECRET_KEY_ENV: &str = "ODAL_TEST_S3_SECRET_KEY";

/// An S3 server to talk to, the bucket this test owns on it, and the key pair
/// that authenticates to it.
struct S3Server {
    /// Held only on the container path — dropping it stops the container.
    /// `None` when the endpoint came from the environment, where the server
    /// outlives every test process and is not this test's to stop.
    _container: Option<testcontainers::ContainerAsync<GenericImage>>,
    endpoint: String,
    bucket: String,
    access_key: String,
    secret_key: String,
}

/// A required variable of the shared-server arrangement, or a panic that says
/// which one is missing.
fn shared_key(name: &str) -> String {
    std::env::var(name)
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| panic!("{SHARED_ENDPOINT_ENV} is set, so {name} must be too"))
}

async fn start_s3() -> S3Server {
    // A bucket per test, so one shared server gives the same isolation a
    // container per test gave. `ensure_bucket` creates it, buckets are cheap,
    // and simple lowercase hex keeps the name inside S3's naming rules.
    let bucket = format!("test-archive-{}", uuid::Uuid::new_v4().simple());

    if let Some(endpoint) = std::env::var(SHARED_ENDPOINT_ENV)
        .ok()
        .filter(|s| !s.is_empty())
    {
        return S3Server {
            _container: None,
            endpoint,
            bucket,
            access_key: shared_key(SHARED_ACCESS_KEY_ENV),
            secret_key: shared_key(SHARED_SECRET_KEY_ENV),
        };
    }

    // A fresh pair for a container that lives as long as this test, so no
    // reusable credential is written down anywhere.
    let access_key = uuid::Uuid::new_v4().simple().to_string();
    let secret_key = uuid::Uuid::new_v4().simple().to_string();

    // The image's default command runs the server on `/data`. RustFS fetches
    // `version.rustfs.com` at every start, and `RUSTFS_CHECK_UPDATES=false` does
    // not stop it in this release — measured, not assumed. Resolving the host to
    // loopback does: a test double has no business reaching the network.
    let image = GenericImage::new(S3_IMAGE.0, S3_IMAGE.1)
        .with_exposed_port(ContainerPort::Tcp(9000))
        .with_env_var("RUSTFS_ACCESS_KEY", access_key.clone())
        .with_env_var("RUSTFS_SECRET_KEY", secret_key.clone())
        .with_host(
            "version.rustfs.com",
            Host::Addr(std::net::Ipv4Addr::LOCALHOST.into()),
        );

    let container = image.start().await.expect("start the S3 server container");
    let port = container
        .get_host_port_ipv4(9000)
        .await
        .expect("S3 server mapped port");
    let endpoint = format!("http://127.0.0.1:{port}");
    wait_until_ready(&endpoint).await;

    S3Server {
        _container: Some(container),
        endpoint,
        bucket,
        access_key,
        secret_key,
    }
}

/// Poll the server's readiness route until it answers, for at most 30 seconds.
///
/// Readiness, not liveness: a server can be up before its storage is, and the
/// first thing every test does is create a bucket. Each probe carries its own
/// timeout, because a server that accepts a connection and never answers would
/// otherwise hold a single probe past any deadline. Not a log-line wait: RustFS
/// writes its log to a file inside the container, so nothing on stdout or
/// stderr marks the moment it starts serving.
async fn wait_until_ready(endpoint: &str) {
    let url = format!("{endpoint}/health/ready");
    let probe = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(2))
        .build()
        .expect("probe client");
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
    while tokio::time::Instant::now() < deadline {
        if let Ok(r) = probe.get(&url).send().await
            && r.status().is_success()
        {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    panic!("the S3 server at {endpoint} was not ready within 30s");
}

fn build_adapter(s3: &S3Server) -> S3ArchiveAdapter {
    S3ArchiveAdapter::new(S3ArchiveConfig {
        endpoint: Some(s3.endpoint.clone()),
        bucket: s3.bucket.clone(),
        access_key_id: s3.access_key.clone(),
        secret_access_key: s3.secret_key.clone(),
        region: "us-east-1".into(),
    })
}

fn make_passport() -> Passport {
    Passport {
        id: PassportId::new(),
        batch_id: None,
        serial_number: None,
        product_name: "Test Battery".into(),
        product_group: ProductGroup::Battery,
        applicable_instruments: Vec::new(),
        granularity: None,
        manufacturer: ManufacturerInfo {
            name: "Test Co".into(),
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

#[tokio::test]
async fn archive_then_verify_integrity() {
    let s3 = start_s3().await;
    let adapter = build_adapter(&s3);
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
    let s3 = start_s3().await;
    let adapter = build_adapter(&s3);
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
    let s3 = start_s3().await;
    let adapter = build_adapter(&s3);
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
    let s3 = start_s3().await;
    let adapter = build_adapter(&s3);
    adapter.ensure_bucket().await.expect("create bucket");

    let result = adapter.retrieve(PassportId::new()).await.expect("retrieve");
    assert!(result.is_none());
}
