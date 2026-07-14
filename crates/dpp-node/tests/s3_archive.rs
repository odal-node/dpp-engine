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
    domain::{
        passport::{ManufacturerInfo, Passport, PassportId},
        sector::Sector,
        status::PassportStatus,
    },
    ports::archive::ArchivePort,
};
use dpp_node::infra::s3_archive::{S3ArchiveAdapter, S3ArchiveConfig};

async fn start_minio() -> (testcontainers::ContainerAsync<GenericImage>, u16) {
    // `with_wait_for` is a `GenericImage` method; the `ImageExt` builders
    // (`with_env_var`/`with_cmd`) convert to `ContainerRequest`, which has no
    // `with_wait_for`. So set the wait condition before those calls.
    // Pinned (not `latest`) for reproducibility — `latest` drifts its startup
    // log (this release emits the `API:` banner on stderr).
    let image = GenericImage::new("minio/minio", "RELEASE.2025-09-07T16-13-09Z")
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
    (container, port)
}

fn build_adapter(port: u16) -> S3ArchiveAdapter {
    S3ArchiveAdapter::new(S3ArchiveConfig {
        endpoint: Some(format!("http://127.0.0.1:{port}")),
        bucket: "test-archive".into(),
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
        sector: Sector::Battery,
        product_category: None,
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
        sector_data: None,
        status: PassportStatus::Published,
        qr_code_url: None,
        jws_signature: Some("test.jws.sig".into()),
        public_jws_signature: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
        published_at: Some(Utc::now()),
        schema_version: "1.0.0".into(),
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

#[tokio::test]
async fn archive_then_verify_integrity() {
    let (_container, port) = start_minio().await;
    let adapter = build_adapter(port);
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
    let (_container, port) = start_minio().await;
    let adapter = build_adapter(port);
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
    let (_container, port) = start_minio().await;
    let adapter = build_adapter(port);
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
    let (_container, port) = start_minio().await;
    let adapter = build_adapter(port);
    adapter.ensure_bucket().await.expect("create bucket");

    let result = adapter.retrieve(PassportId::new()).await.expect("retrieve");
    assert!(result.is_none());
}
