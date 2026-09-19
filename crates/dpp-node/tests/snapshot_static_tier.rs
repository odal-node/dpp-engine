//! Integration test: `S3SnapshotStore` against a real MinIO instance.
//!
//! Run: `cargo test -p dpp-node --features integration-tests`
//!
//! # What this covers that nothing else did
//!
//! `snapshot_outbox.rs` drives the drain against an in-memory store and says
//! "the MinIO tier covers the adapter" — but the MinIO tier only ever covered
//! `S3ArchiveAdapter`. The snapshot store's S3 path had no test against a real
//! object store at all, so nothing checked the property the continuity tier
//! rests on: that an **unauthenticated** reader who fetches the stored object
//! over plain HTTP gets bytes whose signed freshness bound still verifies.
//!
//! That reader is the whole point of the tier. It is what `odal snapshot
//! verify` is, and it holds no credential — the node it would have got one
//! from is the thing that is down.
//!
//! # Scope
//!
//! The document here is built in-test rather than through
//! `render_public_snapshot`, which would drag the whole `PassportService`
//! harness into this binary for no gain. That the producer's output is the
//! shape `verify_snapshot_bound` reads is pinned where the producer lives, in
//! `dpp-vault`'s `continuity_snapshot` suite. What is pinned here is the round
//! trip through storage.

#![cfg(feature = "integration-tests")]

use testcontainers::{
    GenericImage, ImageExt,
    core::{WaitFor, ports::ContainerPort},
    runners::AsyncRunner,
};

use chrono::{Duration, SubsecRound as _, Utc};
use dpp_node::infra::s3_snapshot::{S3SnapshotConfig, S3SnapshotStore};
use dpp_types::snapshot::{SnapshotMeta, SnapshotStore, snapshot_json_key};

/// The MinIO build this file tests against.
///
/// 🚨 `quay.io`, not Docker Hub — `docker.io/minio/minio` was removed and every
/// pull is denied. Pinned to the same pair `s3_archive.rs` and the CI workflow
/// use; the three must move together.
const MINIO_IMAGE: (&str, &str) = ("quay.io/minio/minio", "RELEASE.2025-09-07T16-13-09Z");

/// Point this at a running MinIO and the suite uses it instead of starting a
/// container. Same arrangement `s3_archive.rs` uses, for the same reason:
/// nextest gives each test its own process, so an in-process shared container
/// is one container per test again.
const SHARED_ENDPOINT_ENV: &str = "ODAL_TEST_S3_ENDPOINT";

struct Minio {
    _container: Option<testcontainers::ContainerAsync<GenericImage>>,
    endpoint: String,
    bucket: String,
}

async fn start_minio() -> Minio {
    let bucket = format!("test-snapshot-{}", uuid::Uuid::new_v4().simple());

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

fn config(minio: &Minio) -> S3SnapshotConfig {
    S3SnapshotConfig {
        endpoint: Some(minio.endpoint.clone()),
        bucket: minio.bucket.clone(),
        access_key_id: "minioadmin".into(),
        secret_access_key: "minioadmin".into(),
        region: "us-east-1".into(),
    }
}

/// Create the bucket and make it world-readable.
///
/// `S3SnapshotStore` has no `ensure_bucket` — the production bucket is created
/// by infrastructure, public by policy, because the tier's readers are
/// anonymous. The test has to reproduce both halves or it would be checking a
/// private bucket and proving nothing about the reader that matters.
async fn ensure_public_bucket(minio: &Minio) {
    let credentials =
        aws_sdk_s3::config::Credentials::new("minioadmin", "minioadmin", None, None, "static");
    let conf = aws_sdk_s3::config::Builder::new()
        .credentials_provider(credentials)
        .region(aws_sdk_s3::config::Region::new("us-east-1"))
        .behavior_version(aws_sdk_s3::config::BehaviorVersion::latest())
        .endpoint_url(minio.endpoint.clone())
        .force_path_style(true)
        .build();
    let client = aws_sdk_s3::Client::from_conf(conf);

    client
        .create_bucket()
        .bucket(&minio.bucket)
        .send()
        .await
        .expect("create bucket");

    let policy = format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow",
            "Principal":{{"AWS":["*"]}},"Action":["s3:GetObject"],
            "Resource":["arn:aws:s3:::{}/*"]}}]}}"#,
        minio.bucket
    );
    client
        .put_bucket_policy()
        .bucket(&minio.bucket)
        .policy(policy)
        .send()
        .await
        .expect("make the bucket publicly readable");
}

/// A signed snapshot document and the key that checks it, in the shape
/// `render_public_snapshot` writes: dates in, sign, then attach the proof.
fn signed_snapshot(
    as_of: chrono::DateTime<Utc>,
    valid_until: chrono::DateTime<Utc>,
) -> (tempfile::TempDir, serde_json::Value, String) {
    let dir = tempfile::tempdir().expect("temp dir");
    let store = dpp_crypto::keystore::KeyStore::open(dir.path().join("keystore.json"), "test-pass")
        .expect("open keystore");
    store.generate_key("root").expect("generate key");

    let rfc3339 = |t: chrono::DateTime<Utc>| t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let mut document = serde_json::json!({
        "id": "0198f000-0000-7000-8000-000000000000",
        "productGroup": "battery",
        "asOf": rfc3339(as_of),
        "validUntil": rfc3339(valid_until),
    });
    let proof = dpp_crypto::jws::sign(&store, "root", &document).expect("sign snapshot");
    document["snapshotJwsSignature"] = serde_json::Value::String(proof);

    let did = dpp_vc::build_did_document(&store, "snapshot-test.example.com", "root")
        .expect("build did document");
    let key = dpp_crypto::jws::extract_primary_public_key(&did).expect("primary key");

    (dir, document, key)
}

/// The whole chain an operator's no-node check walks: the real adapter writes
/// to a real bucket, an anonymous HTTP GET reads it back, and the bound still
/// verifies.
#[tokio::test]
async fn a_stored_snapshot_verifies_when_fetched_anonymously() {
    let minio = start_minio().await;
    ensure_public_bucket(&minio).await;
    let store = S3SnapshotStore::new(config(&minio));

    let as_of = Utc::now().trunc_subsecs(0);
    let valid_until = as_of + Duration::days(7);
    let (_dir, document, key) = signed_snapshot(as_of, valid_until);
    let dpp_id = "0198f000-0000-7000-8000-000000000000";

    store
        .put_public_json(
            dpp_id,
            &serde_json::to_vec(&document).expect("serialise"),
            SnapshotMeta {
                as_of,
                valid_until,
                max_age: std::time::Duration::from_secs(86_400),
            },
        )
        .await
        .expect("store the snapshot");

    // No credential, no SDK — exactly what a holder with no node has.
    let url = format!(
        "{}/{}/{}",
        minio.endpoint,
        minio.bucket,
        snapshot_json_key(dpp_id)
    );
    let response = reqwest::get(&url).await.expect("fetch the stored snapshot");
    assert!(
        response.status().is_success(),
        "an anonymous reader must be able to fetch the object: HTTP {}",
        response.status()
    );

    let headers = response.headers().clone();
    let fetched: serde_json::Value = response.json().await.expect("the object is JSON");

    let bound = dpp_vc::verify_snapshot_bound(&fetched, &key, as_of + Duration::days(1));
    assert!(
        matches!(bound, dpp_vc::SnapshotBound::Current { .. }),
        "a stored snapshot fetched anonymously must still verify, got {bound:?}"
    );

    // The `x-amz-meta-*` pair exists so a reader walking the bucket can see the
    // dates without parsing the body. Nothing signs it, so the only property
    // worth asserting is that it agrees with the claim that *is* signed — a
    // mirror that disagreed would read as tampering to whoever compared them.
    let meta_valid_until = headers
        .get("x-amz-meta-odal-valid-until")
        .and_then(|v| v.to_str().ok())
        .expect("the stored object carries its validUntil in metadata");
    assert_eq!(
        meta_valid_until,
        fetched["validUntil"].as_str().expect("signed validUntil"),
        "the object metadata and the signed claim must name the same instant"
    );
}

/// A copy served off the bucket with its proof removed is `Absent`, and
/// `Absent` off the static tier means the bound was stripped.
///
/// 🚨 The failure this tier is exposed to: the dates survive the edit, so
/// anything that read them without checking the proof would report a stale
/// copy as fresh.
#[tokio::test]
async fn a_stored_snapshot_stripped_of_its_proof_is_absent() {
    let minio = start_minio().await;
    ensure_public_bucket(&minio).await;
    let store = S3SnapshotStore::new(config(&minio));

    let as_of = Utc::now().trunc_subsecs(0);
    let valid_until = as_of + Duration::days(7);
    let (_dir, mut document, key) = signed_snapshot(as_of, valid_until);
    document
        .as_object_mut()
        .expect("object")
        .remove("snapshotJwsSignature");
    let dpp_id = "0198f000-0000-7000-8000-000000000001";

    store
        .put_public_json(
            dpp_id,
            &serde_json::to_vec(&document).expect("serialise"),
            SnapshotMeta {
                as_of,
                valid_until,
                max_age: std::time::Duration::from_secs(86_400),
            },
        )
        .await
        .expect("store the snapshot");

    let url = format!(
        "{}/{}/{}",
        minio.endpoint,
        minio.bucket,
        snapshot_json_key(dpp_id)
    );
    let fetched: serde_json::Value = reqwest::get(&url)
        .await
        .expect("fetch")
        .json()
        .await
        .expect("the object is JSON");

    let bound = dpp_vc::verify_snapshot_bound(&fetched, &key, as_of);

    assert_eq!(
        bound,
        dpp_vc::SnapshotBound::Absent,
        "a stripped proof is Absent, never Current — the dates are still there \
         and nothing vouches for them"
    );
    // The metadata still claims a live window. That is exactly why the
    // signature, not the header, is what a reader must go by.
    assert!(
        fetched["validUntil"].is_string(),
        "the dates survive the edit, which is the point"
    );
}
