//! Integration test: `PgJobStore` lifecycle against a real PostgreSQL instance.
//!
//! Guards the bug where `insert()` omitted the required `operatorId` field, so
//! the job record never persisted and import-job status returned `404` forever.
//! The node smoke test uses `InMemoryJobStore`, so this is the only place the
//! *production* store is exercised end to end.
//!
//! Run: `cargo test -p dpp-node --features integration-tests`

#![cfg(feature = "integration-tests")]

use testcontainers::{
    GenericImage, ImageExt,
    core::{WaitFor, ports::ContainerPort},
    runners::AsyncRunner,
};
use uuid::Uuid;

use dpp_dal::pg::{PgDal, sqlx};
use dpp_integrator::{
    domain::batch_runner::{BatchResult, CreatedItem, RowError},
    infra::job_store::{ImportJob, JobStatus, JobStore},
};
use dpp_node::infra::pg_job_store::PgJobStore;

async fn start_pg() -> (PgDal, testcontainers::ContainerAsync<GenericImage>) {
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

    PgDal::migrate(&admin_url).await.expect("apply migrations");

    let app_url = format!("postgres://odal_app:test@127.0.0.1:{port}/odal");
    let dal = PgDal::connect(&app_url).await.expect("app connect");
    (dal, container)
}

#[tokio::test(flavor = "multi_thread")]
async fn job_lifecycle_persists_and_is_retrievable() {
    let (dal, _container) = start_pg().await;
    let store = PgJobStore::new(dal);

    let id = Uuid::now_v7();

    store
        .insert(ImportJob::new(id, 150))
        .await
        .expect("insert must persist the job");

    let job = store
        .get(id)
        .await
        .expect("job retrievable right after insert");
    assert!(matches!(job.status, JobStatus::Queued));
    assert_eq!(job.total_rows, 150);

    store
        .set_status(id, JobStatus::Processing)
        .await
        .expect("set processing");
    assert!(matches!(
        store.get(id).await.unwrap().status,
        JobStatus::Processing
    ));

    let batch = BatchResult {
        created: vec![CreatedItem {
            row: 1,
            passport_id: Uuid::now_v7().to_string(),
        }],
        errors: vec![RowError {
            row: 2,
            field: "gtin".into(),
            message: "O'Brien said \"invalid\"".into(),
        }],
    };
    store.complete(id, batch).await.expect("complete job");

    let done = store.get(id).await.expect("completed job retrievable");
    assert!(matches!(done.status, JobStatus::Completed));
    assert_eq!(done.processed, 150);
    let result = done.result.expect("result populated on completion");
    assert_eq!(result.created.len(), 1);
    assert_eq!(result.errors.len(), 1);
    assert_eq!(
        result.errors[0].message, "O'Brien said \"invalid\"",
        "error message must survive SQL round-trip intact"
    );

    assert!(store.get(Uuid::now_v7()).await.is_none());
}
