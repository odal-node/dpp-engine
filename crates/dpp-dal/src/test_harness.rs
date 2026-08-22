//! One throwaway-Postgres harness, shared by every integration suite that needs
//! a database.
//!
//! # Why it is shared at all
//!
//! Rust cannot share `#[cfg(test)]` code across crate boundaries, so a
//! `mod helpers` in one suite is invisible to the next. That is why `start_pg`
//! was copied into eight files instead of being written once — and by the time
//! it was extracted, those eight copies had already drifted into **six**
//! distinct implementations of the same fifteen lines.
//!
//! The cost was never aesthetic. Each copy carried its own hardcoded readiness
//! sleep, so getting the bootstrap sequence right was eight independent
//! problems; and a change to it — a new role grant, a different image pin —
//! meant eight edits or seven silent divergences.
//!
//! # Why it lives in `dpp-dal` and not its own crate
//!
//! Every consumer already depends on `dpp-dal`: this crate's own suites, and
//! `dpp-node`'s five. A crate holding one function for callers who could
//! already see it earns nothing, and the workspace takes no crate fission
//! before 1.0.
//!
//! Gated behind `test-harness`, off by default. `dpp-dal` is `publish = false`,
//! so this ships nowhere regardless; the feature keeps `testcontainers` and a
//! container-spawning API out of every ordinary build of the DAL. Nothing
//! outside a `[dev-dependencies]` entry may enable it.

use crate::pg::{PgDal, sqlx};
use testcontainers::{
    ContainerAsync, GenericImage, ImageExt,
    core::{WaitFor, ports::ContainerPort},
    runners::AsyncRunner,
};

/// The image every suite tests against. One constant, so a pin bump is one edit.
const POSTGRES_IMAGE: (&str, &str) = ("postgres", "17");

/// How long to wait after the container reports ready before connecting.
///
/// Postgres restarts once during first-time init, so the readiness line on
/// stderr appears *before* the server is actually reachable. Connecting into
/// that window fails, which is why every copy of this harness carried a sleep.
const POST_INIT_SETTLE: std::time::Duration = std::time::Duration::from_millis(1500);

/// A running Postgres with the app role provisioned and no migrations applied.
///
/// The building block. Suites that want the ordinary arrangement should call
/// [`start_pg`]; this exists for the ones that need to control which migrations
/// run, such as a test of a migration itself.
pub struct RawPg {
    /// Superuser connection URL — DDL, raw trigger assertions, migrations.
    pub admin_url: String,
    /// Application-role URL. `odal_app` has no DDL and a narrow DELETE set, so
    /// a test connecting as this role exercises the privileges production has.
    pub app_url: String,
    /// Held so the container outlives the test; dropping it stops the container.
    pub container: ContainerAsync<GenericImage>,
}

/// A running Postgres with every migration applied and a connected [`PgDal`].
pub struct TestPg {
    /// Connected as `odal_app`, the role production uses.
    pub dal: PgDal,
    /// Superuser URL, kept for assertions that need to bypass the app role —
    /// checking that a trigger fired, or that an append-only table refuses.
    pub admin_url: String,
    /// Application-role URL, for a suite that opens its own pool.
    pub app_url: String,
    _container: ContainerAsync<GenericImage>,
}

/// Start Postgres and provision the `odal_app` role. No migrations.
///
/// The role is created exactly as `ops/bootstrap/pg-init.sh` does, so a suite
/// meets the same privilege boundary a deployed node does.
pub async fn start_pg_raw() -> RawPg {
    let image = GenericImage::new(POSTGRES_IMAGE.0, POSTGRES_IMAGE.1)
        .with_exposed_port(ContainerPort::Tcp(5432))
        .with_wait_for(WaitFor::message_on_stderr(
            "database system is ready to accept connections",
        ))
        // The official Postgres image's own required env vars for a throwaway
        // container — NOT the app's DATABASE_POSTGRES_PASS / DATABASE_APP_PASS
        // scheme, which these deliberately do not mirror.
        .with_env_var("POSTGRES_USER", "postgres")
        .with_env_var("POSTGRES_PASSWORD", "test")
        .with_env_var("POSTGRES_DB", "odal");

    let container = image.start().await.expect("start postgres container");
    let port = container
        .get_host_port_ipv4(5432)
        .await
        .expect("mapped port");
    let admin_url = format!("postgres://postgres:test@127.0.0.1:{port}/odal");
    let app_url = format!("postgres://odal_app:test@127.0.0.1:{port}/odal");

    tokio::time::sleep(POST_INIT_SETTLE).await;

    let admin = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&admin_url)
        .await
        .expect("admin connect");
    sqlx::query("CREATE ROLE odal_app LOGIN PASSWORD 'test'")
        .execute(&admin)
        .await
        .expect("create app role");
    admin.close().await;

    RawPg {
        admin_url,
        app_url,
        container,
    }
}

/// Start Postgres, apply every migration, and connect as `odal_app`.
///
/// Migrations need DDL, so they run through the admin URL; the returned
/// [`PgDal`] then connects as the app role without re-running them, which
/// mirrors the ops workflow.
pub async fn start_pg() -> TestPg {
    let raw = start_pg_raw().await;

    PgDal::migrate(&raw.admin_url)
        .await
        .expect("apply migrations via admin");

    let dal = PgDal::connect(&raw.app_url).await.expect("app connect");

    TestPg {
        dal,
        admin_url: raw.admin_url,
        app_url: raw.app_url,
        _container: raw.container,
    }
}

/// Start Postgres and apply migrations in order, stopping **before** the first
/// whose filename begins with `stop_before`.
///
/// For testing a migration itself: bring the schema to the state that existed
/// just before it, then apply it and assert what it did.
///
/// # Panics
///
/// If `stop_before` matches no migration. A test pinned to a prefix that no
/// longer exists would otherwise apply every migration and silently assert
/// nothing — the failure mode this whole crate exists to reduce.
pub async fn start_pg_before(stop_before: &str) -> RawPg {
    let raw = start_pg_raw().await;

    let admin = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&raw.admin_url)
        .await
        .expect("admin connect");

    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../ops/pg");
    let mut files: Vec<_> = std::fs::read_dir(dir)
        .expect("read ops/pg")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "sql"))
        .collect();
    files.sort();

    let mut stopped = false;
    for path in files {
        let name = path.file_name().unwrap_or_default().to_string_lossy();
        if name.starts_with(stop_before) {
            stopped = true;
            break;
        }
        let sql = std::fs::read_to_string(&path).expect("read migration");
        // Repo-controlled migration text from ops/pg, never caller input.
        sqlx::raw_sql(sqlx::AssertSqlSafe(sql))
            .execute(&admin)
            .await
            .unwrap_or_else(|e| panic!("apply {name}: {e}"));
    }
    admin.close().await;

    assert!(
        stopped,
        "no migration in ops/pg starts with '{stop_before}', so every migration was \
         applied and the test would assert against the wrong schema"
    );

    raw
}
