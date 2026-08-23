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

/// Point this at a running Postgres and [`start_pg`] will clone a database on
/// it instead of starting a container.
///
/// # Why this exists
///
/// [`start_pg`] started a fresh `postgres:17` per call, and it is called from
/// 61 places. Measured across the workspace, **171 tests consumed 86% of all
/// test time** at 12–16s apiece — almost all of it container boot, the settle
/// above, and re-running every migration.
///
/// The obvious fix — start one container and share it in a `OnceLock` — does
/// not work: **nextest runs each test in its own process**, confirmed by two
/// tests in one binary reporting two PIDs. So the server has to outlive the
/// test process and be found through the environment.
///
/// Set it to a superuser URL on a database that already exists (`.../postgres`
/// is fine). The harness does the rest, idempotently and safely across
/// concurrent test processes.
///
/// Unset, everything behaves exactly as before — a bare `cargo nextest run`
/// still works, just slowly.
const SHARED_ADMIN_URL_ENV: &str = "ODAL_TEST_PG_ADMIN_URL";

/// The migrated database every per-test database is cloned from.
const TEMPLATE_DB: &str = "odal_test_template";

/// Advisory-lock key serialising template creation across test processes.
///
/// Arbitrary but fixed. Postgres advisory locks are per-cluster, which is
/// exactly the scope needed: many processes, one server, one template.
const TEMPLATE_LOCK_KEY: i64 = 0x0DA1_7E57_0DA1_7E57_u64 as i64;

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
    /// The container this test owns, when it started one.
    ///
    /// `None` on the shared-server path: that server outlives the process, so
    /// there is nothing here to keep alive. Held only so dropping `TestPg`
    /// stops a container the test did start.
    _container: Option<ContainerAsync<GenericImage>>,
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
    if let Ok(admin_url) = std::env::var(SHARED_ADMIN_URL_ENV)
        && !admin_url.trim().is_empty()
    {
        return clone_from_template(admin_url.trim()).await;
    }

    let raw = start_pg_raw().await;

    PgDal::migrate(&raw.admin_url)
        .await
        .expect("apply migrations via admin");

    let dal = PgDal::connect(&raw.app_url).await.expect("app connect");

    TestPg {
        dal,
        admin_url: raw.admin_url,
        app_url: raw.app_url,
        _container: Some(raw.container),
    }
}

/// Swap the database name in a Postgres URL.
fn with_database(url: &str, database: &str) -> String {
    let base = url.split('?').next().unwrap_or(url);
    let trimmed = base.trim_end_matches('/');
    match trimmed.rfind('/') {
        Some(i) => format!("{}/{database}", &trimmed[..i]),
        None => format!("{trimmed}/{database}"),
    }
}

/// Give this test its own database, cloned from the migrated template.
///
/// `CREATE DATABASE ... TEMPLATE` is a file copy inside Postgres — measured at
/// roughly 190ms here, against 12–16s to boot a container and migrate it.
async fn clone_from_template(admin_url: &str) -> TestPg {
    ensure_template(admin_url).await;

    // Short and unique. Postgres caps identifiers at 63 bytes, and a full UUID
    // with its hyphens would need quoting everywhere it appears in a log.
    let suffix = uuid::Uuid::now_v7().simple().to_string();
    let db = format!("odal_test_{}", &suffix[..16]);

    let admin = connect_admin(admin_url).await;
    // Identifiers cannot be bound as parameters, and this name is built from a
    // UUID above rather than from anything a caller supplies.
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
        r#"CREATE DATABASE "{db}" TEMPLATE "{TEMPLATE_DB}""#
    )))
    .execute(&admin)
    .await
    .unwrap_or_else(|e| panic!("clone {TEMPLATE_DB} into {db}: {e}"));
    admin.close().await;

    let test_admin_url = with_database(admin_url, &db);
    let app_url = app_url_for(&test_admin_url);
    let dal = PgDal::connect(&app_url).await.expect("app connect");

    TestPg {
        dal,
        admin_url: test_admin_url,
        app_url,
        _container: None,
    }
}

/// The app-role URL for a database, derived from its superuser URL.
///
/// The role and password are the harness's own fixed pair, matching what
/// [`start_pg_raw`] provisions — not anything read from the environment.
fn app_url_for(admin_url: &str) -> String {
    let after_scheme = admin_url.split("://").nth(1).unwrap_or(admin_url);
    let host_and_db = after_scheme
        .split_once('@')
        .map_or(after_scheme, |(_, rest)| rest);
    format!("postgres://odal_app:test@{host_and_db}")
}

/// Create the `odal_app` role and the migrated template, once per server.
///
/// Guarded by a Postgres advisory lock rather than a process-local `Once`,
/// because the racing parties are separate processes: nextest runs every test
/// in its own. The first to take the lock builds the template and the rest wait
/// and then find it already there.
async fn ensure_template(admin_url: &str) {
    let admin = connect_admin(admin_url).await;

    sqlx::query("SELECT pg_advisory_lock($1)")
        .bind(TEMPLATE_LOCK_KEY)
        .execute(&admin)
        .await
        .expect("take template lock");

    let exists: Option<i32> = sqlx::query_scalar("SELECT 1 FROM pg_database WHERE datname = $1")
        .bind(TEMPLATE_DB)
        .fetch_optional(&admin)
        .await
        .expect("look up template");

    if exists.is_none() {
        // Provisioned exactly as `ops/bootstrap/pg-init.sh` does, so a suite
        // meets the same privilege boundary a deployed node does. Ignore the
        // duplicate error: the role is cluster-wide and may predate us.
        let _ = sqlx::query("CREATE ROLE odal_app LOGIN PASSWORD 'test'")
            .execute(&admin)
            .await;

        sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
            r#"CREATE DATABASE "{TEMPLATE_DB}""#
        )))
        .execute(&admin)
        .await
        .expect("create template database");

        // Migrate through its own pool, then close it. `CREATE DATABASE ...
        // TEMPLATE` refuses while anything is connected to the template, so
        // leaving this pool open would break every clone that follows.
        let template_url = with_database(admin_url, TEMPLATE_DB);
        PgDal::migrate(&template_url)
            .await
            .expect("migrate template database");
    }

    sqlx::query("SELECT pg_advisory_unlock($1)")
        .bind(TEMPLATE_LOCK_KEY)
        .execute(&admin)
        .await
        .expect("release template lock");
    admin.close().await;
}

async fn connect_admin(url: &str) -> sqlx::PgPool {
    sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(url)
        .await
        .unwrap_or_else(|e| panic!("admin connect to {url}: {e}"))
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
