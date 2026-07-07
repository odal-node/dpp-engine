//! Migration → repo drift guard.
//!
//! Pure filesystem check — no Docker/Postgres required, runs in the fast
//! `cargo nextest run --workspace` gate. Every table created in
//! `ops/pg/*.sql` must be referenced (schema-qualified) somewhere under
//! `src/pg/`, or be listed below as a documented, deliberate exception. This
//! catches the class of bug where a migration ships a table nobody wires up
//! — a table nobody reads for weeks is a silent schema drift, not a feature.

use std::fs;
use std::path::Path;

/// `"schema.table"` entries intentionally NOT referenced anywhere under
/// `src/pg/`, with why. Keep this list honest — it's a drift log, not a
/// place to silence the guard.
const DOCUMENTED_EXCEPTIONS: &[(&str, &str)] = &[
    (
        "odal.import_job",
        "owned by dpp-node::infra::pg_job_store (PgJobStore), not dpp-dal — the job \
         store is node-side infrastructure (see docs/agent/CLAUDE.md's Job Store section).",
    ),
    (
        "odal.unsold_goods_report",
        "schema seat for the not-yet-built unsold-goods bulk-import feature in \
         dpp-integrator; no repo reads or writes it yet.",
    ),
    (
        "identity.did_document",
        "dead schema found while adding this guard: dpp-identity's KeyStore \
         (dpp_crypto::keystore) is a local AES-256-GCM encrypted FILE, not \
         Postgres-backed — this table is never queried by any crate in the \
         workspace. Flagged here, not dropped or wired up, since removing/using a \
         live migration is a schema decision outside a structural-refactor pass.",
    ),
    (
        "identity.key_pair",
        "dead schema, same reason as identity.did_document — never queried by any \
         crate in the workspace.",
    ),
];

/// Extract every `schema.table` named in a `CREATE TABLE schema.table (` statement.
fn tables_created_in(sql: &str) -> Vec<String> {
    sql.lines()
        .filter_map(|line| {
            let rest = line.trim_start().strip_prefix("CREATE TABLE ")?;
            let name = rest.split(|c: char| c.is_whitespace() || c == '(').next()?;
            (!name.is_empty()).then(|| name.to_owned())
        })
        .collect()
}

#[test]
fn every_migration_table_has_a_repo_or_a_documented_exception() {
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let migrations_dir = workspace_root.join("ops/pg");
    let pg_src_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/pg");

    let mut migration_files: Vec<_> = fs::read_dir(&migrations_dir)
        .expect("read ops/pg")
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|ext| ext == "sql"))
        .collect();
    migration_files.sort();
    assert!(
        !migration_files.is_empty(),
        "expected migration files under ops/pg"
    );

    let repo_source: String = fs::read_dir(&pg_src_dir)
        .expect("read crates/dpp-dal/src/pg")
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|ext| ext == "rs"))
        .map(|p| fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {p:?}: {e}")))
        .collect();

    let mut undocumented = Vec::new();
    for path in &migration_files {
        let sql = fs::read_to_string(path).unwrap_or_else(|e| panic!("read {path:?}: {e}"));
        for table in tables_created_in(&sql) {
            let is_referenced = repo_source.contains(&table);
            let is_documented = DOCUMENTED_EXCEPTIONS.iter().any(|(t, _)| *t == table);
            if !is_referenced && !is_documented {
                undocumented.push(format!("{table} (created in {})", path.display()));
            }
        }
    }

    assert!(
        undocumented.is_empty(),
        "table(s) created in a migration with no repo reference under src/pg/ and no \
         documented exception in this test — either wire up a repo or add an entry to \
         DOCUMENTED_EXCEPTIONS explaining why not:\n{}",
        undocumented.join("\n")
    );
}
