-- ============================================================================
-- bootstrap.sql — one-time database + login-role provisioning.
--
-- This runs BEFORE the sqlx migrations in ops/pg/ and is deliberately kept in a
-- SEPARATE directory (ops/bootstrap/) so the sqlx::migrate! macro — which scans
-- ops/pg/ — never treats it as a migration. It does the two things migrations
-- cannot:
--
--   1. CREATE DATABASE odal      — migrations run *inside* a database and inside
--      a transaction; CREATE DATABASE can do neither, so it must happen first.
--   2. Set the odal_app login password — migration 0001 creates the role
--      WITHOUT a password (passwords are an ops concern, never in version
--      control); this file sets it from the DATABASE_APP_PASS you pass in.
--
-- WHEN YOU NEED THIS
--   • Managed / external Postgres (RDS, Cloud SQL, a DBA-provisioned cluster):
--     run this once as a superuser before the first node boot.
--   • The bundled Postgres *container* runs this same file automatically: its
--     image entrypoint creates POSTGRES_DB=odal on first init, then the
--     ops/bootstrap/pg-init.sh hook invokes THIS script with DATABASE_APP_PASS
--     to seed the odal_app role. Same SQL, two entry points — no duplication.
--
-- HOW TO RUN (see `just db-bootstrap`)
--   psql "postgres://postgres:SUPERPASS@HOST:5432/postgres" \
--        -v app_pass="YOUR_DATABASE_APP_PASS" \
--        -f ops/bootstrap/bootstrap.sql
--   Pass the password RAW (no surrounding quotes) — the :'app_pass' operator
--   below quotes and escapes it. Pre-quoting it double-quotes and bakes literal
--   quotes into the password.
--   NOTE: connect to the maintenance DB ("postgres"), not "odal" — the target
--   DB may not exist yet.
--
-- Idempotent: safe to re-run. CREATE DATABASE is guarded by \gexec; the role is
-- created if missing and its password is (re)set every run.
-- ============================================================================

-- 1. Create the database if it does not already exist. ------------------------
-- CREATE DATABASE cannot run in a DO block or transaction and has no
-- IF NOT EXISTS, so we use the standard \gexec trick: build the statement as a
-- row only when the DB is absent, then execute that row.
SELECT 'CREATE DATABASE odal'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'odal')
\gexec

-- 2. Provision the application login role and set its password. ----------------
-- Reconnect to the freshly-ensured target database so the role and its
-- privileges live in the right place.
\connect odal

-- :'app_pass' quotes and escapes the RAW value passed via -v app_pass=... into
-- a safe SQL string literal (so do NOT pre-quote it at the call site).
-- Create the role if missing, then always (re)set the password so this file is
-- the single source of truth for the app credential on managed deploys.
DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'odal_app') THEN
    CREATE ROLE odal_app LOGIN;
  END IF;
END $$;

ALTER ROLE odal_app WITH LOGIN PASSWORD :'app_pass';

-- Schemas, tables, and grants are created by the numbered migrations (0001+),
-- applied next by the node via DATABASE_MIGRATE_URL (or `just migrate`).
-- Nothing else belongs here.
