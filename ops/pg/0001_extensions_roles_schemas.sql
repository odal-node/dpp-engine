-- ============================================================================
-- 0001 — schemas, extensions, and the application role.
-- Clean ordered migration set (one logical unit per file, FK-dependency order).
-- Single-tenant: no Row-Level Security — one operator per node, so there is no
-- in-process isolation boundary (tenant isolation is an infrastructure concern).
-- Apply with sqlx::migrate! — never by hand in prod.
-- ============================================================================

CREATE SCHEMA IF NOT EXISTS odal;
CREATE SCHEMA IF NOT EXISTS identity;

CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- App connects as odal_app (no DDL; one sanctioned DELETE); migrations run as
-- the owning role. This migration only guarantees the role EXISTS — it never
-- sets a password (secrets stay out of version control). The password is set by
-- exactly one ops layer depending on environment:
--   • bundled container → docker/pg-init.sh (image init, from DATABASE_APP_PASS)
--   • managed/external  → ops/bootstrap/bootstrap.sql (run once before first boot)
-- Re-running this is harmless: it no-ops if the role already exists.
DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'odal_app') THEN
    CREATE ROLE odal_app LOGIN;
  END IF;
END $$;
