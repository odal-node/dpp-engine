-- ============================================================================
-- 0010 — grants. Single-tenant: NO Row-Level Security — one operator per node,
-- so there is no in-process isolation boundary (tenant isolation is an
-- infrastructure concern). The app role still cannot run DDL or DELETE, except
-- the one sanctioned import-job cleanup path.
-- ============================================================================

GRANT USAGE ON SCHEMA odal, identity TO odal_app;
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA odal TO odal_app;
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA identity TO odal_app;
-- no DELETE grants: deletion is structurally impossible for the app role
GRANT DELETE ON odal.import_job TO odal_app;   -- the one sanctioned cleanup path
