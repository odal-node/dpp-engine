-- ============================================================================
-- 0012 — let the app role manage facilities and operator identifiers via the
-- API/CLI control plane. These are operator-config records (not audited like
-- passports or api_keys), so a hard DELETE is acceptable. SELECT/INSERT/UPDATE
-- were already granted on all odal tables in 0010; only DELETE was withheld.
-- ============================================================================

GRANT DELETE ON odal.facility TO odal_app;
GRANT DELETE ON odal.operator_identifier TO odal_app;
