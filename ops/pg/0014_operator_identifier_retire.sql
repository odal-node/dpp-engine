-- ============================================================================
-- 0014 — operator identifiers (ESPR Art. 13) get the same provenance protection
-- as facilities (0013): their value is stamped by value onto immutable, signed
-- passports (doc.operatorIdentifier), so an identifier that has ever been
-- referenced must never be destroyed. This supersedes 0012's DELETE grant:
--   * identifiers are RETIRED (retired_at), never hard-deleted;
--   * the DELETE grant from 0012 is revoked;
--   * mutations already flow into the append-only odal.registry_identity_audit
--     table from 0013 (entity_type = 'operator_identifier').
-- ============================================================================

-- Soft-delete marker. NULL = live; set = retired (row kept for provenance).
ALTER TABLE odal.operator_identifier ADD COLUMN retired_at TIMESTAMPTZ;

-- The 0002 UNIQUE (operator_id, scheme, value) blocked ever re-adding a retired
-- identifier. Scope uniqueness to LIVE rows so a retired identifier can be
-- re-registered, while two live identifiers still cannot collide.
ALTER TABLE odal.operator_identifier
  DROP CONSTRAINT operator_identifier_operator_id_scheme_value_key;
CREATE UNIQUE INDEX uq_operator_identifier_live
  ON odal.operator_identifier (operator_id, scheme, value)
  WHERE retired_at IS NULL;

-- Deletion is no longer sanctioned (undo 0012). Retirement is an UPDATE, which
-- the app role already holds from 0010.
REVOKE DELETE ON odal.operator_identifier FROM odal_app;
