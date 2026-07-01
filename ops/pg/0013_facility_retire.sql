-- ============================================================================
-- 0013 — facilities are ESPR Annex III provenance: a facility's identifier
-- value is stamped (by value) onto immutable, signed passports (doc.facilityId).
-- A facility that has ever been referenced must never be destroyed, and the
-- operator's facility history must stay reconstructable for market-surveillance
-- requests. This migration supersedes 0012's "a hard DELETE is acceptable":
--   * facilities are RETIRED (retired_at), never hard-deleted;
--   * the DELETE grant added in 0012 is revoked, so deletion is structurally
--     impossible for the app role (as with passports and api_keys);
--   * registry-identity mutations are recorded in an append-only audit table so
--     the Annex III / Art. 13 identity history is reconstructable.
-- (operator_identifier — stamped the same way, per Art. 13 — needs the identical
--  treatment in a follow-up; its DELETE grant is intentionally left for that.)
-- ============================================================================

-- Soft-delete marker. NULL = live; set = retired (row kept for provenance).
ALTER TABLE odal.facility ADD COLUMN retired_at TIMESTAMPTZ;

-- The 0002 UNIQUE (identifier_scheme, identifier_value) blocked ever re-adding a
-- retired identifier. Scope uniqueness to LIVE rows: a retired GLN can be
-- re-registered, while two live facilities still cannot share an identifier.
ALTER TABLE odal.facility
  DROP CONSTRAINT facility_identifier_scheme_identifier_value_key;
CREATE UNIQUE INDEX uq_facility_identifier_live
  ON odal.facility (identifier_scheme, identifier_value)
  WHERE retired_at IS NULL;

-- Deletion is no longer sanctioned for facilities (undo 0012). Retirement is an
-- UPDATE, which the app role already holds from 0010.
REVOKE DELETE ON odal.facility FROM odal_app;

-- Append-only history of registry-identity (Annex III facility / Art. 13
-- operator-identifier) mutations, so the operator can prove what their
-- facility / identifier set was at the time any passport was published.
CREATE TABLE odal.registry_identity_audit (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  operator_id TEXT NOT NULL,
  entity_type TEXT NOT NULL CHECK (entity_type IN ('facility','operator_identifier')),
  entity_id   UUID NOT NULL,
  action      TEXT NOT NULL
                CHECK (action IN ('added','retired','set_default','set_primary')),
  actor       TEXT NOT NULL,
  -- Full record at the time of the action, for reconstruction.
  snapshot    JSONB,
  ts          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_ri_audit_entity ON odal.registry_identity_audit (entity_type, entity_id, ts);

-- Reuse the append-only trigger function from 0005 — any UPDATE/DELETE raises.
CREATE TRIGGER ri_audit_immutable
  BEFORE UPDATE OR DELETE ON odal.registry_identity_audit
  FOR EACH ROW EXECUTE FUNCTION odal.audit_append_only();

-- 0010's blanket grant only covered tables that existed then; grant the app role
-- append + read on this new table (no UPDATE/DELETE — append-only).
GRANT SELECT, INSERT ON odal.registry_identity_audit TO odal_app;
