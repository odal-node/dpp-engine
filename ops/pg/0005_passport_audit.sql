-- ============================================================================
-- 0005 — passport_audit. Append-only by trigger. Single-tenant: no
-- `operator_id` column — `actor` carries who performed the action.
-- ============================================================================

CREATE TABLE odal.passport_audit (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  passport_id     TEXT NOT NULL,
  actor           TEXT NOT NULL,
  actor_user_id   UUID,
  action          TEXT NOT NULL
                    CHECK (action IN ('created','updated','published','suspended','archived')),
  previous_status TEXT,
  new_status      TEXT,
  request_id      TEXT,
  changes         JSONB,
  metadata        JSONB,
  ts              TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_audit_passport      ON odal.passport_audit (passport_id);
CREATE INDEX idx_audit_passport_time ON odal.passport_audit (passport_id, ts);

CREATE FUNCTION odal.audit_append_only() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'ODAL_AUDIT: audit entries are append-only';
END $$;
CREATE TRIGGER audit_immutable
  BEFORE UPDATE OR DELETE ON odal.passport_audit
  FOR EACH ROW EXECUTE FUNCTION odal.audit_append_only();
