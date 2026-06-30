-- ============================================================================
-- 0004 — passport. Document-style: full serde Passport JSON in `doc`,
-- query/constraint-bearing fields as real columns. Includes the 0.2 reserved
-- columns. Single-tenant: no `operator_id` column.
-- ============================================================================

CREATE TABLE odal.passport (
  id               UUID PRIMARY KEY,
  sector           TEXT NOT NULL,
  status           TEXT NOT NULL DEFAULT 'draft'
                     CHECK (status IN ('draft','active','suspended','archived','superseded')),
  retention_locked BOOLEAN NOT NULL DEFAULT false,
  schema_version   TEXT NOT NULL,
  -- 0.2 data-model columns (written by core >= 0.2; NULL/default until then):
  granularity      TEXT CHECK (granularity IN ('model','batch','item')),
  serial_number    TEXT,
  version          INTEGER NOT NULL DEFAULT 1,
  supersedes_id    UUID REFERENCES odal.passport(id),
  ruleset_version  TEXT,
  assessed_at      TIMESTAMPTZ,
  retention_until  TIMESTAMPTZ,
  product_id       UUID,
  template_version INTEGER,
  presentation_profile_id UUID,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  published_at     TIMESTAMPTZ,
  doc              JSONB NOT NULL
);
CREATE INDEX idx_passport_sector     ON odal.passport (sector);
CREATE INDEX idx_passport_status     ON odal.passport (status);
CREATE INDEX idx_passport_published  ON odal.passport (published_at);
CREATE INDEX idx_passport_supersedes ON odal.passport (supersedes_id);
CREATE INDEX idx_passport_name_trgm  ON odal.passport
  USING gin ((doc->>'productName') gin_trgm_ops);
CREATE INDEX idx_passport_batch_trgm ON odal.passport
  USING gin ((doc->>'batchId') gin_trgm_ops);

-- Retention guard (U-2). MUTABLE_KEYS must stay in sync with the resolver's
-- MUTABLE_FIELDS (dpp-resolver/src/infra/did.rs) — single conceptual constant.
-- co2ePerUnit/repairabilityScore/complianceResult are NOT mutable after lock:
-- they are part of the signed payload and the resolver enforces their integrity.
CREATE FUNCTION odal.passport_retention_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
  mutable_keys TEXT[] := ARRAY['status','jwsSignature','qrCodeUrl','publishedAt',
                               'retentionLocked','updatedAt'];
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'ODAL_RETENTION: passports are never deleted (ESPR retention)';
  END IF;
  IF OLD.retention_locked
     AND (OLD.doc - mutable_keys) IS DISTINCT FROM (NEW.doc - mutable_keys) THEN
    RAISE EXCEPTION 'ODAL_RETENTION: retention-locked passport content is immutable';
  END IF;
  NEW.updated_at := now();
  RETURN NEW;
END $$;
CREATE TRIGGER passport_retention
  BEFORE UPDATE OR DELETE ON odal.passport
  FOR EACH ROW EXECUTE FUNCTION odal.passport_retention_guard();
