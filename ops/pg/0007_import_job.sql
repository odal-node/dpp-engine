-- ============================================================================
-- 0007 — import_job: async CSV/XLSX bulk-import tracking (operational scratch
-- data; the one table the app role may DELETE — see 0010). Single-tenant: no
-- `operator_id` column.
-- ============================================================================

CREATE TABLE odal.import_job (
  id          UUID PRIMARY KEY,
  status      TEXT NOT NULL DEFAULT 'queued'
                CHECK (status IN ('queued','processing','completed','failed')),
  fail_reason TEXT,
  total_rows  INTEGER NOT NULL DEFAULT 0 CHECK (total_rows >= 0),
  processed   INTEGER NOT NULL DEFAULT 0,
  result      JSONB,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_import_job_status ON odal.import_job (status);
