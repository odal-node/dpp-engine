-- ============================================================================
-- 0006 — registry_sync: transactional outbox for EU Central Registry
-- registration (written in the publish transaction; drained with backoff).
-- FK → passport (0004). Single-tenant: no `operator_id` column.
-- ============================================================================

CREATE TABLE odal.registry_sync (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  passport_id     UUID NOT NULL UNIQUE REFERENCES odal.passport(id),
  registry_id     TEXT,
  status          TEXT NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending','registered','rejected','suspended','deactivated')),
  payload         JSONB,
  message         TEXT,
  attempts        INTEGER NOT NULL DEFAULT 0,
  next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_attempt_at TIMESTAMPTZ,
  registered_at   TIMESTAMPTZ,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_regsync_due ON odal.registry_sync (next_attempt_at) WHERE status = 'pending';
