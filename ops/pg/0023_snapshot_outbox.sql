-- ============================================================================
-- 0023 — snapshot_outbox: durable reconcile queue for the static continuity
-- tier (pre-rendered public views mirrored to object storage).
--
-- A row means "this passport's public state changed — go reconcile it", NOT
-- "put it" or "remove it". The drain reads the passport's *current* status and
-- derives the action (Published -> put the rendered public view; anything else
-- -> remove). That convergence is deliberate: an explicit put/remove op column
-- lets a stale `put` land after a `remove` on retry or out-of-order drain and
-- resurrect a suspended passport's snapshot in the public tier — the exact
-- failure the tier exists to prevent. A convergent row always drives toward
-- whatever the database currently says, so replays and duplicates are harmless.
--
-- One row per passport (`passport_id UNIQUE`, as in registry_sync): a pending
-- reconcile is idempotent, so a second state change while one is still queued
-- re-arms that row rather than stacking another. FK -> passport (0004).
-- Single-tenant: no `operator_id` column.
-- ============================================================================

CREATE TABLE odal.snapshot_outbox (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  passport_id     UUID NOT NULL UNIQUE REFERENCES odal.passport(id),
  status          TEXT NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending','reconciled','exhausted')),
  attempts        INTEGER NOT NULL DEFAULT 0,
  next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_attempt_at TIMESTAMPTZ,
  message         TEXT,
  reconciled_at   TIMESTAMPTZ,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_snapshot_outbox_due
  ON odal.snapshot_outbox (next_attempt_at) WHERE status = 'pending';

-- 0010's ALL-TABLES grant was a one-time snapshot; tables added later need their
-- own grant (same pattern as 0017/0021/0022). No DELETE: a reconciled row is
-- retained and re-armed in place by the next state change.
GRANT SELECT, INSERT, UPDATE ON odal.snapshot_outbox TO odal_app;
