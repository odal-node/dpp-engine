-- ============================================================================
-- 0029 — registry_transfer: transactional outbox for EU Central Registry
-- transfer-of-responsibility notifications (written in the accept transaction;
-- drained with backoff).
--
-- The key is `transfer_id`, NOT `passport_id`. This is the one structural
-- difference from registry_sync (0006) and it is load-bearing: a passport is
-- registered once but changes hands many times over its life — sale, import,
-- remanufacturing, repurposing. Keying by passport would collapse every
-- handover onto one row, so each new transfer would overwrite the notification
-- for the previous one and the registry would only ever hear about the last.
-- A `TransferRecord` already carries its own id, so the row key is free.
--
-- `payload` holds the serialised `TransferRecord`: both operators, the reason,
-- and the two JWS signatures by which the outgoing and incoming operators
-- authorised the handover. The drain rebuilds the notification from it without
-- re-reading the chain.
--
-- FK -> passport (0004). Single-tenant: no `operator_id` column.
-- ============================================================================

CREATE TABLE odal.registry_transfer (
  transfer_id     UUID PRIMARY KEY,
  passport_id     UUID NOT NULL REFERENCES odal.passport(id),
  status          TEXT NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending','notified','rejected')),
  payload         JSONB NOT NULL,
  registry_id     TEXT,
  message         TEXT,
  attempts        INTEGER NOT NULL DEFAULT 0,
  next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_attempt_at TIMESTAMPTZ,
  notified_at     TIMESTAMPTZ,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- The drain's only query: oldest due rows first.
CREATE INDEX idx_regtransfer_due
  ON odal.registry_transfer (next_attempt_at) WHERE status = 'pending';

-- Every notification owed for one passport, for reconciliation and inspection.
CREATE INDEX idx_regtransfer_passport ON odal.registry_transfer (passport_id);

-- 0010's ALL-TABLES grant was a one-time snapshot; tables added later need their
-- own grant (same pattern as 0017/0021/0022/0023/0028). No DELETE: a rejected
-- row is the record that a transfer went unnotified, and is kept for audit.
GRANT SELECT, INSERT, UPDATE ON odal.registry_transfer TO odal_app;
