-- ============================================================================
-- 0028 — seal_outbox: durable queue for eIDAS qualified sealing, and the
-- retention-guard change that lets a seal be written after publish.
--
-- Sealing is a paid call to a third-party QTSP aggregator, so it is not in the
-- publish path: coupling every publish to that provider's availability would
-- trade a missing seal (visible, repairable) for a blocked regulatory
-- obligation (neither). Publish commits and enqueues; the drain seals.
--
-- Unlike registry_sync and snapshot_outbox, the key is
-- `(passport_id, payload_hash)`, NOT `passport_id` alone. A row is one specific
-- attestation over one specific digest, and a re-publish re-signs the passport,
-- producing a new `jwsSignature`, a new digest, and therefore a legitimately
-- new seal to buy. Collapsing those onto one row per passport would silently
-- leave a re-published passport carrying a seal over its previous signature.
-- The unique key is what makes a retried enqueue of *unchanged* content free.
--
-- FK -> passport (0004). Single-tenant: no `operator_id` column.
-- ============================================================================

CREATE TABLE odal.seal_outbox (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  passport_id     UUID NOT NULL REFERENCES odal.passport(id),
  -- Hex SHA-256 of the passport's jwsSignature compact string: the digest the
  -- QTSP seals. 64 hex chars, pinned so a non-digest cannot be queued.
  payload_hash    TEXT NOT NULL CHECK (payload_hash ~ '^[0-9a-f]{64}$'),
  status          TEXT NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending','sealed','exhausted')),
  attempts        INTEGER NOT NULL DEFAULT 0,
  next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_attempt_at TIMESTAMPTZ,
  message         TEXT,
  sealed_at       TIMESTAMPTZ,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (passport_id, payload_hash)
);
CREATE INDEX idx_seal_outbox_due
  ON odal.seal_outbox (next_attempt_at) WHERE status = 'pending';

-- 0010's ALL-TABLES grant was a one-time snapshot; tables added later need their
-- own grant (same pattern as 0017/0021/0022/0023). No DELETE: an exhausted row
-- is the record that a published passport went unsealed, and is kept.
GRANT SELECT, INSERT, UPDATE ON odal.seal_outbox TO odal_app;

-- ── retention guard: `seal` joins mutable_keys ──────────────────────────────
--
-- The seal is written onto an already-published, already-retention-locked row,
-- so without this the guard refuses the drain's update as an illegal content
-- change and no passport is ever sealed.
--
-- This does not weaken immutability, for the same reason the signature fields
-- do not (0027). What the guard protects is passport *content*; a seal is a
-- statement *about* content frozen at a publish — here, a QTSP attesting that
-- the operator's `jwsSignature` existed at a point in time. It is a proof
-- field, and every other proof field is already listed here.
--
-- Keep this array in lockstep with `dpp_common::event_codes::MUTABLE_FIELDS`
-- (the dpp-resolver parity test asserts they match).
-- ============================================================================

CREATE OR REPLACE FUNCTION odal.passport_retention_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
  mutable_keys TEXT[] := ARRAY['status','jwsSignature','publicJwsSignature',
                               'disclosureSignatures','seal',
                               'qrCodeUrl','publishedAt','retentionLocked',
                               'updatedAt','lintResult'];
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
