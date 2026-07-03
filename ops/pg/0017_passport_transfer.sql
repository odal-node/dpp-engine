-- ============================================================================
-- 0017 — transfer of responsibility chain.
--
-- One dual-signed transfer chain per passport (append-only in the domain type;
-- persisted as JSONB). The outgoing operator's `from_signature` and the incoming
-- operator's `to_signature` are both JWS over the same canonical
-- `TransferRecord::signing_payload()`, so the handover terms are cryptographically
-- bound. Also admits the `transferred` audit action.
-- ============================================================================

CREATE TABLE odal.passport_transfer (
  passport_id UUID PRIMARY KEY REFERENCES odal.passport(id),
  chain       JSONB NOT NULL,
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 0010's ALL-TABLES grant was a one-time snapshot; tables added later need their
-- own grant for the app role (same pattern as 0013).
GRANT SELECT, INSERT, UPDATE ON odal.passport_transfer TO odal_app;

ALTER TABLE odal.passport_audit DROP CONSTRAINT passport_audit_action_check;
ALTER TABLE odal.passport_audit ADD CONSTRAINT passport_audit_action_check
  CHECK (action IN ('created','updated','published','suspended','archived','deactivated','transferred'));
