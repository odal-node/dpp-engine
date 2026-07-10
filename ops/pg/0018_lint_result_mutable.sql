-- 0018_lint_result_mutable.sql
-- Add `lintResult` to the retention guard's mutable_keys.
--
-- `lintResult` is advisory only — it never gates
-- publish and is designed to be re-checked on demand via `POST
-- /dpp/{dppId}/lint`, including against an already-published passport. Unlike
-- `complianceResult`, it is not part of the signed payload (the JWS is a
-- frozen signature over whatever `lintResult` looked like at publish time —
-- evidence export reads that frozen snapshot, not the live row), so a
-- retention-locked passport must be allowed to change it. Keep this array in
-- lockstep with `dpp_common::event_codes::MUTABLE_FIELDS` (the dpp-resolver
-- parity test asserts they match).

CREATE OR REPLACE FUNCTION odal.passport_retention_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
  mutable_keys TEXT[] := ARRAY['status','jwsSignature','publicJwsSignature',
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
