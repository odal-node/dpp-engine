-- 0011_public_jws_mutable.sql
-- Add `publicJwsSignature` to the retention guard's mutable_keys.
--
-- `publicJwsSignature` is the JWS over the public (redacted) passport view that
-- the resolver verifies. Like `jwsSignature`, it is (re)written at every publish
-- (including a suspend → re-publish cycle, where the operator may have rotated
-- keys), so a retention-locked passport must be allowed to change it. Keep this
-- array in lockstep with `dpp_common::event_codes::MUTABLE_FIELDS` (the
-- dpp-resolver parity test asserts they match).

CREATE OR REPLACE FUNCTION odal.passport_retention_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
  mutable_keys TEXT[] := ARRAY['status','jwsSignature','publicJwsSignature',
                               'qrCodeUrl','publishedAt','retentionLocked','updatedAt'];
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
