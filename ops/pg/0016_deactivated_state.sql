-- ============================================================================
-- 0016 — end-of-life `deactivated` state.
--
-- Widen the passport status and audit action CHECK constraints to admit the
-- terminal `deactivated` state and its audit action. The passport is retained
-- (the DPP outlives the product, EN 18221) — deactivation is a status
-- transition, never a delete. The typed EOL reason is stored in the audit
-- entry's metadata (dpp_domain::domain::eol::EolEvent).
-- ============================================================================

ALTER TABLE odal.passport DROP CONSTRAINT passport_status_check;
ALTER TABLE odal.passport ADD CONSTRAINT passport_status_check
  CHECK (status IN ('draft','active','suspended','archived','superseded','deactivated'));

ALTER TABLE odal.passport_audit DROP CONSTRAINT passport_audit_action_check;
ALTER TABLE odal.passport_audit ADD CONSTRAINT passport_audit_action_check
  CHECK (action IN ('created','updated','published','suspended','archived','deactivated'));
