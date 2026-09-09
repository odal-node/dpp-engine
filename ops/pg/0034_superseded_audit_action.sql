-- ============================================================================
-- 0034 — admit the `superseded` audit action.
--
-- `superseded` has been a legal passport status since 0004 and survived every
-- widening of `passport_status_check` since, but no audit action was ever added
-- to match: nothing could reach the state, so nothing ever recorded reaching it.
-- Correcting a published passport now issues a successor and moves the
-- predecessor to `superseded`, and that transition is exactly the kind the trail
-- exists to hold — it is the only record of *why* a passport stopped being
-- current and *which* passport replaced it, both carried in the entry's
-- metadata (`successorId`, `reason`).
--
-- The append-only trigger and hash chain are unchanged.
-- ============================================================================

ALTER TABLE odal.passport_audit DROP CONSTRAINT passport_audit_action_check;
ALTER TABLE odal.passport_audit ADD CONSTRAINT passport_audit_action_check
  CHECK (action IN (
    'created',
    'updated',
    'published',
    'suspended',
    'archived',
    'deactivated',
    'transferred',
    'credentialed_read',
    'superseded'
  ));
