-- ============================================================================
-- 0034 — `superseded` audit action.
--
-- `0016` widened the passport *status* constraint to admit `superseded`
-- alongside `deactivated`, but left the audit action list without it — the
-- status became storable while the entry recording the transition did not.
-- Nothing noticed because nothing produced the transition: `supersedes_id` was
-- never written and no code path set the status, so the gap sat behind a
-- lifecycle state that could not be reached.
--
-- Producing it surfaced the gap immediately, and in the worst shape: the status
-- write committed and the audit append then failed the constraint, leaving a
-- retired passport with no entry saying who retired it.
--
-- The list is restated in full rather than added to, because `ADD CONSTRAINT`
-- replaces it; every prior entry is carried forward deliberately.
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
