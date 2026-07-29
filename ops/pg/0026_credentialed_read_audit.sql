-- ============================================================================
-- 0026 — admit the `credentialed_read` audit action.
--
-- Until now every audit action was a *write*: the trail recorded what the
-- operator did to a passport. An access regime is honoured or breached on the
-- read side, so a credentialed read of a non-public view is itself an auditable
-- event — who vouched, for whom, and which disclosure classes were served.
--
-- Anonymous public reads are deliberately NOT recorded. They are the free,
-- unregistered baseline (ESPR Art. 11(b); the toy and detergent regulations
-- forbid requiring registration), and logging them would turn a public right
-- into a tracked event. Volume is also the reason: the public route is the
-- traffic path, and per-read audit rows there would swamp the chain.
--
-- The append-only trigger and hash chain are unchanged — a read entry links
-- into the same chain as the writes, in timestamp order.
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
    'credentialed_read'
  ));
