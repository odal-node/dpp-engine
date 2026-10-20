-- ============================================================================
-- 0044 — admit the `abandoned` registry state and the `registry_abandoned`
-- audit action.
--
-- A registration the registry never accepted can stall for good: the payload is
-- refused on every attempt, or the product is withdrawn before it was ever
-- registered. The row kept retrying with backoff, forever, and the only way
-- off the queue was a database edit. An operator can now end it with
-- `POST /api/v1/dpp/{dppId}/registry/abandon` — but only once the registry has
-- been shown to hold no submission for the passport, because a `pending` row
-- whose first attempt got through and whose reply was lost looks exactly like
-- one that never did.
--
-- `abandoned` is not `rejected`. A rejection is the registry refusing a
-- submission it received; this is a person deciding to stop asking, about a
-- passport the registry never accepted. Nothing the drain writes moves a row out
-- of it (its updates carry `status <> 'abandoned'`), and only publishing the
-- passport again queues it anew.
--
-- The write is audited as `registry_abandoned`, with who gave up on it and why,
-- because it ends an obligation the node was tracking on a person's say-so. The
-- entry changes no passport status, so both status columns are null.
--
-- History: widen only. The append-only trigger and hash chain are unchanged, and
-- every action and state written before this stays legal.
-- ============================================================================

ALTER TABLE odal.registry_sync DROP CONSTRAINT registry_sync_status_check;
ALTER TABLE odal.registry_sync ADD CONSTRAINT registry_sync_status_check
  CHECK (status IN ('pending', 'submitted', 'registered', 'rejected', 'suspended', 'deactivated', 'abandoned'));

ALTER TABLE odal.passport_audit DROP CONSTRAINT passport_audit_action_check;
ALTER TABLE odal.passport_audit ADD CONSTRAINT passport_audit_action_check
  CHECK (action IN (
    'created',
    'updated',
    'published',
    'suspended',
    'archived',
    'retired',
    'deactivated',
    'transferred',
    'credentialed_read',
    'superseded',
    'registry_handle_recorded',
    'registry_abandoned'
  ));
