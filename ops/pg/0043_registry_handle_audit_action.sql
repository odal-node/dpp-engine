-- ============================================================================
-- 0043 — admit the `registry_handle_recorded` audit action.
--
-- A registry submission whose correlation identifier this node lost is normally
-- found again by the drain, by the unique product identifier the passport was
-- submitted under. Where it cannot be — several submissions report the
-- identifier, or none could be placed — a person reads the right handle off the
-- registry's own interface and records it with
-- `POST /api/v1/dpp/{dppId}/registry/handle`, after the registry has shown the
-- submission to be the passport's.
--
-- That write overrides the drain's own judgement about which submission is the
-- passport's, and it is made by a person, so the trail is the only account of it:
-- who recorded which handle, and what the registry reported when they did. Both
-- are in the entry's metadata (`correlationId`, `report`). The entry changes no
-- passport status, so both status columns are null.
--
-- History: widen only. The append-only trigger and hash chain are unchanged.
-- ============================================================================

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
    'registry_handle_recorded'
  ));
