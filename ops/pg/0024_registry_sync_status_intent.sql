-- ============================================================================
-- 0024 — registry_sync: split the status-change intent out of `status`.
--
-- `status` in 0006 conflated two independent facts: whether a registration is
-- still owed (queue state, drained by `due()`), and which status intent should
-- eventually be pushed to the EU registry. Recording a suspend/EOL intent
-- overwrote 'pending', so `due()` stopped selecting the row and the Art. 13
-- registration was dropped — permanently and silently, since `commit_publish`
-- only re-arms rows sitting at 'rejected'.
--
-- After this migration `status` is queue state alone ('pending'/'registered'/
-- 'rejected') and `status_intent` records the outstanding intent. Only the drain
-- and the publish transaction move `status`; recording an intent cannot dequeue
-- an unsent registration.
-- ============================================================================

ALTER TABLE odal.registry_sync
  ADD COLUMN status_intent TEXT
    CHECK (status_intent IN ('suspended','deactivated'));

-- Heal rows the old write path already clobbered. `registry_id` is the witness
-- of what `status` held before the overwrite: it is set only by
-- `mark_registered`, so a row carrying one had reached 'registered', and a row
-- without one was still 'pending' — i.e. its registration was never sent and is
-- still owed. Restoring those to 'pending' puts them back in the due set and
-- recovers the lost registrations.
UPDATE odal.registry_sync
SET status_intent = status,
    status = CASE WHEN registry_id IS NOT NULL THEN 'registered' ELSE 'pending' END,
    updated_at = now()
WHERE status IN ('suspended','deactivated');

-- Now that no row holds an intent in `status`, narrow the constraint so the
-- conflation cannot reappear.
ALTER TABLE odal.registry_sync
  DROP CONSTRAINT registry_sync_status_check;
ALTER TABLE odal.registry_sync
  ADD CONSTRAINT registry_sync_status_check
    CHECK (status IN ('pending','registered','rejected'));
