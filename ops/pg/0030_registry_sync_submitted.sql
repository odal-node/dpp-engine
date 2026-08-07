-- ============================================================================
-- 0030 — registry_sync: a `submitted` queue state, for the registry's
-- asynchronous validation.
--
-- Registration is not synchronous. The registry accepts a submission, returns a
-- record identifier, and validates afterwards — the submission sits in its own
-- queue until it lands on success or failure. Our drain had only three states,
-- so it treated "accepted for processing" as terminal success: every
-- registration was recorded as complete the moment it was received, and a
-- submission the registry later refused would read as registered forever.
--
-- `submitted` is the missing middle. The row is still drainable, but the drain
-- *polls* it rather than resubmitting — resubmitting is what would create a
-- second registration for the same product.
--
-- 0006 already admitted 'suspended' and 'deactivated' in this CHECK; both now
-- have Rust counterparts, so only 'submitted' is new.
-- ============================================================================

ALTER TABLE odal.registry_sync DROP CONSTRAINT registry_sync_status_check;
ALTER TABLE odal.registry_sync ADD CONSTRAINT registry_sync_status_check
  CHECK (status IN ('pending','submitted','registered','rejected','suspended','deactivated'));

-- The drain's due-set is now both states. A partial index per state would not
-- serve the combined ORDER BY, so widen the one that exists.
DROP INDEX IF EXISTS odal.idx_regsync_due;
CREATE INDEX idx_regsync_due ON odal.registry_sync (next_attempt_at)
  WHERE status IN ('pending','submitted');

-- When the submission was accepted for processing, so the wait for a verdict is
-- visible and boundable. The registration's idempotency key needs no column: it
-- travels inside `payload` as part of the frozen request, which is what makes it
-- identical on every retry.
ALTER TABLE odal.registry_sync ADD COLUMN IF NOT EXISTS submitted_at TIMESTAMPTZ;
