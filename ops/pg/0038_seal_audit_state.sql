-- ============================================================================
-- 0038 — seal_audit_state: where the stored-seal audit keeps its position and
-- its last completed result.
--
-- The audit opens every stored seal and checks whether it still stands up —
-- the one failure no SQL clause can find, because a seal that is present and
-- worthless satisfies every "is the seal member absent" test the node makes.
-- It walks the estate in batches and publishes only when it reaches the end,
-- since a count from half the estate reads exactly like a count from all of it.
--
-- Both halves lived only in process memory, and that cost two things:
--
--   * a restart erased the answer, so the operator surface reported "no pass
--     has completed" for the length of a whole walk after every deployment —
--     hours on a large estate, and indistinguishable from an audit that is not
--     running at all;
--   * a restart also erased the *position*, so a node whose estate takes longer
--     to walk than it goes between restarts would begin again from the start
--     for ever and never publish anything, while doing all of the work.
--
-- The second is the reason the cursor is here and not just the report: storing
-- only the result cannot help a node that never produces one.
--
-- Deliberately NOT a record of validations. Under Reg. (EU) No 910/2014 Art. 33,
-- reached for seals by Art. 40, a qualified validation service is a QTSP service
-- whose result carries the provider's own advanced signature or seal. Nothing
-- written here is signed and nothing here is qualified — it is a node's own
-- housekeeping, kept so an operator can see when it last looked.
--
-- Singleton: one node, one audit, one row, enforced by the primary key check.
-- Single-tenant, so no `operator_id` column.
-- ============================================================================

CREATE TABLE odal.seal_audit_state (
  id         SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
  -- The walk in progress: cursor, start time, and the totals accumulated so
  -- far. NULL between a completed pass and the start of the next.
  --
  -- JSONB rather than columns because the shape is owned by the serde type that
  -- reads it back, the same arrangement every other document column here uses,
  -- and because a partial walk is read and written whole — never queried into.
  progress   JSONB,
  -- The last pass that reached the end. NULL means none ever has, which is the
  -- state the operator surface reports as an absence rather than as a zero: a
  -- check that has not run must not be served as a check that found nothing.
  report     JSONB,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 0010's ALL-TABLES grant was a one-time snapshot; tables added later need their
-- own grant (same pattern as 0017/0021/0022/0023/0028). No DELETE: the row is
-- overwritten in place and there is nothing here to remove.
GRANT SELECT, INSERT, UPDATE ON odal.seal_audit_state TO odal_app;
