-- ============================================================================
-- 0033 — index the continuity tier's refresh scan.
--
-- The snapshot a passport is served from carries a signed `validUntil`, so a
-- published passport's snapshot has to be re-signed before that window closes
-- or it lapses while the passport is still live. The refresh pass finds the
-- rows nearest expiry by scanning for reconciled rows ordered by when they were
-- last written — a different access path from 0023's `idx_snapshot_outbox_due`,
-- which is partial on `status = 'pending'` and keyed on `next_attempt_at`.
--
-- Without this the pass reads and sorts the whole outbox every cycle, and it is
-- the one pass whose lateness expires live passports rather than merely
-- delaying them.
-- ============================================================================

CREATE INDEX idx_snapshot_outbox_refresh
  ON odal.snapshot_outbox (reconciled_at) WHERE status = 'reconciled';
