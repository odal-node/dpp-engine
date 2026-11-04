-- ============================================================================
-- 0047 — a revision on the transfer chain.
--
-- The chain is read, changed in memory and written back whole. Two requests that
-- both read the same chain each wrote a chain the other had not seen, and the
-- second write replaced the first. Every write now bumps `revision`, and the
-- state-change log writes a chain only over the revision it read.
--
-- Rows written before this migration start at 0, the value a reader gets for
-- them, so a chain already stored needs no backfill. A chain with no row yet is
-- told apart by having no revision at all.
-- ============================================================================

ALTER TABLE odal.passport_transfer ADD COLUMN revision BIGINT NOT NULL DEFAULT 0;
