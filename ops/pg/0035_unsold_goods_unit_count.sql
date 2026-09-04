-- ============================================================================
-- 0035 — the *number* of unsold products discarded, alongside their weight.
--
-- `0008` built this table for ESPR Art. 25 destruction-ban reporting and gave
-- it `volume_kg`. Art. 24(1)(a) — the disclosure obligation the table actually
-- serves — asks for both halves:
--
--   "the number and weight of unsold consumer products discarded per year,
--    differentiated per type or category of products"
--
-- so a report built from this table could not satisfy (a) no matter what was
-- written into it. The gap went unnoticed because nothing wrote the table at
-- all.
--
-- Nullable rather than `NOT NULL DEFAULT 0`: a default of zero would assert
-- that nothing was discarded, which is a claim, not an absence. NULL says the
-- count was not recorded. The write path requires it, so new rows always carry
-- one; the column is nullable only so that a row predating this migration
-- stays honest about not having one.
-- ============================================================================

ALTER TABLE odal.unsold_goods_report ADD COLUMN unit_count BIGINT
  CHECK (unit_count IS NULL OR unit_count >= 0);
