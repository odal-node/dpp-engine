-- ============================================================================
-- 0047 — a revision on the transfer chain.
--
-- The chain is read, changed in memory and written back whole. Two requests that
-- both read the same chain each wrote a chain the other had not seen, and the
-- second write replaced the first. The state-change log now writes a chain only
-- over the revision it read, so the revision has to move on every write.
--
-- The database moves it, not each writer: a trigger sets it on every update, so
-- a write that never names the column still moves it. That includes the upsert
-- of a node still running the release before this one, which a rolling upgrade
-- can leave beside the new one for a while.
--
-- Rows written before this migration start at 0, the value a reader gets for
-- them, so a chain already stored needs no backfill. A chain with no row yet is
-- told apart by having no revision at all.
-- ============================================================================

ALTER TABLE odal.passport_transfer ADD COLUMN revision BIGINT NOT NULL DEFAULT 0;

CREATE FUNCTION odal.passport_transfer_revision() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  NEW.revision := OLD.revision + 1;
  RETURN NEW;
END $$;

CREATE TRIGGER passport_transfer_revision
  BEFORE UPDATE ON odal.passport_transfer
  FOR EACH ROW EXECUTE FUNCTION odal.passport_transfer_revision();
