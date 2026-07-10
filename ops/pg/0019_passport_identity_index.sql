-- ============================================================================
-- 0019 — passport identity index. Backs the import delta-matcher's exact
-- (sector, gtin, batch) lookup across Draft and Published passports.
--
-- GTIN is read from doc->'sectorData'->>'gtin', which 9 of 11 sectors
-- populate today (UnsoldGoods and Other carry no gtin field on their typed
-- sector data — a discard-event report and an untyped catch-all); rows for
-- those two sectors are simply never matched by this index, not broken.
-- ============================================================================

CREATE INDEX idx_passport_identity ON odal.passport
  (sector, (doc->'sectorData'->>'gtin'), (doc->>'batchId'))
  WHERE status IN ('draft','active');
