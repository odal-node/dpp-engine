-- ============================================================================
-- 0032 — passport: `sector` becomes `product_group`, and the two indexes that
-- named it follow.
--
-- "Sector" is not a term the Regulation defines. ESPR defines **product group**
-- (Art. 2(5)) and uses it throughout, and the mismatch was load-bearing rather
-- than cosmetic: it let a catalog mix product groups with horizontal
-- obligations, borrow a classification axis from a different regulation, and
-- carry an entry asserting a passport obligation that does not exist. The type
-- and the JSON envelope were renamed with it, so this column is the last place
-- the old word survived.
--
-- Added rather than edited into 0004 and 0019: `sqlx::migrate!` checksums every
-- file, so changing an applied migration makes a node that has already run it
-- refuse to boot, with no in-product remedy.
--
-- No data moves. The column keeps its values — they are catalog keys like
-- 'battery', which did not change — and only the name it is addressed by does.
-- ============================================================================

ALTER TABLE odal.passport RENAME COLUMN sector TO product_group;

-- Renaming a column does not rename the indexes over it, and an index called
-- `idx_passport_sector` on a column called `product_group` is exactly the kind
-- of half-finished rename that outlives everyone who remembers it.
ALTER INDEX odal.idx_passport_sector RENAME TO idx_passport_product_group;

-- The identity index is rebuilt rather than renamed: it indexes an expression
-- over the document, and the JSON key inside that expression changed too — the
-- old `sectorData` key became `productGroupData`. A rename would leave the index
-- silently matching a key no passport emits any more, which returns NULL for
-- every row rather than failing, and that is the exact defect the SQL
-- key-literal drift gate exists to catch.
--
-- Backs the import delta-matcher's exact (product group, gtin, batch) lookup
-- across Draft and Published passports. GTIN is read from
-- `doc->'productGroupData'->>'gtin'`, which most product groups populate;
-- unsold goods and the untyped catch-all carry no gtin on their typed data — a
-- discard-event report and an open extension point — so rows for those two are
-- simply never matched by this index, not broken.
DROP INDEX odal.idx_passport_identity;

CREATE INDEX idx_passport_identity ON odal.passport
  (product_group, (doc->'productGroupData'->>'gtin'), (doc->>'batchId'))
  WHERE status IN ('draft','active');
