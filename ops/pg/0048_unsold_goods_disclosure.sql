-- ============================================================================
-- 0044 — unsold_goods_disclosure: the ESPR Art. 24 disclosure, one financial
-- year per row, in the format Commission Implementing Regulation (EU) 2026/2
-- prescribes.
--
-- The act's unit is one disclosure per undertaking per financial year: who is
-- disclosing (with its EUID), the year, the Annex I table of discarded lines,
-- and the measures taken and planned. `report` holds it whole, as dpp-domain's
-- `UnsoldGoodsReport`, so the shape has one home and this table does not
-- restate it in columns. The financial year is projected out because it is
-- the key: a year is disclosed once, and recording it again replaces it.
--
-- Replaces `unsold_goods_report` (0008, 0037), which predates the act: a
-- five-value category, one destination per line, and no CN code, estimate or
-- packaging marker, EUID or measures. It is dropped rather than migrated: no
-- deployment holds data in it, and a line of the old shape cannot be turned
-- into a line of the new one without inventing the CN code, the reason under
-- Delegated Regulation (EU) 2026/296 and the treatment split.
-- ============================================================================

DROP TABLE odal.unsold_goods_report;

CREATE TABLE odal.unsold_goods_disclosure (
  financial_year_start DATE        PRIMARY KEY,
  financial_year_end   DATE        NOT NULL,
  report               JSONB       NOT NULL,
  -- The API caller who recorded the stored version, as `AuthContext.user_id`.
  recorded_by          TEXT        NOT NULL,
  created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
  CHECK (financial_year_end > financial_year_start)
);

-- No DELETE: recording a year again replaces its row, so the app role never
-- needs to remove one.
GRANT SELECT, INSERT, UPDATE ON odal.unsold_goods_disclosure TO odal_app;
