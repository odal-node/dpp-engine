-- ============================================================================
-- 0008 — unsold_goods_report (ESPR Art. 25 destruction-ban reporting).
-- `operator_id`/`operator_name` here are report *content* (the operator the
-- report is about), not a tenant key — retained.
-- ============================================================================

CREATE TABLE odal.unsold_goods_report (
  id                        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  kind                      TEXT NOT NULL DEFAULT 'textile_unsold',
  operator_id               TEXT NOT NULL,
  operator_name             TEXT,
  reporting_period          TEXT NOT NULL,
  volume_kg                 DOUBLE PRECISION NOT NULL,
  product_category          TEXT NOT NULL
    CHECK (product_category IN ('apparel','footwear','homeTextile','accessories','other')),
  reason                    TEXT NOT NULL
    CHECK (reason IN ('endOfSeason','qualityDefect','packagingDefect','overProduction','customerReturn','other')),
  destination               TEXT NOT NULL
    CHECK (destination IN ('donation','recycling','repurposing','supplierReturn','exemptDestruction')),
  destruction_justification TEXT,
  country_of_disposal       CHAR(2) NOT NULL,
  doc                       JSONB,
  created_at                TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_unsold_operator_period ON odal.unsold_goods_report (operator_id, reporting_period);
