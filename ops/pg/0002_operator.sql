-- ============================================================================
-- 0002 — operator identity: operator_config (the single operator's own row),
-- plus its economic-operator identifiers and facilities. `operator_id` here is
-- the operator's own identity (PK / FK), not a tenant discriminator.
-- ============================================================================

CREATE TABLE odal.operator_config (
  operator_id           TEXT PRIMARY KEY,
  legal_name            TEXT NOT NULL,
  trade_name            TEXT,
  address               TEXT NOT NULL,
  country               CHAR(2) NOT NULL,
  contact_email         TEXT NOT NULL,
  did_web_url           TEXT,
  product_categories    JSONB,
  brand_primary         TEXT,
  brand_secondary       TEXT,
  brand_logo_url        TEXT,
  custom_domain         TEXT,
  data_residency        TEXT NOT NULL DEFAULT 'EU' CHECK (data_residency IN ('EU','GLOBAL')),
  retention_policy_days INTEGER NOT NULL DEFAULT 3650 CHECK (retention_policy_days >= 365),
  feature_flags         JSONB,
  created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at            TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- EORI, VAT, GLN ... consumed by registry sync.
CREATE TABLE odal.operator_identifier (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  operator_id TEXT NOT NULL REFERENCES odal.operator_config(operator_id),
  scheme      TEXT NOT NULL,
  value       TEXT NOT NULL,
  label       TEXT,
  is_primary  BOOLEAN NOT NULL DEFAULT true,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (operator_id, scheme, value)
);
CREATE INDEX idx_opid_scheme_value ON odal.operator_identifier (scheme, value);

CREATE TABLE odal.facility (
  id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  operator_id       TEXT NOT NULL REFERENCES odal.operator_config(operator_id),
  name              TEXT NOT NULL,
  identifier_scheme TEXT NOT NULL,
  identifier_value  TEXT NOT NULL,
  country           CHAR(2) NOT NULL,
  address           TEXT,
  is_default        BOOLEAN NOT NULL DEFAULT false,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (identifier_scheme, identifier_value)
);
CREATE INDEX idx_facility_operator ON odal.facility (operator_id);
