-- ============================================================================
-- 0003 — api_key. Single-tenant: name is globally UNIQUE (no operator scope);
-- key_prefix is UNIQUE (collision gap closed); auth lookup uses the partial
-- active index.
-- ============================================================================

CREATE TABLE odal.api_key (
  id           UUID PRIMARY KEY,
  name         TEXT NOT NULL UNIQUE,
  key_hash     TEXT NOT NULL,
  key_prefix   TEXT NOT NULL UNIQUE,
  scopes       TEXT[],
  is_active    BOOLEAN NOT NULL DEFAULT true,
  created_by   UUID,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_used_at TIMESTAMPTZ,
  expires_at   TIMESTAMPTZ
);
CREATE INDEX idx_api_key_prefix_active ON odal.api_key (key_prefix) WHERE is_active;
