-- ============================================================================
-- 0009 — identity namespace: the node's did:web document and signing key pairs.
-- `operator_id` here is the node's own DID owner identity, not a tenant key.
-- ============================================================================

CREATE TABLE identity.did_document (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  operator_id TEXT NOT NULL UNIQUE,
  did         TEXT NOT NULL UNIQUE,
  document    JSONB NOT NULL,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE identity.key_pair (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  operator_id     TEXT NOT NULL,
  key_id          TEXT NOT NULL,
  public_key_jwk  JSONB NOT NULL,
  private_key_enc TEXT NOT NULL,
  algorithm       TEXT NOT NULL DEFAULT 'EdDSA' CHECK (algorithm = 'EdDSA'),
  is_active       BOOLEAN NOT NULL DEFAULT true,
  rotated_at      TIMESTAMPTZ,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (operator_id, key_id)
);
CREATE INDEX idx_key_pair_active ON identity.key_pair (operator_id, is_active);
