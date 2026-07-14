-- ============================================================================
-- 0022 — webhooks: operator-configured signed outbound delivery.
--
-- `webhook_subscription` holds per-receiver config (url, signing secret, event
-- filter). `webhook_delivery` is a durable outbox — one row per (subscription,
-- event), enqueued after-commit from the event chokepoint and drained with
-- backoff by the node (HMAC-signed HTTP POST). Delivery is best-effort but
-- loss-proof once enqueued: a killed node redelivers `pending` rows on restart.
-- Single-tenant: no `operator_id` column, consistent with `registry_sync`.
-- ============================================================================

CREATE TABLE odal.webhook_subscription (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  url         TEXT NOT NULL,
  -- Signing secret. Unlike api_key (hashed — only ever verified), this must be
  -- replayed to compute the HMAC on every delivery, so it cannot be hashed.
  secret      TEXT NOT NULL,
  -- Subject filter: event_type strings (e.g. 'dpp.passport.published') or '*'.
  events      TEXT[] NOT NULL,
  active      BOOLEAN NOT NULL DEFAULT true,
  description TEXT,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE odal.webhook_delivery (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  subscription_id UUID NOT NULL REFERENCES odal.webhook_subscription(id),
  event_type      TEXT NOT NULL,
  -- The exact serialised DppEvent bytes that will be POSTed and signed, stored
  -- verbatim so there is no canonicalisation ambiguity between sign and send.
  body            TEXT NOT NULL,
  status          TEXT NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending','delivered','exhausted')),
  attempts        INTEGER NOT NULL DEFAULT 0,
  next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_attempt_at TIMESTAMPTZ,
  message         TEXT,
  delivered_at    TIMESTAMPTZ,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_webhook_delivery_due
  ON odal.webhook_delivery (next_attempt_at) WHERE status = 'pending';

-- 0010's ALL-TABLES grant was a one-time snapshot; tables added later need their
-- own grant (same pattern as 0017/0021). No DELETE: subscription removal is a
-- soft `active = false`, delivery rows are retained for audit.
GRANT SELECT, INSERT, UPDATE ON odal.webhook_subscription TO odal_app;
GRANT SELECT, INSERT, UPDATE ON odal.webhook_delivery TO odal_app;
