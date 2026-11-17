-- ============================================================================
-- 0050 — obligation_notice: what the node has announced of the dated
-- obligations in its calendar, and the day its notice pass starts from.
--
-- dpp-core's obligation calendar says which dated obligations take effect on a
-- day. With OBLIGATION_NOTICES=on the node announces each one through its signed
-- webhooks, on the UTC day it takes effect and at configured lead times before
-- it. The calendar cannot hold what was already said, so two tables do:
--
--   * obligation_notice: one row per announced notice, keyed by the notice id, a
--     name-based UUID of the obligation, its date, its kind and its lead time. A
--     pass records a notice and queues its webhook deliveries in one transaction.
--     The primary key is what makes each notice once-only across instances: a
--     second instance that tries to record the same notice inserts nothing and
--     queues nothing. A postponed date is a new name, so it is announced again.
--   * obligation_notice_state: a singleton holding the first day a notice pass
--     covers. The first pass writes it, so a node switched on later does not
--     announce the calendar's history.
--
-- Append-only by trigger (same pattern as 0021): a row is a record of what was
-- announced, and an UPDATE or DELETE would rewrite that record. The singleton is
-- written once and has no UPDATE grant.
--
-- The dates are DATE with no time zone, because a date in EU law has none. The
-- node reads "today" as the UTC calendar date.
--
-- Single-tenant, so no `operator_id` column.
-- ============================================================================

CREATE TABLE odal.obligation_notice (
  notice_id       UUID PRIMARY KEY,
  obligation_id   TEXT NOT NULL,
  obligation_date DATE NOT NULL,
  obligation_kind TEXT NOT NULL,
  -- NULL for the notice on the day the obligation takes effect.
  lead_days       INTEGER CHECK (lead_days IS NULL OR lead_days > 0),
  notice_day      DATE NOT NULL,
  -- Only a date an adopted text fixes is announced. An assumed date is never
  -- recorded, so the basis is checked here as well as by the node.
  basis           TEXT NOT NULL CHECK (basis = 'sourced'),
  -- The serialised event, exactly as it was queued and signed.
  body            TEXT NOT NULL,
  announced_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  CHECK (notice_day = CASE
    WHEN lead_days IS NULL THEN obligation_date
    ELSE obligation_date - lead_days
  END)
);

CREATE INDEX idx_obligation_notice_date ON odal.obligation_notice (obligation_date);

CREATE FUNCTION odal.obligation_notice_append_only() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'ODAL_OBLIGATION_NOTICE: announced notices are append-only';
END $$;
CREATE TRIGGER obligation_notice_immutable
  BEFORE UPDATE OR DELETE ON odal.obligation_notice
  FOR EACH ROW EXECUTE FUNCTION odal.obligation_notice_append_only();

CREATE TABLE odal.obligation_notice_state (
  id           SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
  active_since DATE NOT NULL
);

-- 0010's ALL-TABLES grant was a one-time snapshot; tables added later need their
-- own grant (same pattern as 0021). No UPDATE or DELETE on either table.
GRANT SELECT, INSERT ON odal.obligation_notice TO odal_app;
GRANT SELECT, INSERT ON odal.obligation_notice_state TO odal_app;
