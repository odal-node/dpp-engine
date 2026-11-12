-- ============================================================================
-- 0048 — node_signal: outcomes of the node's own work that leave no other
-- trace, kept across restarts.
--
-- A signal is something the node does whose outcome nothing else records. Two
-- today, named by `dpp_types::node_signal::Signal::name`:
--
--   * `signing`     — signing a passport at publish. A refusal returns before
--                     any write, so it leaves no row this could be rebuilt from;
--   * `rulesetLoad` — loading the Compliance Current ruleset from its channel.
--                     It fails when the channel cannot be read or the bundle it
--                     served is refused, and the node keeps the ruleset it had.
--
-- The names live in that enum and nowhere else: there is no CHECK listing them,
-- so a new signal needs no migration. What does NOT belong here: anything the
-- node can work out from rows it already holds (read it live, a copy drifts),
-- and rates or histories (the metrics endpoint).
--
-- The Prometheus counters for the same failures reset when the process
-- restarts, which is the convention for a series a scraper reads over time. A
-- monitor that reads a value rather than its change would be told that a node
-- whose signing failed for a week is healthy after one restart, so the count
-- the node-health route serves is kept here. That count never resets either,
-- so it cannot say whether the node is failing now. `last_failed_at` and
-- `last_succeeded_at` can: a signal is failing while its latest outcome is a
-- failure. Both are the database clock.
--
-- One row per signal; its first outcome creates it.
--
-- Single-tenant: no `operator_id` column.
-- ============================================================================

CREATE TABLE odal.node_signal (
  name              TEXT        PRIMARY KEY,
  failures          BIGINT      NOT NULL DEFAULT 0 CHECK (failures >= 0),
  last_failed_at    TIMESTAMPTZ,
  last_succeeded_at TIMESTAMPTZ
);

GRANT SELECT, INSERT, UPDATE ON odal.node_signal TO odal_app;
