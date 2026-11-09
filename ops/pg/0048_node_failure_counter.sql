-- ============================================================================
-- 0048 — node_failure_counter: refusals this node has counted, kept across
-- restarts.
--
-- Two refusals are counted for the node-health route:
--
--   * `signing`      — a publish refused because a passport could not be
--                      signed. The publish path returns before any write, so
--                      the refusal leaves no row this table could be rebuilt
--                      from;
--   * `ruleset_load` — a Compliance Current ruleset bundle refused on load.
--
-- The Prometheus counters with the same meaning reset when the process
-- restarts, which is the convention for a series a scraper reads over time. A
-- monitor that reads the value rather than its change would be told that a node
-- whose signing failed for a week is healthy after one restart, so the count the
-- route serves is kept here.
--
-- A count that never resets cannot say whether the node is failing now: one
-- refusal a year ago reads the same as one this morning. So each row also keeps
-- `last_refused_at`, the database clock at its latest refusal. A monitor that
-- keeps no state alarms on a recent refusal; one that does can diff the count.
--
-- One row per kind, named by the code that increments it. The first refusal of a
-- kind creates its row, so the table starts empty.
--
-- Single-tenant: no `operator_id` column.
-- ============================================================================

CREATE TABLE odal.node_failure_counter (
  name            TEXT        PRIMARY KEY CHECK (name IN ('signing', 'ruleset_load')),
  refusals        BIGINT      NOT NULL DEFAULT 0 CHECK (refusals >= 0),
  last_refused_at TIMESTAMPTZ NOT NULL
);

GRANT SELECT, INSERT, UPDATE ON odal.node_failure_counter TO odal_app;
