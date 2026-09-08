-- ============================================================================
-- 0036 — idempotency_key: the record of a write a client may safely retry.
--
-- A client whose POST times out cannot tell whether it landed. This table is
-- what lets it ask, by resending the same request under the same
-- `Idempotency-Key`: the first outcome is replayed, and no second resource is
-- created.
--
-- Only routes where a replay would *create a second thing* are keyed — see the
-- policy table in `dpp_common::idempotency`. The convergent lifecycle
-- transitions (publish, suspend, archive, …) are not, because a second call
-- reaches the same state on its own.
--
-- Single-tenant: no `operator_id`. `principal` is *which caller*, not which
-- tenant — the API key's `user_id`, or `mtls:<CN>` for the internal
-- certificate-gated routes that carry no `AuthContext`.
-- ============================================================================

CREATE TABLE odal.idempotency_key (
  -- The uniqueness key, and the reason it has four parts:
  --
  -- `principal` so one key-holder can neither collide with nor probe another's
  -- keys. `method`+`path` because a client minting one id per logical operation
  -- that fans out across several routes is normal, and treating that as a
  -- reused key would be a false accusation. `idem_key` is the client's own
  -- opaque string.
  --
  -- `path` is the matched *route template* (`/dpp/{dppId}/evidence`), not the
  -- concrete URI: it is the identity of the operation, and it is bounded, so a
  -- caller cannot mint unbounded distinct rows by varying a path parameter.
  principal        TEXT        NOT NULL,
  method           TEXT        NOT NULL,
  path             TEXT        NOT NULL,
  idem_key         TEXT        NOT NULL,

  -- Hex SHA-256 of the raw request body bytes. Raw, not canonicalised JSON:
  -- canonicalising would invent a normalisation this API does not otherwise
  -- have, and a client that re-serialises its body differently on retry has
  -- changed its request. Pattern-pinned like 0028's `payload_hash` so a
  -- non-digest cannot be stored.
  fingerprint      TEXT        NOT NULL CHECK (fingerprint ~ '^[0-9a-f]{64}$'),

  -- `in_flight` is claimed before the handler runs and updated to `completed`
  -- after it answers. The two states exist because a middleware cannot commit
  -- this row in the same transaction as the handler's write — the repository
  -- ports are per-operation — so a crash mid-request is representable and must
  -- be recoverable rather than wedging the key forever. See `lease_expires_at`.
  state            TEXT        NOT NULL DEFAULT 'in_flight'
                     CHECK (state IN ('in_flight', 'completed')),

  -- The replayed response. NULL while in flight; a completed row must carry at
  -- least a status, which the CHECK below enforces rather than trusting the
  -- writer.
  response_status  SMALLINT    CHECK (response_status BETWEEN 100 AND 599),
  response_body    BYTEA,
  content_type     TEXT,

  -- How long an `in_flight` row is believed. A crash between the claim and the
  -- completion leaves a row nothing will ever finish; past this instant the
  -- claim is reclaimable and the request runs again. Before it, a concurrent
  -- duplicate is told to retry rather than being allowed to double-execute.
  lease_expires_at TIMESTAMPTZ NOT NULL,

  -- When the row stops being honoured at all. The window must cover a client's
  -- whole retry budget, including an operator restarting an integration after
  -- an outage — which is the case the feature exists for. A caller that has not
  -- retried within a day is not retrying.
  expires_at       TIMESTAMPTZ NOT NULL,

  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  completed_at     TIMESTAMPTZ,

  PRIMARY KEY (principal, method, path, idem_key),

  -- A completed row that cannot be replayed is worse than no row: the client
  -- would be told "already done" and handed nothing. Refuse to store one.
  CONSTRAINT completed_rows_can_be_replayed
    CHECK (state <> 'completed' OR (response_status IS NOT NULL AND completed_at IS NOT NULL))
);

-- Backs the sweep only. The replay lookup is the primary key.
CREATE INDEX idx_idempotency_expiry ON odal.idempotency_key (expires_at);

-- 0010's ALL-TABLES grant was a one-time snapshot; tables added later need
-- their own (same pattern as 0017/0021/0022/0023/0028).
--
-- **This one includes DELETE**, which makes it the fourth table in the
-- sanctioned DELETE set. It is a queue, not a fact: the row exists to answer a
-- retry for a bounded window and is worthless afterwards, and a key retained
-- forever is a slow leak. `ops/pg/README.md` carries the list — that file, not
-- this one, because a grant list has to stay editable and a migration does not.
GRANT SELECT, INSERT, UPDATE, DELETE ON odal.idempotency_key TO odal_app;
