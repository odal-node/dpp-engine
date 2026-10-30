-- ============================================================================
-- 0044 — idempotency_key.claim_token: whose claim the row is.
--
-- 0036 matched an outcome or a release to its row by the four-part key and
-- `state = 'in_flight'` alone. That says a claim is in flight, not whose. Once a
-- lease runs out the claim is reclaimable, so a request that outlived its lease
-- would, when it finally finished, record its outcome over the claim of the
-- request that reclaimed the key (later retries then replay the superseded
-- response), or release that claim, which lets a third request run while the
-- second is still going.
--
-- Each claim now carries a token, minted by the store when it grants the claim
-- and replaced when a claim is reclaimed. An outcome or a release names the
-- token it was granted and matches no row once the claim is not its own.
--
-- A UUID rather than a counter: a row can be swept and the key claimed afresh,
-- and a counter would start again from its first value, where a token is never
-- repeated.
--
-- Rows that exist now are completed (a token no one will present) or `in_flight`
-- under a process that no longer exists (a token no one holds, which is correct:
-- nothing will finish them, and their lease reclaims them). So the default only
-- has to give each of them some value.
--
-- The grant on this table (0036) is table-level and covers the column.
-- ============================================================================

ALTER TABLE odal.idempotency_key
  ADD COLUMN claim_token UUID NOT NULL DEFAULT gen_random_uuid();
