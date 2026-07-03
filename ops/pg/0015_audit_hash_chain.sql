-- ============================================================================
-- 0015 — audit hash chain: tamper-evident per-passport audit log.
--
-- `entry_hash` = SHA-256 over the JCS-canonicalised content of the entry folded
-- with `prev_hash`; `prev_hash` links to the predecessor entry's `entry_hash`
-- (empty string for the genesis entry). Computed in the app (repo append), not
-- SQL, so the canonicalisation matches verification exactly.
--
-- The append-only trigger from 0005 already forbids UPDATE/DELETE, so the chain
-- cannot be silently rewritten by the app role. Columns are nullable so any
-- pre-chain historical rows coexist until backfilled (a privileged one-off with
-- the trigger temporarily disabled).
-- ============================================================================

ALTER TABLE odal.passport_audit ADD COLUMN prev_hash  TEXT;
ALTER TABLE odal.passport_audit ADD COLUMN entry_hash TEXT;
