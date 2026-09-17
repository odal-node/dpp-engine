-- ============================================================================
-- 0041 — the terminal status is `retired`; `archived` keeps its other meaning.
--
-- `archived` was this system's terminal *publication* status: the state a record
-- reaches once the ESPR retention period has elapsed and it stops changing.
-- EN 18221:2026 clause 4.2 — one of the six standards cited by Commission
-- Implementing Decision (EU) 2026/1736 — uses "archiving" for something else
-- entirely: the retention of historical versions of a passport that is **still
-- live**, which this node does in `passport_version` (0040).
--
-- Two things wore one word, so anyone mapping this schema onto the standard by
-- name ticked a box that was not ticked. The status is renamed; the word stays,
-- and now means only what the standard means by it.
--
-- ── Two tables, two different treatments, deliberately ──────────────────────
--
-- `passport.status` is *current state*, so it is rewritten: a row saying
-- `archived` and a row saying `retired` describe the same record, and only one
-- of those spellings is a status any longer.
--
-- `passport_audit.action` is *history*, and is NOT rewritten. The action,
-- prevStatus and newStatus of every entry are covered by the append-only hash
-- chain (`dpp_types::audit`, columns chained in 0015), so an UPDATE here would
-- break `verify_audit_chain` from the edited row onward and every later entry
-- would read as tampered. An entry that says `archived` is a true record of a
-- transition performed while that was the word: history keeps the name it
-- happened under. So `retired` is ADDED to the permitted set and `archived`
-- STAYS, spending one permanently permitted legacy value to keep the trail
-- verifiable.
--
-- ── 0040's header is now stale, and cannot be fixed ────────────────────────
--
-- It says "THIS IS NOT WHAT `status = 'archived'` MEANS" and contrasts this
-- table with `PassportStatus::Archived`. Both name a status that no longer
-- exists; read it as `retired`. An applied migration cannot be edited — sqlx
-- checksums every file, so a comment-only change makes a node that has already
-- run it refuse to boot — so the correction lives here, in the migration that
-- caused it, rather than there.
--
-- While correcting it: the two things 0040 contrasts are not the only two. A
-- third, `BackupCopyPort`, is the ESPR Art. 10(4) back-up copy. 🚨 Clause 4.2
-- expects archived versions to be held by the back-up provider as well as by
-- this node, so the provider is not exempt from the clause — the port simply
-- carries no series, so nothing about clause 4.2 is expressible through it.
-- This table is this node's side of the clause and is not made redundant by
-- any back-up arrangement.
--
-- The append-only trigger, the hash chain and the grants are unchanged.
-- ============================================================================

-- ── `doc` is the one that matters; the column is only a projection ─────────
--
-- 🚨 Rewriting `passport.status` alone would leave every pre-rename row
-- unreadable. `doc` holds the full serde `Passport` — `status` included — and
-- `PgPassportRepo::read_doc` calls `Passport::from_stored` on **`doc`**, never
-- on the column, which 0004's own header and the insert's comment both say is
-- "a projection of `doc`, never a second source of truth". Core refuses
-- `"archived"` on deserialisation as of 0.21.0, so a row whose `doc` still
-- carries it fails to read at all: a 500 per request, on exactly the passports
-- that already existed. That is the shape of the `product_group` envelope
-- rename, which cost 244 of 276 passports.
--
-- So `doc` is rewritten first and the column follows it, in that order and in
-- one transaction, because a migration that did only the second would look
-- like it had worked.
UPDATE odal.passport
   SET doc = jsonb_set(doc, '{status}', '"retired"'::jsonb)
 WHERE doc->>'status' = 'archived';

UPDATE odal.passport SET status = 'retired' WHERE status = 'archived';

-- `passport_version.doc` is deliberately NOT rewritten, for two reasons that
-- agree. It is history, like `passport_audit` above. And it is append-only by
-- the `passport_version_immutable` trigger (BEFORE UPDATE OR DELETE, 0040), so
-- an UPDATE here raises rather than silently succeeding. Nothing deserialises a
-- version into a `Passport` — `PassportVersion.doc` is a `serde_json::Value`
-- the versions route filters and serves as-is — so a version carrying the old
-- spelling reads fine and says what the record said at the time, which is the
-- whole point of keeping it.

ALTER TABLE odal.passport DROP CONSTRAINT passport_status_check;
ALTER TABLE odal.passport ADD CONSTRAINT passport_status_check
  CHECK (status IN ('draft','active','suspended','retired','superseded','deactivated'));

-- History: widen only. `archived` remains legal so the chain still verifies over
-- entries written before the rename.
ALTER TABLE odal.passport_audit DROP CONSTRAINT passport_audit_action_check;
ALTER TABLE odal.passport_audit ADD CONSTRAINT passport_audit_action_check
  CHECK (action IN (
    'created',
    'updated',
    'published',
    'suspended',
    'archived',
    'retired',
    'deactivated',
    'transferred',
    'credentialed_read',
    'superseded'
  ));
