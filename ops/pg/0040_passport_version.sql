-- ============================================================================
-- 0040 — passport_version: the passport as it stood, kept per change.
--
-- ✅ COMPLIANCE-PIN: EN 18221:2026 clause 4.2 (archiving and rules for
-- archiving), one of the six standards cited by Commission Implementing
-- Decision (EU) 2026/1736.
--
-- 🚨 THIS IS NOT WHAT `status = 'archived'` MEANS.
--
-- Two different things wear the word "archive" here, and the collision is the
-- reason this table exists:
--
--   * `PassportStatus::Archived` is a **terminal lifecycle state**, reached
--     after the ESPR retention period has elapsed. The record stops changing.
--   * EN 18221 clause 4.2's **archiving** is the retention of *historical
--     versions of a passport that is still live*. Nothing to do with lifecycle.
--
-- Anyone mapping this system onto the standard by name would have ticked a box
-- that was not ticked: before this table, no historical version of any passport
-- was retained anywhere.
--
-- What the clause asks for, in our own words:
--
--   * archiving begins at the **first change** to the initial passport — not at
--     create, and not at end of life;
--   * every version is kept for the passport's lifetime;
--   * all changes are archived, save those a product-specific requirement
--     exempts;
--   * archived attributes carry the same access restrictions as the
--     corresponding attributes in the **current** passport;
--   * the version as it stood at a given point in time is retrievable by
--     authenticated and authorised actors.
--
-- # What was already here and is not this
--
-- The **audit trail** (`0005`) records *that* a change happened, by whom and
-- when. On the update path it carries no metadata at all, so it cannot
-- reconstitute a passport — it was never meant to. It stays as it is; this
-- table is the record of *what the passport was*, and the two answer different
-- questions about the same event.
--
-- **Continuity snapshots** hold the rendered *public* view, one per passport,
-- refreshed rather than versioned. Being redacted, they cannot satisfy the
-- access-restriction limb even in principle: a version has to be stored whole
-- so that each reader's own restrictions can be applied to it.
--
-- # Why the document is stored whole
--
-- A diff would be smaller and would make "the version at time T" a replay
-- rather than a read — every retrieval reconstructing a record from a chain,
-- with one corrupt link losing everything after it. The clause wants the
-- version retrievable, and a stored version is retrievable; a derived one is
-- computed and hoped for.
--
-- # Append-only, like the audit trail and for the same reason
--
-- `superseded_at` says when this version stopped being current. A row is never
-- updated and never deleted: "all archived versions shall be maintained during
-- the digital product passport lifetime" is not a retention policy this node
-- gets to interpret, and a trigger is a stronger statement of that than a
-- missing grant.
--
-- Single-tenant, so no `operator_id` column.
-- ============================================================================

CREATE TABLE odal.passport_version (
  -- UUID v7, so rows sort by creation time like every other identifier here.
  id            UUID PRIMARY KEY,

  -- The passport this is a version of. Deliberately **not** a foreign key: a
  -- version outlives what it is a version of, and the clause's "for the
  -- passport's lifetime" is a floor rather than a ceiling. A cascade here would
  -- make the archive deletable by deleting the thing it exists to remember.
  passport_id   UUID NOT NULL,

  -- The complete record as it stood, exactly as the `passport.doc` column holds
  -- it. Whole rather than a diff — see the header.
  doc           JSONB NOT NULL,

  -- When this version stopped being current, which is the moment the change
  -- that replaced it was applied.
  --
  -- One timestamp rather than a validity range: the previous row's
  -- `superseded_at` is this row's start, and two columns that must agree are
  -- two columns that can disagree. "As of T" is then the earliest row for the
  -- passport whose `superseded_at` is after T — and if there is none, the live
  -- record is the answer.
  superseded_at TIMESTAMPTZ NOT NULL,

  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- The as-of lookup: by passport, ordered by when each version ended.
CREATE INDEX idx_passport_version_asof
  ON odal.passport_version (passport_id, superseded_at);

CREATE FUNCTION odal.passport_version_append_only() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'ODAL_VERSION: archived passport versions are append-only';
END $$;
CREATE TRIGGER passport_version_immutable
  BEFORE UPDATE OR DELETE ON odal.passport_version
  FOR EACH ROW EXECUTE FUNCTION odal.passport_version_append_only();

-- 0010's ALL-TABLES grant was a one-time snapshot; tables added later need
-- their own (same pattern as 0017/0021/0022/0023/0028/0038/0039). No UPDATE and
-- no DELETE: the trigger above refuses both anyway, and withholding the grant
-- says the same thing to anyone reading the grants rather than the triggers.
GRANT SELECT, INSERT ON odal.passport_version TO odal_app;
