-- ============================================================================
-- 0043 — personal_data_record: personal data a passport's statement names,
-- held where it can be erased.
--
-- A published passport is signed, frozen, archived and copied to the back-up
-- provider, so personal data it is not required to carry cannot live in it: a
-- withdrawn consent (GDPR Art. 7(3)) obliges erasure (Art. 17(1)(b)), and
-- nothing the passport is copied to can be erased from. The passport carries a
-- statement naming a record and the basis it is held on; this table is the
-- record.
--
-- Its own table, and deliberately nothing else's neighbour:
--
--   * not a column or a key of `passport.doc`, which is archived into
--     `passport_version`, hashed into the audit chain, sealed, snapshotted and
--     copied to the back-up provider;
--   * read by no resolver or view route, and by no query that builds one. The
--     only reader is `PgPersonalDataRepo`, which `dpp-vault` reaches through
--     core's `PersonalDataPort`.
--
-- A row is in exactly one of two states, enforced below:
--
--   * PRESENT — `content` holds the data, `erased_at` is NULL;
--   * ERASED  — `content` is NULL, `erased_at` says when. The row stays as a
--               tombstone: the identifier, the passport and the field, and the
--               instant. None of the content.
--
-- **A tombstone is not free of personal data.** A passport identifier can
-- relate to whoever owns the item, and GDPR Recital 26 counts information that
-- can be linked to a person as personal data. So the tombstone is protected
-- like the passport's individual-item data, and is kept only as long as the
-- controller has a basis to keep it — to show that it erased (Art. 5(2)) is
-- one; nothing in this table decides when that ends, and nothing deletes it.
--
-- Erasure overwrites `content` in place. The database's own write-ahead log,
-- replicas and backups hold earlier row versions, and no application role can
-- reach them; how long those live is the operator's retention, not this table's.
--
-- Single-tenant: no `operator_id` column.
-- ============================================================================

CREATE TABLE odal.personal_data_record (
  -- Minted by the store (UUID v7) and never reused. It goes into a signed
  -- passport that outlives the record, so it is derived from nothing in the
  -- content or about the person.
  id          UUID PRIMARY KEY,

  -- The passport the record relates to. A foreign key, so a record cannot be
  -- held for a passport this node has no row for; passports are never deleted,
  -- so it can never be the thing that blocks anything.
  passport_id UUID        NOT NULL REFERENCES odal.passport(id),

  -- The marked field, as a dotted path inside `productGroupData`
  -- (`usageHistory.negativeEvents`). Whether it is marked is the passport's
  -- check, made when the statement naming the record is written.
  field       TEXT        NOT NULL CHECK (field <> ''),

  -- The data, in whatever shape the controller keeps it. NULL once erased.
  content     JSONB,

  stored_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  erased_at   TIMESTAMPTZ,

  -- Exactly one of the two states. Without this a row could be erased and still
  -- hold its content, or be present and hold none.
  CONSTRAINT personal_data_record_one_state CHECK (
    (content IS NOT NULL AND erased_at IS NULL)
    OR
    (content IS NULL AND erased_at IS NOT NULL)
  )
);

-- `records_for`: every record a passport has, in the order stored.
CREATE INDEX idx_personal_data_record_passport
  ON odal.personal_data_record (passport_id, stored_at, id);

-- Erasure is one-way. A record may change once — present to erased, content
-- dropped and the instant set, the other columns as they were — and a tombstone
-- never changes again: the receipt a retried erasure returns is the first one,
-- and an erased record is not brought back by anything the app role can run.
CREATE FUNCTION odal.personal_data_record_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF OLD.erased_at IS NOT NULL THEN
    RAISE EXCEPTION 'ODAL_PERSONAL_DATA: an erased record is a tombstone and cannot change';
  END IF;
  IF NEW.content IS NOT NULL
     OR NEW.id <> OLD.id
     OR NEW.passport_id <> OLD.passport_id
     OR NEW.field <> OLD.field
     OR NEW.stored_at <> OLD.stored_at THEN
    RAISE EXCEPTION 'ODAL_PERSONAL_DATA: a record can only be erased, not rewritten';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER personal_data_record_guard
  BEFORE UPDATE ON odal.personal_data_record
  FOR EACH ROW EXECUTE FUNCTION odal.personal_data_record_guard();

-- 0010's ALL-TABLES grant was a one-time snapshot; tables added later need their
-- own (same pattern as 0017/0021/0022/0023/0028/0038/0039).
--
-- **No DELETE.** Erasure is an UPDATE that drops the content and keeps the row,
-- because the tombstone is the controller's proof that it erased — so this
-- table does not join the DELETE set in ops/pg/README.md. UPDATE is granted on
-- the two columns erasure writes and no others.
GRANT SELECT, INSERT ON odal.personal_data_record TO odal_app;
GRANT UPDATE (content, erased_at) ON odal.personal_data_record TO odal_app;
