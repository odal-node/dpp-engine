-- ============================================================================
-- 0052 — discard_record: one discard of unsold consumer products, and the
-- passports it names.
--
-- ESPR Art. 24 has an operator keep, for each discard, the documentation that
-- demonstrates its delivery and reception, and the yearly disclosure is computed
-- from these rows rather than uploaded whole. The record's shape is dpp-core's
-- discard-record schema (`dpp_domain::unsold_goods`); the node stores it as the
-- schema checked it, so a stored record is read back as the version it was
-- written under.
--
-- Append-only, with no DELETE grant: a discard counted once is a fact the
-- operator must be able to show. The passport join is a fact of the same kind.
-- ============================================================================

CREATE TABLE odal.discard_record (
  id             UUID PRIMARY KEY,
  -- The record schema version the record was checked against.
  schema_version TEXT NOT NULL,
  -- The day of the discard. Financial-year listings filter on it.
  discarded_on   DATE NOT NULL,
  -- The whole record, camelCase, as core models it.
  record         JSONB NOT NULL,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_discard_record_discarded_on ON odal.discard_record (discarded_on, id);

CREATE FUNCTION odal.discard_record_append_only() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'ODAL_DISCARD: discard records are append-only';
END $$;

CREATE TRIGGER discard_record_immutable
  BEFORE UPDATE OR DELETE ON odal.discard_record
  FOR EACH ROW EXECUTE FUNCTION odal.discard_record_append_only();

-- The passports a record names. A join in this node's storage, not part of the
-- record core models. A foreign key, so a discard cannot name a passport this
-- node does not hold.
CREATE TABLE odal.discard_record_passport (
  discard_record_id UUID NOT NULL REFERENCES odal.discard_record(id),
  passport_id       UUID NOT NULL REFERENCES odal.passport(id),
  PRIMARY KEY (discard_record_id, passport_id)
);

CREATE TRIGGER discard_record_passport_immutable
  BEFORE UPDATE OR DELETE ON odal.discard_record_passport
  FOR EACH ROW EXECUTE FUNCTION odal.discard_record_append_only();

-- 0010's ALL-TABLES grant was a one-time snapshot; tables added later need
-- their own grant. No UPDATE or DELETE: append-only.
GRANT SELECT, INSERT ON odal.discard_record TO odal_app;
GRANT SELECT, INSERT ON odal.discard_record_passport TO odal_app;
