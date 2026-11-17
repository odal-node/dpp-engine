-- ============================================================================
-- 0053 — evidence_file and discard_record_evidence: the documents behind a
-- discard, stored once and cited by every record that relies on them.
--
-- A file is addressed by the SHA-256 of its bytes, so the same document cited
-- by two records is one row here. The hash is the file's identity: a record
-- cites it by hash, and the append-only link below is what makes the citation
-- a fact. Integrity therefore does not depend on how the bytes are stored, so an
-- object store with write-once retention can later implement the same port.
--
-- Append-only for the app role: SELECT and INSERT, and a trigger refusing UPDATE
-- and DELETE, as `odal.evidence_dossier` is.
-- ============================================================================

CREATE TABLE odal.evidence_file (
  -- Lower-case hex SHA-256 of `content`.
  sha256     TEXT PRIMARY KEY CHECK (sha256 ~ '^[0-9a-f]{64}$'),
  content    BYTEA NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE FUNCTION odal.evidence_file_append_only() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'ODAL_EVIDENCE_FILE: evidence files are append-only';
END $$;

CREATE TRIGGER evidence_file_immutable
  BEFORE UPDATE OR DELETE ON odal.evidence_file
  FOR EACH ROW EXECUTE FUNCTION odal.evidence_file_append_only();

-- A document attached to a record under one evidence kind. The kind is dpp-core's
-- `EvidenceKind`, checked by the node when it is read from the request, so the
-- column carries no allowlist of its own.
CREATE TABLE odal.discard_record_evidence (
  discard_record_id UUID NOT NULL REFERENCES odal.discard_record(id),
  evidence_sha256   TEXT NOT NULL REFERENCES odal.evidence_file(sha256),
  kind              TEXT NOT NULL CHECK (kind <> ''),
  attached_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (discard_record_id, evidence_sha256, kind)
);

CREATE FUNCTION odal.discard_record_evidence_append_only() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'ODAL_DISCARD: discard records are append-only';
END $$;

CREATE TRIGGER discard_record_evidence_immutable
  BEFORE UPDATE OR DELETE ON odal.discard_record_evidence
  FOR EACH ROW EXECUTE FUNCTION odal.discard_record_evidence_append_only();

GRANT SELECT, INSERT ON odal.evidence_file TO odal_app;
GRANT SELECT, INSERT ON odal.discard_record_evidence TO odal_app;
