-- ============================================================================
-- 0021 — evidence_dossier: persisted, immutable evidence-dossier snapshots.
-- Doc-style table: query columns + the full DossierV1 (camelCase) in `doc`.
-- Append-only by trigger (same pattern as 0005): a stored snapshot is a fact.
-- ============================================================================

CREATE TABLE odal.evidence_dossier (
  id          UUID PRIMARY KEY,
  passport_id UUID NOT NULL REFERENCES odal.passport(id),
  actor       TEXT NOT NULL,
  doc_hash    TEXT NOT NULL,
  doc         JSONB NOT NULL,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_evidence_dossier_passport ON odal.evidence_dossier (passport_id, created_at);

CREATE FUNCTION odal.evidence_append_only() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'ODAL_EVIDENCE: evidence dossiers are append-only';
END $$;
CREATE TRIGGER evidence_dossier_immutable
  BEFORE UPDATE OR DELETE ON odal.evidence_dossier
  FOR EACH ROW EXECUTE FUNCTION odal.evidence_append_only();

-- 0010's ALL-TABLES grant was a one-time snapshot; tables added later need
-- their own grant (same pattern as 0017). No UPDATE/DELETE: append-only.
GRANT SELECT, INSERT ON odal.evidence_dossier TO odal_app;
