-- ============================================================================
-- 0020 — import_job gains report and parent_job_id.
--
-- report: the persisted, row-addressed findings report — every import job,
-- dry-run or apply, now populates this via JobStore::record_report, so the
-- report is retrievable via GET /api/v1/imports/{jobId} instead of only
-- returned synchronously. Independent of the existing `result` column
-- (apply-mode's created/errors bookkeeping).
--
-- parent_job_id: reserved for a future re-run/apply-from-dry-run flow; not
-- set by any code path yet.
-- ============================================================================

ALTER TABLE odal.import_job
  ADD COLUMN report JSONB,
  ADD COLUMN parent_job_id UUID REFERENCES odal.import_job(id);
