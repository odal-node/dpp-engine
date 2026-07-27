-- ============================================================================
-- 0025 — scan telemetry: privacy-safe aggregate resolution counts.
--
-- Two mutable counter tables, keyed only by (passport, day, surface). There is
-- deliberately NO column for an IP, user agent, session, or per-event row — the
-- schema *is* the privacy policy: nothing about the scanner is representable, so
-- nothing about the scanner can leak. Any richer telemetry is a new, deliberate
-- decision with its own assessment, not an ALTER on these tables.
--
-- Unlike the append-only fact tables (0005 audit, 0021 evidence), these are
-- upserted (count = count + delta), so they carry no immutability trigger. They
-- do carry a DELETE grant: bounded retention is part of the privacy posture and
-- is enforced by the node's prune task (a rolling horizon), which the app role
-- must be permitted to run.
-- ============================================================================

-- Consumer resolutions of a passport (rows are per-day, but the name does not
-- pin the granularity — the `day` column carries it). `variant` is constrained
-- to the terminal view surfaces: the CHECK is what guarantees a QR *render*
-- (label production) can never be miscounted here as a resolution.
CREATE TABLE odal.scan_telemetry (
  dpp_id  UUID NOT NULL REFERENCES odal.passport(id),
  day     DATE NOT NULL,
  variant TEXT NOT NULL CHECK (variant IN ('html', 'json')),
  count   BIGINT NOT NULL DEFAULT 0,
  PRIMARY KEY (dpp_id, day, variant)
);
-- Operator rollup and prune both range over `day` across all passports.
CREATE INDEX idx_scan_telemetry_day ON odal.scan_telemetry (day);

-- Operator-side production of a passport's QR image. A separate table so it can
-- never be summed into resolution counts; no `variant` (a render is a render).
CREATE TABLE odal.qr_render (
  dpp_id UUID NOT NULL REFERENCES odal.passport(id),
  day    DATE NOT NULL,
  count  BIGINT NOT NULL DEFAULT 0,
  PRIMARY KEY (dpp_id, day)
);
CREATE INDEX idx_qr_render_day ON odal.qr_render (day);

-- 0010's ALL-TABLES grant was a one-time snapshot; tables added later need their
-- own grant (same pattern as 0021). Telemetry needs the upsert pair (INSERT +
-- UPDATE), SELECT for stats, and — uniquely among app-writable tables — DELETE,
-- because retention pruning is a first-class part of the privacy contract.
GRANT SELECT, INSERT, UPDATE, DELETE ON odal.scan_telemetry TO odal_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON odal.qr_render TO odal_app;
