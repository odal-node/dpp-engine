-- ============================================================================
-- 0031 — operator_config: when this operator was verified for the EU registry.
--
-- Registry access is not permanent. An operator holds "verified economic
-- operator" status only until the electronic identification means it verified
-- with expire, and in any case **no longer than three years** from the date of
-- verification. Once that lapses it can no longer register new passports or
-- modify registration data until it verifies again.
--
-- Nothing modelled that, so the first sign of expiry would have been
-- registrations starting to fail against a live registry, with no local
-- explanation. One timestamp is enough to see it coming: the three-year cap is
-- derived from it.
--
-- NULL means "never verified" — the correct state for a deployment that has not
-- onboarded to the registry, and distinct from "verified, but we don't know
-- when".
-- ============================================================================

ALTER TABLE odal.operator_config
  ADD COLUMN IF NOT EXISTS registry_verified_at TIMESTAMPTZ;

COMMENT ON COLUMN odal.operator_config.registry_verified_at IS
  'When this operator completed EU registry identity verification. Verified '
  'status expires when the eID means used expire, and at most three years from '
  'this date — whichever comes first. NULL = never verified.';
