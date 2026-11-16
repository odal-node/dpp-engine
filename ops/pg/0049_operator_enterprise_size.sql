-- ============================================================================
-- 0049 — operator_config: the operator's enterprise size class.
--
-- ESPR Art. 25(1) bars destroying unsold consumer products of Annex VII from
-- 19 July 2026. Art. 25(1) exempts micro and small enterprises, and medium-sized
-- ones until 19 July 2030. Whether a destruction declared at end of life must
-- cite a derogation (Commission Delegated Regulation (EU) 2026/296 Art. 2)
-- therefore depends on who the operator is, which no passport records. The
-- operator states it here, once.
--
-- The values are dpp-core's `EnterpriseSize` wire names. NULL means not stated,
-- and the node then treats the operator as not exempt: a destruction the ban
-- would reach is asked for a derogation rather than let through on a size
-- nobody declared.
-- ============================================================================

ALTER TABLE odal.operator_config
  ADD COLUMN IF NOT EXISTS enterprise_size TEXT
    CHECK (enterprise_size IN ('micro', 'small', 'medium', 'large'));

COMMENT ON COLUMN odal.operator_config.enterprise_size IS
  'Enterprise size class (ESPR Art. 25(1) exemptions): micro, small, medium or '
  'large. NULL = not stated, treated as not exempt from the destruction ban.';
