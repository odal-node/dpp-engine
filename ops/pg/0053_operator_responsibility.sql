-- ============================================================================
-- 0053 — operator_config: the role the operator answers in, and the law that
-- makes it answerable.
--
-- ESPR Annex III point (k) asks a passport to carry the name, contact details
-- and unique operator identifier of the economic operator responsible for the
-- tasks of Art. 4 of Regulation (EU) 2019/1020 or Art. 15 of Regulation (EU)
-- 2023/988, or similar tasks under other Union law applicable to the product.
-- The name, contact details and identifier are this operator's own and are
-- already held. The role it answers in, and which of those laws makes it the
-- responsible one, are facts about the operator's business that nothing here can
-- derive, so the operator states them once.
--
-- One JSON object, {"role": ..., "basis": ...}, in dpp-core's wire names. The two
-- halves are written together and read together: a role without its basis states
-- nothing, so there is no column for either alone. The object is the node's
-- default. A create request may send its own for one passport, because the basis
-- belongs to the pairing of operator and product.
--
-- NULL means not stated, and the node never fills one in: a guessed basis is a
-- false claim and not a missing one, and a published passport is corrected by a
-- successor rather than an edit.
-- ============================================================================

ALTER TABLE odal.operator_config
  ADD COLUMN IF NOT EXISTS responsibility JSONB
    CHECK (responsibility IS NULL OR jsonb_typeof(responsibility) = 'object');

COMMENT ON COLUMN odal.operator_config.responsibility IS
  'The operator''s default statement for ESPR Annex III point (k): {"role", "basis"} '
  'in dpp-core''s wire names. NULL = not stated, never defaulted.';
