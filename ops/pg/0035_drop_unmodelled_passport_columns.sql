-- ============================================================================
-- 0035 — drop the two passport columns that model nothing.
--
-- `0004` reserved ten scalar columns for values that would live in the `doc`
-- JSONB. Eight of them project a field that exists: `version` and
-- `supersedes_id` (written since the amend path), `granularity`,
-- `retention_until`, `product_id`, `assessed_at` and `ruleset_version` (written
-- as of this change), and `serial_number`, which is reserved for a field the
-- core library does not carry yet — tracked upstream, and kept for that reason.
--
-- `template_version` and `presentation_profile_id` are not in that group. They
-- reference a product-template and presentation-profile model that exists
-- nowhere: no field, no type, no handler, no reference of any kind in the
-- workspace outside `0004` itself. Nothing has ever intended to write them.
--
-- Dropping them loses nothing, because nothing was ever there. Keeping them
-- would cost something: a column reads as authoritative whether or not anything
-- writes it, so `WHERE presentation_profile_id IS NULL` returns every row and
-- looks like a fact about the data rather than an artefact of the column never
-- having been populated. That is the failure this pair invites, and the reason
-- to remove them rather than leave them documented.
--
-- Re-adding a column is a one-line migration on the day a model needs it.
-- ============================================================================

ALTER TABLE odal.passport DROP COLUMN template_version;
ALTER TABLE odal.passport DROP COLUMN presentation_profile_id;
