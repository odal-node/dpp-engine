-- ============================================================================
-- 0042 — index a passport by its product identifier and by its printed carrier.
--
-- dpp-core 0.21.0 replaced the GTIN-only lookups with two that take an EN 18219
-- clause 5 identifier — `find_by_identifier` and `find_by_carrier` — and
-- `ProductIdentity` now keys on that identifier as well. The two indexes this
-- migration adds back them; the identity index is rebuilt over the same
-- expression.
--
-- # The identifier, as one string
--
-- The identifier is an object — `{"scheme":"gs1","gtin":…}`,
-- `{"scheme":"identificationLink","url":…}` or `{"scheme":"did","did":…}` — so
-- the expression takes whichever value key is present. It is the SQL twin of
-- `ProductIdentifier::as_str`, and it needs no scheme beside it: a GTIN is
-- digits, a link is an absolute `http(s)` URL and a DID starts `did:`, so the
-- three value spaces cannot collide.
--
-- The last arm is a stored document written before the identifier existed,
-- which carries `productGroupData.gtin`. Those documents read forward through the
-- lens chain in Rust, but SQL sees the stored bytes, and a signed record is
-- never rewritten — so the expression reads both shapes rather than a migration
-- rewriting one into the other.
--
-- 🚨 `PgPassportRepo` splices this expression into its queries from one Rust
-- macro, `identifier_sql!`. Postgres uses an expression index only for a query
-- that repeats the expression, so the two must stay identical;
-- `the_identifier_expression_is_the_one_the_index_covers` pins that.
--
-- # The carrier serial
--
-- A printed AI 21 value is the passport's effective carrier serial: the
-- attributed `carrierSerial` where the operator set one, and otherwise
-- `PassportId::default_carrier_serial` — the last ten bytes of the id as
-- lowercase hex, which is the last twenty hex digits of its canonical text. A
-- Postgres `uuid` renders as lowercase hyphenated text, so dropping the hyphens
-- and taking the right twenty characters is that derivation, and one expression
-- over the id indexes every passport without a stored copy of the default.
--
-- Added rather than edited into 0032: `sqlx::migrate!` checksums every file.
-- ============================================================================

DROP INDEX odal.idx_passport_identity;

CREATE INDEX idx_passport_identity ON odal.passport
  (product_group,
   (COALESCE(doc->'productGroupData'->'productIdentifier'->>'gtin',
             doc->'productGroupData'->'productIdentifier'->>'url',
             doc->'productGroupData'->'productIdentifier'->>'did',
             doc->'productGroupData'->>'gtin')),
   (doc->>'batchId'))
  WHERE status IN ('draft','active');

CREATE INDEX idx_passport_identifier ON odal.passport
  ((COALESCE(doc->'productGroupData'->'productIdentifier'->>'gtin',
             doc->'productGroupData'->'productIdentifier'->>'url',
             doc->'productGroupData'->'productIdentifier'->>'did',
             doc->'productGroupData'->>'gtin')));

CREATE INDEX idx_passport_carrier_serial ON odal.passport
  ((COALESCE(doc->>'carrierSerial', right(replace(id::text, '-', ''), 20))));
