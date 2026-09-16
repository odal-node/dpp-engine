-- ============================================================================
-- 0039 — trusted_list_cache: the EU Trusted Lists this node has verified, and
-- the territories it could not.
--
-- A qualification verdict asks "does any Member State's list name this seal's
-- issuer as a qualified CA?". Answering it needs the lists, and fetching and
-- verifying them costs ~40 MB of XML across the Union and an XAdES signature
-- check over each document. That is not work to redo per seal, and not work to
-- redo on every restart either: a node whose cache lives only in process memory
-- reports "nothing consulted" for the length of a whole refresh after every
-- deployment, and cannot tell an operator whether it is filling or broken.
--
-- One row per territory the list of trusted lists names, and a row is in
-- exactly one of two states:
--
--   * VERIFIED    — `content` holds the parsed list, `signed_by` the digest of
--                   the certificate that signed it, `verified_at` when the
--                   check ran;
--   * UNAVAILABLE — `unavailable_reason` says why the list could not be
--                   verified, in terms an operator can act on.
--
-- The CHECK enforces exactly one of those, because the whole value of this
-- table is that the two are told apart. A territory that is simply absent from
-- the table was never named by the list of trusted lists; a territory present
-- and unavailable was named and could not be read, and a verdict of "this
-- issuer is on no list" is not a statement about the Union while any exist.
-- Germany is the live example — its list does not verify against the mandated
-- signature profile, and it has one of the larger provider populations.
--
-- **The parsed form, never the documents.** Storing the XML would put ~40 MB of
-- signed material in the database that is already published, signed and
-- retrievable from its Member State. `MAX_TRUSTED_LIST_BYTES` is 8 MiB and
-- bounds a hostile fetch; it is not a retention budget.
--
-- Deliberately NOT a record of validations. Under Reg. (EU) No 910/2014 Art. 33,
-- reached for seals by Art. 40, a qualified validation service is a QTSP service
-- whose result carries the provider's own seal. Nothing written here is signed
-- and nothing here is qualified: a stored row is this node's note that it read
-- a published list, never an attestation that a seal was valid.
--
-- Single-tenant, so no `operator_id` column.
-- ============================================================================

CREATE TABLE odal.trusted_list_cache (
  -- The SchemeTerritory the list of trusted lists names. One list per territory
  -- in the machine-processable form; the PDF variants several Member States
  -- publish beside their XML are filtered out before anything reaches here.
  territory          TEXT PRIMARY KEY,

  -- The parsed UnverifiedTrustedList: territory, providers, services,
  -- histories, certificates. JSONB rather than columns because the shape is
  -- owned by the serde type that reads it back, and a list is read and written
  -- whole rather than queried into — the same arrangement every other document
  -- column here uses.
  content            JSONB,

  -- Base64 SHA-256 of the certificate whose signature was verified. Carried
  -- rather than recomputed on read: it is part of the verification record, and
  -- the signature it came from does not travel with the parsed form.
  signed_by          TEXT,

  -- When the signature check ran. A restored list is evidence that verification
  -- happened *then*; what makes it still current is the refresh policy, which
  -- reads this and the list's own NextUpdate.
  verified_at        TIMESTAMPTZ,

  -- Why this territory could not be verified, when it could not.
  unavailable_reason TEXT,

  updated_at         TIMESTAMPTZ NOT NULL DEFAULT now(),

  -- Exactly one of the two states. Without this a row could carry content and a
  -- reason, or neither, and the distinction this table exists to keep would be
  -- the first thing to rot.
  CONSTRAINT trusted_list_cache_one_state CHECK (
    (content IS NOT NULL AND signed_by IS NOT NULL AND verified_at IS NOT NULL
      AND unavailable_reason IS NULL)
    OR
    (content IS NULL AND signed_by IS NULL AND verified_at IS NULL
      AND unavailable_reason IS NOT NULL)
  )
);

-- 0010's ALL-TABLES grant was a one-time snapshot; tables added later need their
-- own grant (same pattern as 0017/0021/0022/0023/0028/0038). No DELETE: a
-- refresh overwrites a row in place, and removing a territory the list of
-- trusted lists has dropped is a policy decision nothing makes yet — when it
-- does, it adds the grant and the row in ops/pg/README.md's DELETE set with it.
GRANT SELECT, INSERT, UPDATE ON odal.trusted_list_cache TO odal_app;
