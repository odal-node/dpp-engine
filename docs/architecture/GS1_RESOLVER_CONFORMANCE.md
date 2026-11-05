# GS1 Conformant Resolver Standard: conformance record

This is the record behind one row of the
[standards register](STANDARDS.md): whether the resolver (`dpp-resolver`)
conforms to the **GS1 Conformant Resolver Standard, release 1.2.1** (ratified
August 2026, <https://ref.gs1.org/standards/resolver/1.2.1/>). It was read in
full on 2026-11-05, together with the two schemas it names and the compression
standard for EPC binary strings it points at.

## Verdict

**Conformance is not claimed.** Of the 25 numbered criteria in section 5 of the
standard, 21 are met, one is met by how the resolver is deployed, two do not apply
to it, and **one is met in part: criterion 5**, which asks a resolver to decompress
an EPC binary string. Until it is met in full, saying the resolver conforms would
be a claim nothing backs, which is what the wording this record replaces did.

| Item | Value |
|---|---|
| Revision | Release 1.2.1 |
| Class claimed for | A GS1-conformant resolver for the primary keys it declares |
| Scope | The GTIN (AI 01) with its qualifiers AI 22, AI 10, AI 21 and AI 235, at `/01/…`, and the description file at `/.well-known/gs1resolver`. No other primary key is served, and the description file says so |
| Deviation | Criterion 5: only the SGTIN-96 and SGTIN-198 EPC schemes are decoded (D1 below) |
| Evidence | `crates/dpp-resolver/tests/gs1_conformance.rs`, one test per criterion, named in the table below |

`crates/dpp-node/tests/gs1_resolver_conformance.rs` holds this document to its
own table: every row is numbered 1 to 25 in order, every test a row names exists,
and the register row says `No` for exactly as long as a row marked `SHALL` is not
met. Renaming a test in `gs1_conformance.rs` without editing this table fails it.

## The criteria

The wording is the standard's section 5, restated. `SHALL`, `SHOULD` and `MAY` are
its own keywords; the standard does not label a criterion mandatory or
recommended in any other way. A row can stop a claim only if its keywords include
`SHALL` or `SHALL NOT` and it is not met; criteria 7, 20 and 24 carry more than one.

| # | Section | Keyword | What it asks | Status | Evidence |
|---|---|---|---|---|---|
| 1 | 2.1, 2.5.9 | SHALL | Every qualifier of each supported primary key is supported | Met | `every_qualifier_combination_of_a_gtin_is_served` |
| 2 | 2.2 | SHALL | HTTP 1.1 or higher, for GET, HEAD and OPTIONS | Met | `get_head_and_options_are_all_answered`, `the_resolver_is_served_over_http_1_1` |
| 3 | 2.2 | SHALL | HTTP over TLS | Met by deployment | `docs/ops/PRODUCTION-RUNBOOK.md` |
| 4 | 2.2 | SHALL | CORS | Met | `cross_origin_requests_are_allowed` |
| 5 | 2.3 | SHALL | Decompress an EPC binary string | Partly met | `an_epc_binary_uri_is_decompressed_before_it_is_resolved`, `an_epc_scheme_this_resolver_does_not_decode_is_a_404`, `an_epc_with_an_impossible_field_is_a_bad_request` |
| 6 | 2.3 | SHOULD | When redirecting to another resolver, redirect the uncompressed URI | Not applicable | `a_redirect_never_leaves_the_resolver_s_own_host` |
| 7 | 2.4, 2.4.1 | SHOULD, SHALL | Validate the identifiers in the request; answer an error with `400` | Met | `an_identifier_that_cannot_be_valid_is_a_bad_request_and_is_not_looked_up` |
| 8 | 2.4.1 | SHALL | A valid link for an unknown entity is a plain `404` | Met | `a_valid_link_nobody_published_is_a_404` |
| 9 | 2.4.1 | SHALL NOT | No `200` for a request that causes an error | Met | `no_failure_is_answered_with_a_200` |
| 10 | 2.2, 2.9, 2.5.10 | SHALL | `linkType=linkset` or `Accept: application/linkset+json` returns an RFC 9264 linkset that validates against GS1's schema, holds the links of every level up to the primary key, and is anchored at the uncompressed URI | Met | `a_linkset_is_returned_without_redirecting_and_validates_against_gs1_s_schema`, `the_linkset_holds_the_links_of_every_level_up_to_the_gtin`, `the_linkset_subject_is_the_uncompressed_uri`, `a_level_the_vault_cannot_answer_fails_the_linkset` |
| 11 | 2.5.1 to 2.5.5 | SHALL | Every link has a target, a link type and a title; a media type, if given, is IANA's | Met | `every_link_has_a_target_a_type_and_a_title` |
| 12 | 2.5.8 | SHALL | A default link also carries a descriptive link type | Met | `the_default_link_is_also_described_by_a_descriptive_type` |
| 13 | 2.10 | SHOULD | A linkset's `Link` header points at a JSON-LD context | Met | `a_linkset_points_at_a_json_ld_context` |
| 14 | 2.5.8 | SHALL | One default link, with no optional attribute | Met | `exactly_one_default_link_carries_no_optional_attribute` |
| 15 | 2.6, 2.6.1 | SHALL | With nothing to match on, redirect to the default link | Met | `without_a_link_type_the_reader_is_sent_to_the_default_link` |
| 16 | 2.5.9 | SHALL | Every request URI has a default link at its level or above | Met | `a_request_with_no_record_of_its_own_gets_the_default_of_a_level_above` |
| 17 | 2.6.2 | SHALL | Redirect to the requested link type when it exists | Met | `a_requested_link_type_the_linkset_offers_is_redirected_to` |
| 18 | 2.6.2 | SHALL | `404` when the requested link type does not exist | Met | `a_link_type_the_linkset_does_not_offer_is_a_404` |
| 19 | 2.12 | SHALL | Pass the query string on when redirecting | Met | `the_query_string_is_handed_on_when_redirecting` |
| 20 | 2.6.3, 2.5.6 | SHOULD, MAY | Choose between links of one type by `Accept-Language`, `Accept` and `context` | Not applicable | `language_and_context_choose_between_nothing` |
| 21 | 3 | SHALL | A resolver description at `/.well-known/gs1resolver` that validates against GS1's schema | Met | `the_resolver_describes_itself_in_a_file_that_validates` |
| 22 | 2.5.9, 3 | SHALL | The description lists the supported primary keys | Met | `the_description_lists_gtin_and_no_other_primary_key` |
| 23 | 2.5.10 | SHALL | The GTIN qualifier rules: which combinations may carry links, and the union a query returns | Met | `the_gtin_qualifier_rules_are_kept`, `the_linkset_holds_the_links_of_every_level_up_to_the_gtin` |
| 24 | 2.14 | SHALL, MAY | Recognise the `gs1:` namespace; another namespace must not duplicate GS1's link types | Met | `only_link_types_of_the_gs1_vocabulary_are_offered`, `gs1_linkset_schema_cannot_carry_a_hyphenated_relation_host` |
| 25 | 2.13 | SHOULD | Tolerate a trailing slash | Met | `a_trailing_slash_is_tolerated` |

## What is not met, and why

### D1. Criterion 5: only two EPC schemes are decoded

A compressed Digital Link whose last segment is `eh` and lower-case hexadecimal,
or `ex` and URI-safe base 64, holds an EPC binary string, and the compression
standard for EPC binary strings says to decode it as the GS1 Tag Data Standard
does. `dpp-resolver` decodes **SGTIN-96 and SGTIN-198** (`src/domain/epc.rs`),
the two schemes for a GTIN with a serial that need no variable-length machinery.
They are checked against the compression standard's two worked examples and the
Tag Data Standard's own summary examples (appendix E.3), not against a decoder
written from the same reading.

Not decoded: **SGTIN+, DSGTIN+, SGTIN++ and DSGTIN++**, the Tag Data Standard 2.x
schemes for a GTIN, whose serials take any of six encodings and which can carry a
date or a domain name; and every scheme for a primary key this resolver does not
serve (SSCC, GRAI, GIAI and the rest). A link of one of these answers `404`, the
answer its decoded URI would get from a resolver that does not serve that key. For
the 2.x GTIN schemes that is wrong: they name a GTIN the resolver does serve, so
the answer ought to be a resolution. Nothing else about the resolver changes when
they are added, and `an_epc_scheme_this_resolver_does_not_decode_is_a_404` fails
the day one resolves, which is the cue to move this row to Met and make the claim.

## Readings of the standard

Places where the standard leaves room and this resolver chose. None is a
deviation; each is written down so a later reader does not have to rediscover it.

- **A `404` is a problem document.** The standard asks for a "simple" `404` (2.4.1).
  This resolver answers an RFC 9457 `application/problem+json` body, as every other
  public route here does, and reads "simple" as "a `404`, not a redirect or a
  `200`".
- **TLS is a deployment property (criterion 3).** The resolver process serves plain
  HTTP and the production runbook puts a TLS proxy in front of it, in the section
  named "TLS proxy". The claim holds for a resolver deployed that way, and no test
  can show it.
- **No relation outside the `gs1:` namespace is offered.** An earlier linkset
  carried `predecessor` and `hasComponent` relations in this project's own
  vocabulary, so a scanner could walk second-life lineage and the bill of
  materials. GS1's linkset schema (the one criterion 10 holds a linkset to) matches
  a relation by a pattern that has no room for a hyphen, so a relation on a host
  with one, as `ref.odal-node.io` has, fails it. A linkset that carries one is not
  a conformant linkset. Both are still in the passport itself (`derivedFrom` and
  `componentRefs`); only the linkset stopped repeating them.
  `gs1_linkset_schema_cannot_carry_a_hyphenated_relation_host` pins the cause, and
  fails if GS1 corrects the pattern.
- **A duplicated Application Identifier is refused.** The standard's validation
  notes (2.4) say to compare the values of a repeated AI and accept equal ones. A
  repeated qualifier here is a `400` whatever its value; the case the note has in
  mind, several barcodes concatenated from one label, does not arrive as a URL
  path.
- **The linkset of a granular request is built from the levels the vault holds.**
  The vault answers one record, the nearest, so a linkset reads the levels above
  it the way a label carrying less would be read (2.5.10, rule 4). A level whose
  passport is withdrawn adds no link. A level the vault cannot answer fails the
  request.
- **No language or context to choose between.** A passport has no language
  variants or contexts here, so `gs1:defaultLinkMulti` and `Accept-Language`
  matching are not used, and the description file declares no context values
  (criterion 20).
- **Several levels of one link type redirect to the nearest, and never return a
  `300`.** A request that names a serial or a lot, with a passport on record at more
  than one level, has several `pip` and `dpp` links in its linkset whose attributes
  are identical. The standard says a resolver that cannot tell which is best
  *should* answer `300 Multiple Choices` (2.6.3), and also allows any deterministic
  answer. This one redirects to the nearest level, the record a scan of that label
  ought to reach. GS1's test page grades the missing `300` a **warning**, not a
  failure, and only for a link whose request names more than the GTIN.
  `several_levels_of_one_link_type_redirect_to_the_nearest_and_never_return_a_300`
  pins it.
- **The `gs1:` link types offered are `pip`, `dpp` and `defaultLink`**, all three
  in the GS1 Web Vocabulary's list of link types read on 2026-11-05. A request for
  any other link type is a `404`, including `linkType=all`, the alias an earlier
  GS1 standard used for the linkset.
- **`linkset` is not a default link type.** The description file says
  `linkTypeDefaultCanBeLinkset: false` (2.11).

## GS1's own test suite

GS1 publishes a test suite for this release (<https://ref.gs1.org/test-suites/resolver/>,
source at `gs1/GS1DL-resolver-testsuite`, Apache-2.0). **It was not run, and is not
evidence here.** It is JavaScript that runs in a browser and sends every request
through a PHP helper hosted by the suite's author at a fixed address (`testUri`
in `GS1DigitalLinkResolverTestSuite.js`), which makes the calls from there. So it
reaches only a resolver on a public HTTPS host whose name contains a dot, and a
resolver on `localhost` is out of its reach by construction. Running it would mean
putting a node on the public internet and sending its address to a third party.
It also does not exercise every criterion: in the revision read on 2026-11-05, the
compression checks and the check of `supportedPrimaryKeys` in the description file
are commented out.

What stands in its place is `gs1_conformance.rs`, which checks the same facts (and
the ones the suite leaves out) against GS1's two JSON schemas, kept in
`crates/dpp-resolver/tests/fixtures/gs1/`, in process and in CI. The linkset
schema is identical to the Apache-2.0 copy in `gs1/linkset`. The description-file
schema is as `ref.gs1.org` serves it and carries no licence statement.

**The page's requests are replayed, not run.** Its source says what it asks and what
it looks for, so `the_requests_gs1_s_test_page_makes_are_answered_as_it_expects`
sends the same requests over a real socket with the headers its helper sends (an
`OPTIONS` from its origin, the link with `/foo` after it, a trailing slash, a query
string, `linkType=linkset`, the `Accept` probe that also sends `linkType=all`, one
request per link type the linkset lists, and a link type it does not). That is an
emulation read from source and can be wrong about it: it stands in until the page is
run against a deployed node.

Two things the page does that a deployment must meet, from reading it:

- It looks for the default link under an `anchor` equal to the address it was given,
  and this resolver writes `RESOLVER_BASE_URL` and the GTIN padded to 14 digits. So
  `RESOLVER_BASE_URL` must be exactly the origin the page is pointed at, and the page
  should be given a GTIN-14, or it finds no default link.
- It reads a link type as `gs1:` when its URI starts `https://ref.gs1.org/voc/`, which
  is the form this resolver writes.

Running GS1's suite against a deployed node, before a claim is made, is still worth
doing once; it is not a gate, because it cannot be one.
