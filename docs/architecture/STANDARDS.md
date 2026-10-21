# Standards Register

One row per IETF specification this repository cites: every `RFC NNNN` and every
`draft-ietf-…`. Each row records:

- the specification and the revision cited;
- its status when it was last read, the date of that read, and where it was read;
- where this repository uses it;
- what evidence backs that use;
- whether conformance is claimed.

**What is not here.** Acts of Union law, the CEN/CLC harmonised standards, and
the W3C, GS1, IDTA and ETSI specifications take too many shapes to match
reliably, so nothing checks them. The register of the library this repository
builds on, [`dpp-core`'s `STANDARDS.md`](https://github.com/odal-node/dpp-core/blob/main/docs/architecture/STANDARDS.md),
records those it cites. A specification both repositories cite has a row in
each, because this one pins dpp-core from crates.io, which does not ship `docs/`,
and a pointer row would switch the check off for exactly those specifications.

## How this register is kept true

`crates/dpp-node/tests/standard_citations.rs` finds every `RFC NNNN` and
`draft-ietf-…` cited in the repository and fails when:

- a cited specification has no row;
- an obsoleted specification is cited and its row has no `kept:` reason. The fix
  is to cite the successor. Where a superseded specification is cited on purpose,
  the row says why, and `RFC 2822` is the one case today;
- a draft is cited without its revision number, or a row claims conformance;
- a row is cited nowhere, so the register cannot outlive the citations it records;
- a row has an empty `Status as read`, or a `Read` that is not a `YYYY-MM-DD`
  date.

It reads every `.rs`, `.md`, `.toml`, `.json`, `.yml` and `.yaml` file in the
repository, plus `justfile` and `.gitattributes`, and skips build output and
hidden directories other than `.github`. It does not read this file, which is
what citations are checked against, `CHANGELOG.md`, which records what was said
at each release, or itself, whose fixtures cite on purpose.

**What the gate cannot prove.** That a recorded status is *current*. It reads a
file, not the IETF. What it proves is that every citation has a row, and that
every row has a status somebody read and dated. That makes the release-time
re-read a walk down one table, not a search.

**Every status is re-read at release.** The Pre-Release Checklist in
[`governance/RELEASE.md`](../governance/RELEASE.md) re-reads each row at its
source and updates `Read`. The source for an RFC is
`https://www.rfc-editor.org/info/rfcNNNN`, whose status line and its
"Obsoleted by" and "Updated by" lists are what the `Status as read` cell
records.

## Claiming conformance

This repository claims conformance to no specification: citing one says what the
code relies on, and implementing a part of it is not a claim. Every row therefore
says `No`, and the gate fails on anything else. The day a claim is made it needs
what dpp-core requires of one (a named conformance class, the scope, the known
deviations, and evidence that is not circular, such as the specification's own
test vectors) and a rule here that holds it to that.

## IETF

| Spec | Title | Status as read | Read | Source | Implemented in | Evidence | Conformance claimed |
|---|---|---|---|---|---|---|---|
| RFC 1918 | Address Allocation for Private Internets | Best Current Practice. Obsoletes RFC 1597, RFC 1627. Updated by RFC 6761 | 2026-10-21 | [RFC Editor](https://www.rfc-editor.org/info/rfc1918) | `dpp-common` outbound guard: private ranges are refused before a request leaves | Unit tests | No |
| RFC 2822 | Internet Message Format | Proposed Standard. Obsoleted by RFC 5322. Obsoletes RFC 822. Updated by RFC 5335, RFC 5336 | 2026-10-21 | [RFC Editor](https://www.rfc-editor.org/info/rfc2822) | `dpp-seal` eIDAS client reads a server date; the name is chrono's `parse_from_rfc2822`. **kept:** the RFC is cited because it names the format chrono's parser accepts, and the code uses that parser as a fallback; nothing here implements RFC 5322 | Unit tests (`eideasy/client_tests.rs`) | No |
| RFC 3161 | Internet X.509 Public Key Infrastructure Time-Stamp Protocol (TSP) | Proposed Standard. Updated by RFC 5816 | 2026-10-21 | [RFC Editor](https://www.rfc-editor.org/info/rfc3161) | `dpp-seal` timestamp tokens (`timestamp/rfc3161.rs`, `cades/timestamp.rs`, archive renewal); `dpp-node` renewal configuration | Unit tests; a live-authority test that is `#[ignore]`d | No |
| RFC 3279 | Algorithms and Identifiers for the Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile | Proposed Standard. Updated by RFC 4055, RFC 4491, RFC 5480, RFC 5758, RFC 8692 | 2026-10-21 | [RFC Editor](https://www.rfc-editor.org/info/rfc3279) | `dpp-seal` algorithm identifiers (`cades/signature.rs`) | Unit tests | No |
| RFC 3339 | Date and Time on the Internet: Timestamps | Proposed Standard. Updated by RFC 9557 | 2026-10-21 | [RFC Editor](https://www.rfc-editor.org/info/rfc3339) | `dpp-vault` `asOf` parameter of the versions route; `dpp-node` snapshot instants; parsing is `chrono`'s | Unit tests | No |
| RFC 3370 | Cryptographic Message Syntax (CMS) Algorithms | Proposed Standard. Obsoletes RFC 2630, RFC 3211. Updated by RFC 5754, RFC 8702 | 2026-10-21 | [RFC Editor](https://www.rfc-editor.org/info/rfc3370) | `dpp-seal` RSA signature algorithm handling (`cades/signature.rs`) | Unit tests | No |
| RFC 3739 | Internet X.509 Public Key Infrastructure: Qualified Certificates Profile | Proposed Standard. Obsoletes RFC 3039 | 2026-10-21 | [RFC Editor](https://www.rfc-editor.org/info/rfc3739) | `dpp-seal` qualified-certificate statements (`cades/certificate.rs`) | Unit tests | No |
| RFC 3986 | Uniform Resource Identifier (URI): Generic Syntax | Internet Standard. Obsoletes RFC 1808, RFC 2396, RFC 2732. Updates RFC 1738. Updated by RFC 7320, RFC 8820 | 2026-10-21 | [RFC Editor](https://www.rfc-editor.org/info/rfc3986) | `dpp-cli` percent-encoding of a query value (`cli/src/core/passport/list.rs`) | Unit tests | No |
| RFC 4055 | Additional Algorithms and Identifiers for RSA Cryptography for use in the Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile | Proposed Standard. Updates RFC 3279. Updated by RFC 5756 | 2026-10-21 | [RFC Editor](https://www.rfc-editor.org/info/rfc4055) | `dpp-seal` RSA signature algorithm identifiers, whose parameters must be NULL (`cades/signature.rs`) | Unit tests | No |
| RFC 4514 | Lightweight Directory Access Protocol (LDAP): String Representation of Distinguished Names | Proposed Standard. Obsoletes RFC 2253 | 2026-10-21 | [RFC Editor](https://www.rfc-editor.org/info/rfc4514) | `dpp-common` mTLS common-name extraction (`mtls.rs`); `dpp-types` and the API description name a certificate's distinguished names in this form | Unit tests | No |
| RFC 5126 | CMS Advanced Electronic Signatures (CAdES) | Informational. Obsoletes RFC 3126 | 2026-10-21 | [RFC Editor](https://www.rfc-editor.org/info/rfc5126) | `dpp-seal` CAdES attribute identifiers (`cades/signed.rs`) | Unit tests | No |
| RFC 5280 | Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile | Proposed Standard. Obsoletes RFC 3280, RFC 4325, RFC 4630. Updated by RFC 6818, RFC 8398, RFC 8399, RFC 9549, RFC 9598, RFC 9608, RFC 9618, RFC 9925, RFC 10007 | 2026-10-21 | [RFC Editor](https://www.rfc-editor.org/info/rfc5280) | `dpp-seal` certificate handling (`cades/signed.rs`, `qualification/`) | Unit tests | No |
| RFC 5480 | Elliptic Curve Cryptography Subject Public Key Information | Proposed Standard. Updates RFC 3279. Updated by RFC 8813 | 2026-10-21 | [RFC Editor](https://www.rfc-editor.org/info/rfc5480) | `dpp-seal` key-type survey over published certificates (`tests/ca_key_survey.rs`) | A survey test; no unit tests | No |
| RFC 5652 | Cryptographic Message Syntax (CMS) | Internet Standard. Obsoletes RFC 3852. Updated by RFC 8933, RFC 9629 | 2026-10-21 | [RFC Editor](https://www.rfc-editor.org/info/rfc5652) | `dpp-seal` signed attributes and the message digest (`cades/signature.rs`, `cades/ats.rs`); `dpp-types` and the API description name the digest binding | Unit tests | No |
| RFC 6596 | The Canonical Link Relation | Informational | 2026-10-21 | [RFC Editor](https://www.rfc-editor.org/info/rfc6596) | `dpp-resolver` AAS door gives its reason for sending an `alternate` link and not a `canonical` one (`handlers/resolve_aas.rs`) | A comment only; the `canonical` relation is not emitted | No |
| RFC 6598 | IANA-Reserved IPv4 Prefix for Shared Address Space | Best Current Practice. Updates RFC 5735 | 2026-10-21 | [RFC Editor](https://www.rfc-editor.org/info/rfc6598) | `dpp-common` URL guard: the carrier-grade NAT range 100.64.0.0/10 is refused (`url_guard.rs`) | Unit tests | No |
| RFC 6750 | The OAuth 2.0 Authorization Framework: Bearer Token Usage | Proposed Standard. Updated by RFC 8996, RFC 9700 | 2026-10-21 | [RFC Editor](https://www.rfc-editor.org/info/rfc6750) | `dpp-vault` authentication challenge naming every accepted scheme (`middleware/auth.rs`) | Unit tests | No |
| RFC 6839 | Additional Media Type Structured Syntax Suffixes | Informational. Updates RFC 3023. Updated by RFC 7303 | 2026-10-21 | [RFC Editor](https://www.rfc-editor.org/info/rfc6839) | `dpp-common` request-id middleware accepts a `+json` structured suffix (`request_id.rs`) | Unit tests | No |
| RFC 6901 | JavaScript Object Notation (JSON) Pointer | Proposed Standard | 2026-10-21 | [RFC Editor](https://www.rfc-editor.org/info/rfc6901) | `dpp-common` `Problem` field errors (`http_problem.rs`) and the `ProblemFieldError` schema | Unit tests; the OpenAPI contract test (`dpp-node/tests/openapi_contract.rs`) | No |
| RFC 7515 | JSON Web Signature (JWS) | Proposed Standard | 2026-10-21 | [RFC Editor](https://www.rfc-editor.org/info/rfc7515) | Delegated to dpp-core's `dpp-crypto`; cited by a `dpp-vault` test helper | None here | No |
| RFC 7617 | The 'Basic' HTTP Authentication Scheme | Proposed Standard. Obsoletes RFC 2617 | 2026-10-21 | [RFC Editor](https://www.rfc-editor.org/info/rfc7617) | `dpp-vault` authentication middleware, the `Basic` scheme (`middleware/auth.rs`) | Unit tests | No |
| RFC 7638 | JSON Web Key (JWK) Thumbprint | Proposed Standard | 2026-10-21 | [RFC Editor](https://www.rfc-editor.org/info/rfc7638) | Delegated to dpp-core; cited by the demo-dossier generator and the DID document schema | None here | No |
| RFC 8017 | PKCS #1: RSA Cryptography Specifications Version 2.2 | Informational. Obsoletes RFC 3447 | 2026-10-21 | [RFC Editor](https://www.rfc-editor.org/info/rfc8017) | `dpp-seal` RSA key identifiers (`cades/signature.rs`, `tests/ca_key_survey.rs`) | Unit tests | No |
| RFC 8785 | JSON Canonicalization Scheme (JCS) | Informational | 2026-10-21 | [RFC Editor](https://www.rfc-editor.org/info/rfc8785) | Delegated to dpp-core's `dpp-crypto`; cited by `dpp-identity` signing, `dpp-types` audit chain and evidence ordering, and `dpp-vault` | The audit chain's persisted golden value (`dpp-types` `audit.rs`) | No |
| RFC 9110 | HTTP Semantics | Internet Standard. Obsoletes RFC 2818, RFC 7230, RFC 7231, RFC 7232, RFC 7233, RFC 7235, RFC 7538, RFC 7615, RFC 7694. Updates RFC 3864 | 2026-10-21 | [RFC Editor](https://www.rfc-editor.org/info/rfc9110) | `dpp-resolver` `Accept` negotiation and `q=0` (§12.4, §12.5.1); `dpp-vault` authentication scheme matching (§11.1) and the public read's `Content-Location` (§8.7); `dpp-seal` eID Easy client reads the provider's `Date` header | Unit tests | No |
| RFC 9264 | Linkset: Media Types and a Link Relation Type for Link Sets | Proposed Standard | 2026-10-21 | [RFC Editor](https://www.rfc-editor.org/info/rfc9264) | `dpp-resolver` linkset responses for a GS1 label (`handlers/resolve_by_gtin.rs`) | No test names the linkset | No |
| RFC 9278 | JWK Thumbprint URI | Proposed Standard | 2026-10-21 | [RFC Editor](https://www.rfc-editor.org/info/rfc9278) | Delegated to dpp-core; cited by the DID document schema and the demo-dossier generator | None here | No |
| RFC 9457 | Problem Details for HTTP APIs | Proposed Standard. Obsoletes RFC 7807 | 2026-10-21 | [RFC Editor](https://www.rfc-editor.org/info/rfc9457) | `dpp-common` `Problem` (`http_problem.rs`), which every HTTP surface of the node, the integrator, the identity service and the resolver answers with, and the `Problem` schema | Unit tests (`http_problem.rs` asserts the media type); the OpenAPI contract test | No |
