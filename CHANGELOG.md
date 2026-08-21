# Changelog

All notable changes to dpp-engine are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
under the pre-1.0 conventions in [VERSIONING.md](docs/governance/VERSIONING.md): a
**minor** bump may contain breaking changes, each listed below under a
**Breaking** heading with a migration note.

## [Unreleased]

### Breaking


- **A battery passport can no longer be published without the content its
  category makes mandatory.** Publishing an electric-vehicle, LMT or industrial
  battery now requires all 38 fields the Commission's guidance marks mandatory
  for it, and a passport missing any of them is refused with every missing field
  named at once. A draft that published before this release may be refused until
  those fields are supplied.

  The gate is `dpp-core`'s, added in 0.17.0, and this engine was not reaching it.
  `publish` set `status`, `published_at` and `retention_locked` by hand and never
  called `Passport::transition_to`, which is the only path to the check —
  `check_mandatory_content` is private to `dpp-domain` precisely so a consumer
  cannot decline it while still transitioning. Setting the three fields directly
  declined it. Publish now transitions, and keeps only what core has no view of:
  `retention_until` from this deployment's sector catalog, and `qr_code_url` from
  its resolver.

  **Also refused: a battery passport carrying no `sectorData` at all.** The gate
  returns before asking which fields are missing, so a battery with no sector
  data stops publishing rather than publishing empty.

  **Portable and SLI batteries are unaffected**, deliberately. The guidance
  covers three categories and core declines to invent requirements for the
  others; the engine inherits that scope rather than over-applying the gate. That
  is a real hole, held open until a source covering those categories exists — and
  it is now pinned by a test, so it cannot close by accident.

  Suites whose subject is not battery content — credentials, audit trails,
  suspension, registry status — now use `portable` fixtures. That is choosing a
  valid product category, not evading the gate: the gate itself is covered by
  tests that assert the refusal, name the missing fields, and check that a
  refused first publish leaves no `publishedAt` and no retention lock. Core is
  explicit that a half-applied first publish would be unrepairable, since
  retention lock is permanent.

- **Pinned to `dpp-core` 0.17.0.** Three of its changes are visible here, and
  **one of its new refusals is still not reached by this engine** — see the note
  at the end of this entry. The count is stated because "we adopted what the
  release changed" and "we adopted the parts that touched our types" must not
  look the same from the changelog.

  **Battery passports stored under schema versions below v2.5.0 can no longer be
  read.** `batteryType` became required and closed at v2.5.0 (EU 2023/1542
  Annex VI Part A point 2, via Annex XIII point 1(a)). A record written before
  the mandate carries no such value and `dpp-domain` refuses to upgrade it rather
  than inventing a regulatory classification the operator never stated — the
  right call, and it means no lens can rescue those documents. The frozen-document
  guard records each affected shape in `UNREADABLE_FIXTURES` with its reason; the
  fixtures themselves are untouched, because a frozen document edited to make a
  test pass is no longer evidence of anything. **This is only defensible while no
  such document exists in any deployment.**

  **Disclosure is now resolved from the passport's own schema version.** A
  published passport is filtered by the classes in force when its signature was
  frozen, not by whatever the catalog says today — otherwise a later
  reclassification silently changes what an already-signed passport serves, and
  body and proof disagree for reasons no reader can distinguish from tampering.
  `public_policy` takes the version and returns `Option`; an unknown sector *or
  version* now fails closed.

  The fail-closed backstop moved with it, and this is the part worth reading
  twice: it used to key on "is the sector unknown to the catalog". That was the
  same condition while the policy was unversioned. It is not any more — a
  **known** sector at an **unknown** version resolves to no policy, and a
  sector-only check would have served every `sectorData` field publicly. It now
  keys on whether the policy resolved.

  **`batteryType` is a required CSV column.** The battery import template gains
  it, and a row without a recognised value is rejected naming the accepted set.
  Previously an absent or misspelled value parsed to `None` and produced a
  passport missing a mandatory field instead of a failed row.

  **Two of 0.17.0's new refusals were unreached when the repin landed.** Both
  are compliance gates core added, and both live on methods this engine did not
  call. One is now wired — see the mandatory-content entry above, which adopts
  `Passport::transition_to`.

  The other still is not. `Passport::validate()` is called nowhere in this
  repo, so the same release's requirement that an unsold-goods passport carry an
  in-scope `commodity_code` agreeing with its `productCategory` remains
  unreachable. Not a regression — the refusal is new in 0.17.0 and was never
  enforced here — but a rule core added and this engine does not run is worth
  naming rather than leaving to be discovered. Tracked in #110.

- **A seal request now names the conformance level it wants, and a backend that
  cannot produce it is refused.** `SEAL_CONFORMANCE_LEVEL` selects it —
  `B`, `T`, `LT` or `LTA` — and defaults to **`B-LT`**, the first baseline
  level that stays verifiable after the signing certificate expires, and
  therefore the first that suits a passport, whose retention lock is
  permanent. An unrecognised value fails the boot rather than falling back,
  so a deployment that asked for `B-LTA` and misspelled it cannot seal lower
  than it believes it is sealing.

  **`SEAL_PROVIDER=local` stops sealing at the default.** The development
  sealer signs with a self-signed certificate and adds no timestamp and no
  revocation material, so it advertises `BaselineB` and nothing above it. At
  `B-LT` its requests are now refused, and a local node seals again only with
  `SEAL_CONFORMANCE_LEVEL=B`. That is the intended consequence: a seal that
  cannot outlive its own certificate should not silently satisfy a request for
  one that can.

  **The check is new, not just the level.** `SealCapabilities` was advertised by
  every backend and consulted by none — `QtspSealAdapter` forwarded whatever it
  was handed, so a node asking for `B-LT` from a backend enabled only for `B-T`
  received whatever the provider chose to return and recorded it as what was
  asked for. Nothing would have surfaced the difference until the seal stopped
  verifying, years later, with the evidence dossier still naming the higher
  level. `can_produce` now runs in the adapter **before** the backend is called,
  because every drained row is billable and a call already destined to produce
  the wrong level should not be paid for to discover that.

  **The contract is now pinned by core's own kit.** `dpp-domain` ships
  `ports::seal::conformance::check_seal_port`, and nothing in this repo — its
  only real implementor — ran it. A test now does, against the local development
  sealer, because the kit seals once per advertised pair and would spend real
  money against a live QTSP. It covers refusing the unadvertised, returning the
  format that was asked for rather than substituting one, and verdict coherence:
  no pass founded on nothing checked, and no placeholder read as a qualified
  pass.

  A refused row backs off and eventually exhausts, which the boot reconciliation
  log and the `seal_outbox_*` gauges already report as published-but-unsealed.


- **`NODE_PROFILE=production` now refuses a `Sandbox` trust tier, not only a
  ghost.** A production node asserts that its passports are backed by real
  authorities; admitting a sandbox tier made that untrue, and a provider's test
  certificate could seal a passport claiming to be real. The tiers are ordered
  `Ghost < Sandbox < Live` so a profile states a floor rather than enumerating
  what it rejects — adding a tier later cannot silently pass an existing guard.

  **Migration.** A node running `NODE_PROFILE=production` against a provider's
  test environment now fails to boot, naming the ports that resolved too low.
  Either set the new **`NODE_PROFILE=sandbox`** — a full node in every respect
  except that the authorities behind it are test ones, and still a hard boot
  failure on ghosts — or point the backend at its production endpoint with
  production credentials. Sandbox is deliberately a property of the *deployment*
  rather than a tier a production node may quietly carry: running it as its own
  environment is the closest rehearsal of production there is, and keeping the
  two apart is what stops a test certificate ever sealing a real passport.

### Added

- **The CLI has an automated test tier.** `cli/tests/` runs the `odal` binary as
  a child process and asserts on exit codes, output, and what lands in
  `config.toml`. Nothing in the suite previously reached the CLI's behaviour —
  only pure functions inside `cli/src/**` were covered — which is why the recent
  CLI audit had to be a manual walkthrough of every command against a clean
  `$HOME`.

  **No new dependencies.** `CARGO_BIN_EXE_odal` resolves the binary under test
  and `tempfile` was already a dev-dependency, so a child process plus two
  assertions covers what `assert_cmd` and `predicates` would have added a
  dependency subtree for.

  **The environment is set per child, never on the test process.** `std::env`
  mutation is process-global, so a suite that relied on it would describe the
  runner rather than the CLI. The harness also clears `HOMEDRIVE`/`HOMEPATH` and
  the `ODAL_*` variables — a developer with any of them exported would otherwise
  get different results — and sets the child's working directory, because
  `find_install_root` walks up from it and would otherwise find the repository's
  own compose file and shell out to `docker compose ps`.

  **No feature gate and no Docker.** The one behaviour that looked like it
  needed a live node — consistent RFC 7807 rendering — is tested against a local
  stub server that emits a problem body, because what is under test is how the
  CLI renders one rather than a node that means it. Gating this tier behind
  `integration-tests` would have kept it out of `just check`, which is the lane
  where it catches a regression.

  Each test was confirmed to fail when its behaviour is reverted, rather than
  only to pass against the fixed code.

- **`odal whoami`** reports what the configured credential actually is —
  identity, scope, and key id. It is the only authenticated route a `read`
  scoped key can reach, which is the point: `odal key list` requires `admin`,
  so a least-privilege credential previously discovered its own limits by
  having a write rejected. Local-admin Basic auth has no key row and is
  reported as such rather than given a placeholder id.

- **`odal passport validate <file>`** dry-runs a passport body against the node
  and persists nothing. Without an argument the command still checks the stored
  drafts, so the existing behaviour is unchanged.

  Both verdicts are always shown, because create and publish deliberately
  differ and collapsing them would hide the gap until publish time. The publish
  line is labelled as the **sector-data schema gate**, not as acceptance:
  publish additionally requires registry identity, and category-mandatory
  content for some product categories, and the preview runs neither. Reporting
  its pass as "would be accepted" would promise more than the node checked.

  A rejection comes back as the identical response `create` would have sent, so
  a non-2xx is the verdict. `401`/`403` are the exception — those mean the
  caller was not entitled to ask, which says nothing about the file, and are
  reported as errors rather than as a verdict about it.

- **`odal status` surfaces the node's trust posture.** The deployment profile,
  each trust port's mode, and the active ruleset version now appear, so
  `seal: ghost` is visible from the CLI. The posture lives on the authenticated
  `/node/state`, while the health probes need no credential, so an unreadable
  posture is reported as absent rather than failing the command — `status`
  keeps working for a caller who has no key. A node that reports no posture
  renders nothing, because "not reported" and "nothing is a ghost" are
  different claims and only one is safe to make.

  Only `ghost` ports are called stand-ins. `sandbox` is a real service in a
  test tier, and warning about it would teach operators to ignore the line that
  matters.

- **`odal status` no longer renders two kinds of check as one table.** HTTP
  probes have a URL and a round-trip latency; Docker containers have a name and
  a state and no latency at all. They shared a table, which gave every container
  an empty latency cell and implied it had been probed over HTTP. They are now
  two tables, and the probe failure reason moved out of the fixed-width status
  column, where anything longer than eight characters broke the rows below it.

- **`GET /vault/api/v1/whoami`** reports the presented credential's identity,
  scope and key id. A client previously had no way to discover what its
  credential was allowed to do — a read-only key found out by having a write
  rejected, which cannot be checked ahead of time. Available to every scope,
  including `read`. `keyId` is the key's row id, never the token, and is absent
  for local Basic auth.

- **`POST /vault/api/v1/dpp/validate`** dry-runs a passport body and persists
  nothing. It runs the same validation `POST /vault/api/v1/dpp` runs — one
  implementation, so a preview and the real create cannot disagree — and on
  rejection returns the identical `422` create would have returned. It reports
  **two** verdicts, `createValid` and `publishValid`, because the two gates
  deliberately differ: create is lenient about a sector with no resolvable JSON
  Schema, while publish fails closed on it. A body can be creatable and not yet
  publishable, and that gap is now visible before publish is attempted rather
  than after.


- **Sealing is answerable from the control plane** — `GET /vault/api/v1/seal`
  and `odal seal status [id]`. With an id: that passport's seal, its signing
  certificate, and whether it still covers the current signature. Without one:
  how many published passports carry no seal, operator-wide.

  Both facts were previously reachable only through Prometheus (`seal_outbox_*`
  gauges) or by curling the per-passport route with an id you had to already
  know. Neither answers "is anything unsealed", which is the question an
  operator actually has.

  **The summary counts passports, not outbox rows**, and the distinction is the
  reason for the new `SealOutbox::unsealed_published_count`. The row counts
  cannot answer it: `enqueue` runs after the publish commits, so a crash in that
  window publishes a passport that no row will ever cover, and an outbox
  reporting `pending: 0, exhausted: 0` is consistent with any number of unsealed
  passports. A summary built on rows alone would have shown all clear while the
  obligation went unmet. It shares the repair sweep's predicate so the two
  cannot drift on what "unsealed" means.

  The CLI prints no verdict on the seal itself. The node does not validate the
  CAdES and says so; inventing "valid" in the client would manufacture a claim
  the API declined to make. `superseded` renders as a fact with its explanation,
  not a failure — the seal remains valid for the signature it does cover.
- **Frozen stored-doc fixtures for battery v2.6.0, textile v1.2.0 and
  electronics v1.2.0**, and `just capture-fixture <sector>` to produce them.

  The compatibility guard had no readable battery document at all: all six
  battery fixtures are in `UNREADABLE_FIXTURES`, so `every_frozen_passport_doc_still_reads`
  skipped every one and the sector with the most schema movement had no
  protection against the next non-additive change. It has one again.

  **Captured, not written.** The recipe creates and publishes a passport through
  the real vault against real Postgres, then writes the row's `doc` column. A
  fixture authored from the current structs would deserialise back into them by
  construction — it would look like coverage and be none. What makes these
  evidence is that the create and publish paths produced everything the guard
  inspects: the schema version resolved from the catalog, `publishedAt`,
  `retentionLocked`, `version`, the stamped Annex III facility and Art. 13
  operator identifier, and the exact serde shape of `sectorData`.

  **What is not real in them:** the signer is the test harness's mock, so
  `jwsSignature` and the `disclosureSignatures` carry placeholder header and
  signature segments over a real payload, and `complianceResult` reports
  `PASSTHROUGH_NO_VALIDATION` because no sector plugin is loaded. Neither
  weakens the guard — it checks that a stored document still *deserialises*, and
  those fields are strings and a struct either way — but a frozen document
  should not be read as more than it is.

  The recipe reads the version out of the stored document rather than taking it
  as an argument, and refuses to overwrite an existing fixture — a frozen
  document that gets re-captured has stopped being evidence about the release
  that produced it.

  The battery body carries the full set its category makes mandatory rather than
  the minimum that validates, which surfaced a real cross-field rule: core
  refuses recycled content for a metal the chemistry does not contain, so an LFP
  passport cannot carry the mandatory cobalt and nickel figures at all. The
  fixture is NMC for that reason.

- **eIDAS qualified sealing, end to end** (migration `0028_seal_outbox.sql`).
  `dpp-seal` becomes a real adapter against eID Easy Cloud Direct e-Sealing,
  which aggregates qualified QTSPs and returns
  **CAdES**. `dpp-node` loads it — the crate had no dependent until now — and the
  trust report's `seal` port stops being a hardcoded `ghost`, so
  `NODE_PROFILE=production` can boot for the first time. Unconfigured, the
  adapter still delegates to `GhostSeal` and production still refuses.

  **What is sealed is `SHA-256(passport.jwsSignature)`** — the compact JWS
  string as stored, not the canonicalized document. The JWS is frozen at
  publish, while `lintResult`, `status` and `qrCodeUrl` stay mutable after it, so
  a seal over the document would be silently invalidated by a later re-lint. It
  is also reconstructible by anyone holding the passport with no canonicalization
  step, and it makes the seal a countersignature: a QTSP attesting that this
  operator signature existed at this time.

  **Sealing is queued, not inline.** Publish commits and enqueues; a drain task
  seals with backoff. Sealing is a paid third-party call, and putting it in the
  publish path would couple every publish to that provider's availability —
  trading a missing seal, which is visible and repairable, for a blocked
  publication obligation, which is neither. A published passport can therefore
  briefly carry no seal; it is absent, never a placeholder. The outbox is keyed
  `(passportId, payloadHash)` rather than by passport alone, because a re-publish
  re-signs and the new signature needs its own attestation.

  **`verify()` is not implemented for the hosted backend and says so**,
  returning a typed error. The reason is independence, not tooling: a qualified
  seal is worth exactly as much as the independence of whoever checked it, so a
  verdict issued by the node that bought the seal attests nothing a relying party
  should accept. Those seals are checked by an independent AdES validator against
  the EU Trusted List. The route and the dossier both state this plainly rather
  than letting their output read as a verdict.

- **`GET /vault/api/v1/dpp/{dppId}/seal`** returns the qualified seal together
  with the JWS it covers and that JWS's digest. The seal needs its own route
  because it is stripped from every audience view, public included: it covers the
  **full**-payload signature, so attaching it to a redacted body would hand the
  reader a proof that verifies against nothing they received. `404` when the
  passport carries no seal — an unsealed passport has no seal resource rather
  than an empty one.

- **Evidence dossiers carry the qualified seal** as a `qualifiedSeal` member,
  bound into `contentHashes` like every other member. A dossier is what an
  authority is handed, and the seal is its one member carrying an eIDAS
  Art. 35(2) presumption; it is also unreachable from a dossier otherwise, for
  the same stripping reason above. Carries `signedOverJws` and `payloadHash`
  alongside the envelope, so a verifier holding only the file has both the CAdES
  and the preimage to check it against.

- **A repair sweep for unsealed passports.** The drain only sees rows that were
  successfully queued; this covers the two cases that leave a published passport
  unsealed with nothing to notice — a crash between commit and enqueue, and a row
  that exhausted its retries during a provider outage. Targeted, so a converged
  deployment sweeps to zero work, and it only ever queues a passport carrying no
  seal at all, so it cannot double-bill. Exhausted rows are held back for six
  hours so sweep and drain do not hammer an outage together.

- **A local development sealing backend** (`SEAL_PROVIDER=local`). Signs
  in-process with a generated P-256 key under a self-signed certificate,
  producing a real detached CMS `SignedData` — the same shape a provider returns,
  so the whole pipeline is exercised without a provider account, a contract, or a
  sandbox credential. The key is persisted between runs, because a restart that
  silently invalidated every seal it had produced would teach the wrong thing
  about how seals behave.

  **It is not qualified and cannot become so.** The certificate is on no EU
  Trusted List, which is a property of the certificate rather than of this code —
  nothing in the signing or verification path differs between a self-signed key
  and a QTSP-held one. What differs is the legal weight, which is none. The node
  states that structurally by resolving this backend to the `Ghost` trust tier,
  so a production profile refuses to boot on it while the envelope still drains.

  **This backend does verify its own seals**, and is the only one that does. Its
  seals make no trust claim beyond "this key signed this digest", so a
  cryptographic check is the whole truth about them and there is no authority
  whose independence could be borrowed. It carries the digest in CMS
  `signedAttrs` and signs over their DER `SET OF` encoding, as CAdES requires,
  which is what makes the envelope self-checking: a holder of the bytes alone
  confirms the signature against the certificate travelling inside. `valid: true`
  from it means exactly that and nothing about trust.

- **`signingCertRef` names the certificate a seal was made with.** Read out of
  the returned CAdES and surfaced on the seal route, so the question "which
  certificate signed this, and was it on the EU Trusted List at the time?" no
  longer requires being handed the `.p7s` and parsing it by hand.

  **Reported by the seal, never verified.** It answers *which* certificate to ask
  about and nothing else — no chain is built, no Trusted List consulted, no
  revocation checked. A convenience field that read as verification while
  verifying nothing would be worse than an absent one, because an absent field
  prompts the question and a populated one settles it wrongly.

  A hex SHA-256 thumbprint rather than issuer+serial or a subject key identifier:
  one fixed-length value naming exactly one certificate, comparable without
  parsing, and the same thing the local backend already reports — a test asserts
  the two agree, since a field that means different things per backend is not a
  key anyone can match on. A seal the parser cannot read still stores, with the
  reference left `null`.

- **`sealedPayloadHash` and `coverage` on the seal route.** The seal envelope
  records no preimage, so a node could not previously tell a current seal from
  one superseded by a later re-publish — it could only hand both digests to an
  external validator. But the outbox row that bought the seal does carry the
  preimage and is never deleted, so the answer was already held and only ever a
  query away. `coverage` reports `current`, `superseded`, or `unknown`.

  This is the node's own record of what it *asked* to seal, not proof of what the
  CAdES covers; only an independent validator establishes the latter, and the two
  agreeing is the cross-check. `unknown` is deliberately distinct from
  `superseded`: a seal restored from a backup is very likely current, and
  branding it stale on the strength of a missing row would be the same error in
  the opposite direction.

- **A clock-skew hint on authentication failures.** `X-Timestamp` is inside the
  signed message and eID Easy allows five minutes of drift, so a wrong node clock
  produces a 401 byte-for-byte identical to a bad key. The adapter now compares
  its timestamp against the provider's `Date` header and, when the drift alone
  explains the rejection, says so — otherwise the operator rotates a perfectly
  good credential and the failure persists. `429` is likewise typed separately
  from a generic provider error, with `Retry-After` surfaced when present.

- **An Art. 8 recycled-content determination, with a receipt — the first
  calculation this engine performs on a passport.** `CalcBatteryStrategy` starts
  from the passthrough's answer, so the declared metrics are lifted exactly as
  they are on any other node, then attaches an EU 2023/1542 Art. 8
  minimum-recycled-share determination: `rulesetVersion`, `assessedAt` and a
  `CalculationReceipt` under `receipt`. Those three fields existed on
  `ComplianceResult` and nothing had ever populated them, which is why
  `calcReceipts` in the evidence dossier was documented as always empty.

  **It runs host-side rather than in the battery plugin.** The plugin already
  checks Art. 8 and keeps doing so. What it cannot do is mint a receipt:
  `dpp-calc` is not reachable from `wasm32-wasip1` without pulling `chrono`,
  `uuid`, `sha2` and `serde_jcs` into every plugin binary, and a receipt minted
  inside a sandbox is only as trustworthy as the sandbox. A threshold change
  would also mean recompiling and re-signing ten artefacts.

  **Which battery, and when, decides everything.** Scope is taken from the
  battery's Art. 8 category — and for industrial batteries its energy capacity,
  read from the rated figure or nominal V × Ah. Declared shares are filtered to
  the metals the chemistry actually contains, so an LFP cell is never reported
  short of the cobalt or nickel it cannot hold. A battery Art. 8 does not reach
  produces no finding at all: an obligation that does not apply is not one an
  operator has failed.

  Two states are reported as warnings rather than silently: a battery whose
  `placedOnMarketDate` is absent gets `market_date_missing` and **no
  determination**, because without the date there is no phase to select and
  picking today's would produce an answer that changes on 18 Aug 2031 for a
  battery that has not; and a battery in scope but placed on the market before
  its phase begins gets `not_yet_binding` naming the ruleset and the date it
  starts. Neither is a shortfall.

  **Registered on the node, and only reached where no battery plugin is
  loaded.** `boot()` hands `WasmPluginHost` a `PassthroughRegistry` with this
  strategy substituted for the passthrough battery entry. The host dispatches to
  a plugin whenever one is loaded for the sector and to this registry only when
  none is — so on a node carrying `sector-battery.wasm`, which is every node
  `compliance_trust` rates above `Ghost`, the plugin's findings are still what a
  battery passport gets. The two are not interchangeable and neither contains
  the other: the plugin checks the Commission's per-category data-point table
  and Annex VII's parameter sets, which this strategy does not, and this strategy
  mints a receipt, which the plugin cannot. Changing that precedence would trade
  one set of checks for the other, so it has not been changed.

- **`placedOnMarketDate` on passport create.** Optional on
  `POST /vault/api/v1/dpp`, and omitting it is not neutral — a determination that
  depends on a phase date has no answer without it, and the node will not
  substitute today's date to manufacture one.

### Changed

- **The API description is authored multi-file and shipped as one file.**
  `api/openapi.yaml` is now a thin root — `info`, `servers`, security schemes,
  tags and a `$ref` per path — over `api/paths/` and `api/components/`.
  `api/openapi.bundled.yaml` is the generated single file every consumer reads,
  committed so the documentation site can verify its vendored copy against a
  specific commit. `just openapi-bundle` regenerates it and CI fails if the
  committed bundle has drifted from the tree.

  Splitting discards YAML comments, so the four that carried design rationale
  were moved somewhere durable first: the fused-versus-standalone identity
  routing, the internal mTLS surface, and why `/credential/` sits outside both
  `/public` and `/api/v1` are now tag descriptions; the OpenAPI 3.1 nullable
  rule is in a new `api/README.md`.

- **The API description's version tracks the crate version.** It read `0.1.0`
  against an 0.11.0 engine. `just spec-version-check` now runs inside
  `just check` and in CI, so the two move together on a release instead of
  drifting apart between them.


- **`POST /vault/api/v1/dpp` refuses a `schemaVersion` that is not the sector's
  current one**, with `422`. Omitting it is unchanged, and remains the normal
  case.

  Previously the field was accepted and silently discarded: the handler resolved
  it, and `PassportService::create` then overwrote it from the catalog on
  persist. So no caller-supplied version ever reached the database — but nothing
  said so, and a client sending `"1.0.0"` had no way to learn it got `2.6.0`.

  That overwrite is also, as of this release, the only thing standing between a
  caller and the disclosure table its passport is served under, which the same
  release makes version-dependent (above). An older table classifies fewer
  fields and `SectorAccessPolicy` defaults the rest to public — battery v1.0.0
  annotates 11 against v2.6.0's 68, so a passport filtered at v1.0.0 would serve
  `stateOfHealth` and thirteen others publicly. That hazard is pinned by
  `an_older_schema_version_widens_the_public_view`. Refusing the mismatch at the
  edge means the guarantee no longer rests on a single line in the service.

- **Two battery fields became public** at core's battery schema v2.6.0, on its
  cited reading of Annex XIII: `criticalRawMaterials` (point 1(b), listed
  alongside chemistry and hazardous substances as publicly accessible material
  composition) and `dueDiligenceUrl` (point 1(d)). Both are widenings of what the
  public and AAS doors emit. The cross-door masking tests name their fields
  explicitly rather than re-reading the catalog, so each had to be re-checked
  against the schema's stated basis rather than silently dropped.

- **The electronics page renders a device-type label, not the wire value.**
  `productCategory` became a closed `DeviceType` with kebab-case values, so
  rendering it raw would have put `other-mobile-phone` in front of a consumer.
  Unrecognised values pass through untouched — a token this mapping does not know
  is one it cannot honestly relabel.

- **`productCategory` is gone from the documented passport response.** Core
  removed `Passport.product_category` in 0.17.0, so the API spec described a
  field the response no longer carries. No wire change: the field was
  `skip_serializing_if = "Option::is_none"` and every write path set it to
  `None`, so the key was never emitted — only the spec claimed otherwise. The
  sector-level `productCategory` inside `sectorData` (steel, electronics) is a
  different field and is untouched.

- **Pinned to `dpp-core` 0.18.0**, superseding the 0.17.0 pin recorded above.
  Four of its changes are visible here, and **one of its new refusals is still
  not reached by this engine** — the same shape of gap the 0.17.0 entry names,
  and for the same reason.

  **`Passport` carries `placedOnMarketDate`.** Previously the date lived only on
  `BatteryData`, which left the governing law underivable for every other
  sector. It is envelope lifecycle data and it selects a rule, so it now sits
  beside `publishedAt`. Additive on the wire; `POST /vault/api/v1/dpp` accepts
  it as an optional field.

  **`ComplianceRegistry::compute` and `ComplianceStrategy::compute` take the
  governing-law date.** Threaded from `passport.placed_on_market_date` at both
  call sites — create and the publish-time violation check. Never
  `Utc::now()`:
  a determination made against today is wrong for every product not placed on
  the market today, and would change its own answer as phase dates pass. The
  Wasm plugin path deliberately does not take it, because a guest receives the
  sector payload as JSON and reads `placedOnMarketDate` from it directly, which
  is the only channel the ABI has.

  **`SealVerification` moved to the ETSI validation-indication model.** The
  `valid: bool` it carried became `indication` (passed / failed /
  indeterminate) and `checks` — what the verdict was actually founded on. The
  local sealer reports `SignatureOnly`, which is exactly what its verification
  does: the signature against the certificate carried inside the seal, no
  certificate path, no revocation, no timestamp, no Trusted List. A placeholder
  envelope now returns *indeterminate* rather than a pass or a failure, because
  no validation was attempted on it.

  **`dpp-registry`'s modules moved to the crate root**, so the imports drop a
  `registry::` segment.

  **A sector with no plugin loaded now lifts its declared metrics.** The
  previous entry promised the strategy seam would stay inert "until this engine
  repins", because `PassthroughRegistry` in 0.17.0 registered no strategies. It
  registers two in 0.18.0, so a node with no battery plugin routes battery
  through `PassthroughBatteryStrategy` and `co2eScore` now carries the declared
  figure where it was previously absent. No determination is made — the status
  is still `PassthroughNoValidation`, and the field is documented as "calculated
  **or** manufacturer-supplied" — but a reader watching that field will see it
  populate. A plugin-host integration test asserted the old absence and now
  asserts the value is carried through unchanged; it was pinning the inline
  passthrough that #131 removed, not the contract.

  **The unreached refusal:** 0.18.0 makes `Passport::validate()` refuse a
  passport whose two market dates — the new envelope field and
  `BatteryData.placedOnMarketDate` — disagree. `Passport::validate()` is still
  called nowhere in this repo, so that refusal cannot fire here. It joins the
  unsold-goods `commodity_code` check named in the 0.17.0 entry above: same
  method, same reason, and one more rule core enforces that this engine does
  not run.


- **Seal configuration is provider-neutral**: `SEAL_PROVIDER=eideasy|local|none`
  plus `SEAL_EIDEASY_*` / `SEAL_LOCAL_*`, replacing the bare `EIDEASY_*` names.
  Env var names are a published interface, so a second QTSP should be a new value
  rather than a config migration for every self-hoster. An unrecognised provider
  fails the boot, as does setting one backend's credentials without selecting it
  — both would otherwise downgrade a node configured for qualified sealing into
  one with none.

  Backends sit behind a `SealBackend` trait, each owning its own module,
  variables, validation, wire types and failure classification. Nothing outside a
  backend's module names it: the adapter holds one `dyn SealBackend` and the
  selector maps one environment value to one module, so adding a provider is
  additive and removing one leaves nothing behind. `SealProvider` is deliberately
  not `#[non_exhaustive]` — adding a backend should break every wiring site
  rather than fall into a `_` arm, which is how a node silently seals with
  something other than what it was asked for.

- **`seal` joins the retention guard's mutable keys** (`0028_seal_outbox.sql`)
  and `MUTABLE_FIELDS`. Without it the drain's write to an already-published,
  already-retention-locked row is refused outright and no passport is ever
  sealed. This does not weaken immutability, for the reason the signature fields
  do not: what the guard protects is passport *content*, and a seal is a
  statement about content frozen at a publish.

- The `MUTABLE_FIELDS` parity test now **parses `ops/pg/*.sql`** instead of
  comparing against a hardcoded copy. It claimed to machine-check that the Rust
  constant and the database trigger cannot diverge, but compared two Rust
  constants — it passed whenever those two agreed, whether or not the SQL that
  actually governs the trigger had been touched.

### Fixed

- **A packaged install can start.** `odal init` scaffolded `docker/docker-compose.yml`
  and nothing else, and `odal up` then forced that install down a path requiring
  the engine source tree, so the documented quickstart could only ever work from
  inside a checkout of this repository. Two independent failures, both fixed:

  **`odal up` decided whether to build from the profile kind.** `kind` answers
  "is this a production deployment"; it was being read as "does this operator
  have the engine source". Those coincide only for someone developing the
  engine — every self-hosted node is reached over localhost and therefore infers
  `dev` — so every packaged install was built from a source tree it did not
  have, failing with `GetFileAttributesEx …/dpp-engine: The system cannot find
  the file specified`. It now builds only when the compose file's `build:`
  context actually resolves, and uses the published image otherwise. The pull
  path always worked; the flag was overriding it.

  **The compose file bind-mounts two files `odal init` never wrote.** The
  database role-provisioning hook and its SQL live in `ops/bootstrap/`. Docker
  does not fail on a missing bind-mount source — it creates an empty
  **directory** — and the Postgres entrypoint skips a directory without
  comment. So the stack started, `odal up` reported success, and the node then
  retried `password authentication failed for user "odal_app"` for as long as it
  ran, because migration `0001` deliberately creates that role *without* a
  password and only `bootstrap.sql` sets one. Both scaffolders now write the
  whole install through one function, so neither can produce a partial one.

  **`odal up` also refuses up front** when a mount source is missing, naming the
  files and pointing at `odal init`. A silently fabricated directory is why this
  failed late and somewhere unrelated to its cause, so the check is worth having
  even once the scaffolder is fixed — an install created by an earlier version
  still has no `ops/`.

  Existing files are never overwritten, so re-running `init` on a configured
  install leaves an edited compose file alone.
- **A withdrawn passport no longer reports itself as never having existed.** The
  resolver's by-id and AAS routes took their HTTP status from the fetch result —
  404 for an unknown id, 410 for a suspended passport, 502/503 upstream — and
  then attached a body hardcoded to a 404 "Not Found" problem regardless. A
  suspended passport arrived as `410 Gone` carrying `"status": 404` and
  `"title": "Not Found"`, inverting the one distinction 410 exists to draw, for
  any client reading the structured half rather than the status line.

  The body is now built from the status it ships with, and says what actually
  happened: a withdrawn passport reads *"This passport has been withdrawn and is
  no longer served."* Error responses also carry `application/problem+json`
  rather than `application/json`, matching what the AAS route already did.

  The existing regression test asserted only the status line, which is why this
  stood. It now asserts the body agrees, with a companion test pinning that a
  genuinely absent passport still reads 404 in both halves.

  **The GS1 Digital Link route is not fixed by this** and still answers 404 for
  a suspended passport — the route a consumer reaches by scanning the product.
  The vault's by-GTIN lookup filters to `status = 'active'` inside
  `PassportRepository::find_published_by_gtin`, so the handler never learns the
  passport exists at all. That trait is defined in `dpp-core`, so making the
  lookup status-aware is a core change and a repin, not an engine one.
- **The unstated-resolver warning no longer fires on a resolver that was
  stated.** `odal profile create prod --resolver-url http://localhost:8103
  --kind prod` warned that the resolver "is still" the default and told the
  operator to set it with the flag they had just passed. The check inferred
  "nobody set this" from "the value is localhost", which breaks whenever
  localhost is the deliberate answer — as it is for a full containerised stack
  run on one machine.

  `create` and `init` now warn only when no `--resolver-url` was supplied on the
  invocation: a flag that was passed is a stated answer whatever its value. The
  value test also compares against the default rather than testing for
  localhost, so a chosen localhost resolver on a non-default port is not
  mistaken for an untouched one.

  `odal profile show` has no invocation flag to consult and cannot know whether
  a stored value was chosen or left alone, so it no longer claims one. It states
  what is true — that the profile is prod and resolves locally — and leaves the
  judgement to the operator.
- **`RESOLVER_BASE_URL` is documented in `.env.example`.** It decides the URL
  printed onto the product, and was the one variable with that consequence
  absent from the file operators are told to copy. Its default is the project's
  own demo resolver, which is not wired up: an operator who never set it minted
  QR codes that resolve to nothing, and the mistake only surfaces when someone
  scans a printed label — after the ESPR retention window has made reissuing
  expensive. Every operator serves their own resolver, so this is a value each
  deployment must state.

- **`.env.example`'s mangled characters are repaired.** Seventeen comment
  characters were double-encoded — an em dash and a middle dot read as
  Windows-1252 and re-encoded as UTF-8, rendering as `â€"` and `Â·`. Comments
  only, no functional effect, but the file is the one operators copy.

- **Every demo dataset and sector template imports again.** All of them were
  rejected outright: the GTINs were 13 digits where 14 are required, *and* their
  check digits were wrong, so padding alone did not rescue them. They are now
  valid GTIN-14 values, kept distinct — widening on the first twelve digits
  would have collapsed 176 products into 29, since many differ only in the
  thirteenth.

  The battery datasets needed a second repair: `batteryType` became required and
  the fixtures never gained the column, though `templates/battery-v1.csv`
  already had it. Values are chosen to match each product (`ev` for traction
  modules, `lmt` for the e-bike pack, `portable` for home storage).

  `05-textile-invalid-gtin.csv` keeps its purpose: it is a catalogue of distinct
  defects — too short, too long, non-numeric, bad check digit, spaces, hyphens —
  so each row keeps the defect it demonstrates rather than being made valid, and
  its one contrast row is now genuinely valid.

  `11-mixed-sectors.csv` still rejects its battery rows, and that is not a data
  defect: `detect_sector` reads the sector from the first data row and the import
  endpoint is per-sector, so a file mixing sectors is validated entirely against
  the first one. Its GTINs are corrected; the mixing behaviour is a property of
  the design.
- **An import no longer reports about eighteen quintillion successes.** A row
  can fail several checks, so the error list is longer than the number of
  rejected rows. `successCount` was `total_rows - all_errors.len()`, which
  underflows as soon as any row fails twice — and `usize` wraps rather than
  panics in release builds, so the API returned a number near `usize::MAX` and
  the CLI printed it verbatim:

  ```
  Import complete: 18446744073709551613 created, 8 failed
  ```

  Both counts are now per row, which is what their names and the line that
  renders them always implied: `successCount` is the rows that were not
  rejected, and `errorCount` the rows that were, counted once each however many
  checks a row failed. Success is deliberately not "wrote a record" — a row
  already up to date, or one that conflicted, writes nothing and is still not a
  failure. The
  `errors` array is unchanged and still carries one entry per failed field, so
  `errorCount` and `errors.length` are deliberately different numbers — now
  documented as such in the API description.

  Every existing fixture failed at most one check per row, so the two counts
  coincided and the defect stayed invisible. The regression test uses a row that
  fails two.

- **A profile pointed at a remote node no longer keeps localhost service URLs.**
  `odal profile create prod --vault-url https://node.example.com/vault` wrote a
  profile whose `identity_url` and `resolver_url` were still `localhost`, and
  neither command took a flag to set them — hand-editing `config.toml` was the
  only remedy, which nothing in either command's help text suggested existed.

  Both commands now accept `--node-url`, which settles the vault and identity
  URLs together: the single-binary node serves both sub-routers on one origin,
  so a normal install states one URL rather than three. `--vault-url` still
  works and is rejected alongside `--node-url`, since the two describe the same
  thing at different depths and a silent precedence rule would be undiscoverable.

  **The resolver is not derived from the node's origin, and is not going to be.**
  It is a separately deployed process on its own host, so guessing it would only
  replace one wrong answer with another. It takes `--resolver-url`, and a profile
  that infers `kind = prod` while keeping the localhost resolver now says so, at
  `create`, at `init`, and in `profile show` — the last of those so a profile
  written by an earlier version, which never saw the warning, still explains
  itself when an operator goes looking. The guided console prompts for it
  instead, since the operator is right there.

  **The on-disk file was also disagreeing with the CLI.** `load` normalises
  service URLs on the way in but the write path did not, so `config.toml` showed
  a localhost identity URL while every command that reported one showed the
  correct remote host. Profiles are now normalised on the way out too, so the
  file says what the CLI will do.

- **An unconfigured CLI now says so, instead of blaming the credential.** On a
  machine with no `config.toml`, every command that talks to the node reached
  localhost anyway and reported `Unauthorized — Missing or invalid Authorization
  header.` — pointing at a credential, when the actual state was that nothing
  had been configured yet. `profile list` already reported it correctly, so the
  signal existed and simply was not used. Both now say the same sentence, from
  one string, and the commands that need a credential exit non-zero while
  `profile list` still exits `0`.

  An API key supplied through `ODAL_API_KEY` with no profile on disk is a
  legitimate deployment, so the absence of **both** a profile and a credential
  is what identifies a fresh install.

  `odal status` and `odal schema check` are deliberately exempt: they read
  public endpoints and authenticate nothing, so on an unconfigured machine
  probing the localhost defaults is a truthful answer rather than a misleading
  one. Every other command that reaches the node goes through the check.

- **`odal stats` no longer prints a raw RFC 7807 body.** Against the same node,
  the same HTTP 401 rendered as a sentence from `odal key list` and as a JSON
  dump — `requestId`, `status` and `type` included — from `odal stats`, which
  was the one call site of fifty-nine that formatted the response itself
  instead of going through the shared renderer. It now goes through it too.

- **The OpenAPI lint runs.** The recipe existed and nothing invoked it, and the
  same OpenAPI 3.0 `nullable` defect reached `main` twice as a result. It is now
  a CI job, with Redocly pinned to one version in both the recipe and the
  workflow so the two cannot disagree about what the spec is allowed to contain.

- **The spec declares W3C VC Data Model 2.0**, matching the `credentials/v2`
  context the code actually emits.


- **`WasmPluginHost` now serves an unplugged sector from a real registry.** It
  returned a hard-coded `ComplianceResult::passthrough()` inline, so
  `PassthroughRegistry` — and therefore the per-sector `ComplianceStrategy` seam
  it dispatches through — **never ran in the node**, whatever `dpp-domain`
  documented about it being the extension point a compliance tier wires into.
  The host now holds an `Arc<dyn ComplianceRegistry>` fallback, defaulted to
  `PassthroughRegistry`, and `with_fallback` replaces it.

  Both halves are asserted by a test that fails on the previous behaviour: the
  fallback is consulted when no plugin is loaded, and its result is returned
  verbatim rather than replaced by a bare passthrough.

  **No behaviour changes until this engine repins.** `PassthroughRegistry` in
  the pinned `dpp-core` 0.17.0 is a unit struct registering no strategies, so
  every sector still takes the same bare passthrough it did before. The strategy
  dispatch it delegates to arrives with the next core version; this removes the
  bypass that would have kept it unreachable when it does.

- **`just build-plugins` no longer copies a months-old binary and reports
  success.** It read the built artifact from `sector-<name>/target`, which the
  sector plugins have not been built into since they moved to a shared cargo
  workspace — cargo writes to `plugins/target`. Stale per-member target
  directories from the older layout are still on disk, `ls | head -n1` found one,
  and `cp` succeeded. The battery plugin shipped here ran two months behind its
  source as a result.

  The recipe now names the artifact rather than globbing, errors when it is
  absent, and refuses to copy one older than its own source.

- **`just check-plugins`**, wired into `just check`: fails when an installed
  `plugins/*.wasm` is older than the source it was built from. Nothing noticed a
  stale plugin binary before, because nothing looked. Skips cleanly when the
  sibling `dpp-core` checkout is absent, so CI — which has neither that checkout
  nor these unsigned dev artifacts — is unaffected.


- **An exhausted seal row was terminal forever.** `enqueue` used
  `ON CONFLICT DO NOTHING`, so a passport whose seal burned its retry budget
  during a provider outage stayed published and unsealed with no way back short
  of re-publishing — which changes the very signature the seal attests to. An
  `exhausted` row is now re-armed, because it has no artifact and nothing was
  delivered to pay for; a `sealed` row still never is, since that would buy the
  same attestation twice. Caught by review before the feature shipped.

### Removed


- The `csc` module. It modelled the Cloud Signature Consortium `credentials/sign`
  flow with OAuth2 and JAdES, which is not the API, the auth model, or the
  envelope format of the provider being onboarded.

## [0.11.0] - 2026-08-04

Pins `dpp-core` 0.15.0 and opens the AAS door. The two belong in one release:
the projection has existed in core for several releases with no consumer, and
0.15.0 is the first version of it that emits a valid document — so this is the
first pin on which serving it over HTTP is an honest thing to do.

### Added

- **The AAS projection is served over content negotiation.** `GET /dpp/{id}`
  with `Accept: application/aas+json` returns an IDTA Asset Administration
  Shell Environment. This is the first time the AAS projection has been
  reachable over HTTP at all — it has existed in the core library for several
  releases with no consumer.

  It is built from the **verified signed public payload**, never the live
  database row, for the same reason the JSON-LD door is: body and signature
  must agree by construction. An Environment assembled from current state would
  drift from the view the operator actually signed.

  Field selection is not made here. `dpp_aas::build_aas_environment` filters the
  passport through the disclosure seam before any mapper sees it, so the door
  cannot widen what a public caller receives. A test asserts, field by field,
  that none of battery's eight restricted or individual-tier fields appears in
  the public output — battery because it has the most non-public fields of any
  product group, and because `stateOfHealthPct` was once served publicly.

  A passport with no GTIN — unsold-goods reports and untyped sectors, neither of
  which identifies a trade item — has no AAS asset identity, and returns `406`
  rather than an Environment with an invented `globalAssetId`.

  The Environment is **unsigned**, and every `200` says where the signed thing
  is: `Link: <…/dpp/{id}>; rel="alternate"; type="application/ld+json"`. The
  public proof covers the canonical payload, not this serialisation of it, so
  attaching the signature here would hand a verifier a proof that fails against
  the bytes it arrived with. `alternate` rather than `canonical` because the two
  representations share one URL and are separated only by `Accept` — a
  `canonical` relation would point the resource at itself. Errors carry no
  `Link`.

  AAS reads are recorded as the `json` scan variant. Telling them apart from
  JSON-LD reads would need a migration, since the `variant` column is
  `CHECK`-constrained, and is only worth doing if the distinction is ever needed.

- **A cross-door gate: the AAS door may withhold no less than the JSON-LD
  door.** The two representations reach the same passport at the same URL
  through entirely separate code — one filters here in the resolver, the other
  delegates field selection to the core library — and each had its own masking
  test with nothing comparing them. That is the shape that drifts: both tests
  keep passing while the two definitions of "public" separate.

  The comparison is driven from the served passport rather than a hand-written
  list: any key the JSON-LD door dropped must also be absent from the AAS
  projection. Structural names the AAS invents are not in the source, so they
  cannot be used to smuggle a field past it.

  The battery fixture now carries all ten of the fields battery's catalog entry
  classifies non-public, up from three. Five of the eight assertions in the
  existing AAS masking test named fields the fixture never carried, and could
  not have failed.

- **`coreVersion` on `/api/v1/info` and `/health`**, reporting the `dpp-core`
  version the node was built against.

### Breaking

- **The evidence dossier manifest carries `core_version`.** A dossier recorded
  only the node version, so it attested a compliance determination without
  naming the code that computed it — the regulatory logic, schemas and
  disclosure policy behind a verdict live in the core library, and the two
  version lines move independently.

  *Migration:* the manifest uses `deny_unknown_fields`, so this is a format
  change rather than an optional addition. No dossier exists outside tests, so
  format `"1"` is simply defined to include it rather than carrying an optional
  field permanently.

- **An unacceptable `Accept` on `/dpp/{id}` now returns `406`** instead of
  falling through to JSON-LD.

  *Migration:* deliberately narrow, and almost certainly affects nobody. An
  absent, empty, `*/*`, `application/*`, `application/json` or
  `application/ld+json` header all still reach the JSON-LD default — `*/*` is
  what curl and most HTTP clients send, and treating it as unacceptable would
  break every existing consumer. Only a header naming something the route
  genuinely cannot produce (`application/pdf`, say) now returns `406`, and the
  response names the three types that are available.

### Fixed

- **`Accept` weights are honoured.** `q=0` means "not acceptable" (RFC 9110
  §12.5.1), and naming a type then weighting it to zero is the standard way to
  say *anything but this*. `Accept: application/aas+json;q=0, application/ld+json`
  was served AAS — the one representation it asked not to receive. This route
  now agrees with `dpp-digital-link`'s own `Accept` parser, which has always
  honoured `q`.

- **`text/*` resolves to HTML instead of `406`.** Its sibling `application/*`
  was already honoured; refusing the text subtype wildcard was an oversight, not
  a policy. Narrow by design: `text/*` selects HTML only when nothing
  JSON-shaped is also acceptable, so `Accept: text/*, application/json` returns
  JSON-LD exactly as before.

- **The local-core development override was missing two crates.** `dpp-vc` and
  `dpp-aas` were split out of their former homes in `dpp-core` 0.13.0 but never
  added to `.cargo/config.toml.example`, so `just core-local` silently produced
  a build with those two resolved from the registry and everything else from the
  working tree.

- **`wasmtime` 46.0.1 → 46.0.2**, clearing RUSTSEC-2026-0222 and
  RUSTSEC-2026-0223 — low-severity advisories against the Wasm sandbox's
  internal state handling: type indices mixing between engines, and preemption
  during bulk operations.

  Shipped ahead of this release on its own, because it had to be. The advisories
  were published on 2026-07-31, the same day `main` last ran CI, so nothing
  re-ran to surface them: `main` was failing its own security audit and every
  new branch inherited the failure. A security fix gated behind an unrelated
  dependency repin is a security fix that waits for a release cycle.

### Changed

- **Pinned to `dpp-core` 0.15.0.** Two things come with it.

  Port traits dispatch on the sector's catalog key rather than the `Sector`
  enum, so `PluginHost` and `ComplianceRegistry` implementations take `&str` and
  call sites pass `Sector::catalog_key()`. No wire or database change.

  More importantly for the door above: **0.15.0 is the first release whose AAS
  projection is actually valid.** Every earlier one emitted a document no AAS
  parser would accept — `assetKind` missing, submodel references as bare
  `{"id": …}` objects, `modelType: "Reference"` on an element class that does
  not exist, empty arrays where the metamodel requires `minItems: 1`, and a
  `kind` member on the shell that no JSON Schema catches because IDTA sets
  `additionalProperties` nowhere. Serving AAS over HTTP on any earlier pin would
  have published invalid documents to integrators.

  Core now validates every Environment against metamodel 3.0, 3.1 **and** 3.2
  and must satisfy all three, so this door's output is not tied to one
  revision's reading of a rule.

- **Line endings are normalised to LF** via a first `.gitattributes`, and PR
  titles are gated on conventional commits in CI. The title gate exists because
  a squashed PR *is* a commit on `main`, and several landed as prose or as a
  branch name before anything checked.

## [0.10.0] - 2026-07-31

Pins `dpp-core` 0.13.0. Cut as a checkpoint ahead of the `dpp-core` 0.14.0
repin, so the audience-scoped access work and three core repins land on a tag
rather than accumulating unreleased.

### Breaking

- **Pinned to `dpp-core` 0.13.0.** This entry read *"Pinned to `dpp-core`
  0.11.0"* and was two repins stale — corrected on release. The 0.11.0 items
  below are unchanged and still apply; what 0.12.0 and 0.13.0 added on top is
  recorded in the three entries that follow.

- **`Passport` gains `disclosure_signatures`** (`dpp-core` 0.12.0), a
  per-audience signature map. Stored passports carry it; the audience-scoped
  read routes below are what serve from it.

- **Core crate layout moved under the boundary refactor** (`dpp-core` 0.13.0).
  The AAS projection and the verifiable-credential layer were carved into
  `dpp-aas` and `dpp-vc`, so imports move: `dpp_crypto::TrustedIssuerRegistry`
  is now `dpp_vc::TrustedIssuerRegistry`. **This repo does not depend on
  `dpp-aas` at all** — the AAS projection has no engine consumer and is not
  reachable over HTTP.
  *Migration:* re-point `TrustedIssuerRegistry` imports; no wire or database
  change.

- **The resolver serves `dpp-core`'s inlined JSON-LD context** (`dpp-core`
  0.13.0) instead of referencing remote context URLs. Both previous URLs
  returned 404, so any consumer that actually dereferenced the context failed;
  nothing was deployed, so nothing received them. The vocabulary is now inlined
  rather than hosted, because serving a context document is a commitment to keep
  a URL resolving for as long as any passport references it — years, under ESPR
  retention.

- **Retention is read from the sector catalog, with a floor applied rather than
  a refusal** (`dpp-core` 0.13.0). A sector whose catalog retention falls below
  the statutory floor previously caused the vault to refuse; it now clamps to
  the floor.
- **Sector country fields collapsed onto `countryOfOrigin`.** Aluminium,
  construction, detergent, furniture, steel, textile and toy previously used
  `countryOfManufacture` / `countryOfProduction` / `countryOfManufacturing`;
  `MaterialEntry`'s `originCountry` becomes `countryOfOrigin` too. The
  passport-level `manufacturerCountry` is a **different** field and is
  unchanged. *Migration:* CSV import templates are updated in place — the
  column is now `countryOfOrigin` (and `material_N_countryOfOrigin`); a file
  built from an older template will fail validation with a missing-required-
  field error naming the new column.
- **Passports stored under 0.10.0 or earlier are not readable.** There is no
  `serde` alias for the old field names, so an existing `doc` row either fails
  to deserialise (the six sectors where the field is required) or silently
  loses the value (textile's top-level field and `MaterialEntry`, both
  optional). No migration ships: there are no deployed nodes and no operator
  data, so a migration would be code that never runs. *Migration:* drop and
  re-seed any development or staging database.
- **The public view changed, so signatures over it changed.** `stateOfHealthPct`
  and `lintResult` are now correctly excluded (both were disclosed; the state-of-
  health leak is present in published 0.10.0 and earlier). Because
  `publicJwsSignature` signs the public view, **a passport published before this
  release will not verify against a view recomputed after it** — the bytes
  differ. Continuity snapshots render through the same path and diverge the same
  way, and the BOM graph pins components to a parent by `publicJwsHash`, which
  also changes. All of these are correctness fixes; they are listed as breaking
  because they invalidate artefacts produced earlier.
- **The QR data-carrier URL changed for every passport.** `short_serial` was cut
  from the leading bytes of a UUIDv7 — a millisecond timestamp — so serials
  sorted in creation order and decoded to the creation instant. It now derives
  from the random tail. The resolver is GTIN-keyed, so resolution is unaffected,
  but a previously printed label no longer matches a freshly generated one.
- **The local-admin credential is now sent as `Authorization: Basic`, not
  `Bearer`.** `auth_middleware` routes on the scheme: `Bearer` reaches only the
  API-key providers, `Basic` only the local-admin provider. Previously both
  arrived on the same chain, so a `Bearer base64(user:pass)` token
  authenticated as admin — the scheme was decorative, and `AUTH.md` documented
  a `Basic` header the middleware never accepted. *Migration:* send
  `Authorization: Basic base64(user:pass)`. `odal bootstrap` and the console
  first-run flow already do; any script minting the first API key by hand must
  change, and will get a 401 until it does.
- **The node refuses to boot when `DATABASE_URL` connects as a superuser
  role.** A superuser owns the audit table, so the append-only trigger cannot
  bind it and the tamper-evidence guarantee silently stops holding. *Migration:*
  connect as `odal_app` (or any non-superuser); `DATABASE_MIGRATE_URL` is
  unaffected and still needs a privileged role.

### Fixed

- **The electronics public page never showed a repairability score.** The
  section read `repairabilityScore` as a scalar, but `ElectronicsData` carries a
  `RepairabilityScore` struct (`{ overall, criteria }`) — it has done since
  before 0.10.0 — so the lookup always missed and rendered a dash. The section's
  own test asserted against a hand-written bare float, which is why nothing
  caught it. Furniture's field really is a scalar and was always correct.

### Security

- Every dependency path carrying a known advisory is gone rather than
  suppressed: the AWS SDK's legacy `rustls` alias feature (rustls 0.21 /
  rustls-webpki 0.101.7, three advisories, present in the published image) and
  the pre-0.41 `quick-xml` reached through `calamine` on the untrusted-XLSX
  import path. `cargo audit` against an unsuppressed lockfile goes from 8
  vulnerabilities and 5 warnings to 1 — an orphaned `rsa` entry that is not in
  any resolved build graph. `image` is now PNG-only, dropping an OpenEXR
  decoder stack the QR encoder never used.
- Suppressions are now a dated, code-anchored register
  (`.cargo/audit.toml` + `scripts/check-audit-register.sh`, in CI): each entry
  states its reachability as a checked category, the code fact that makes it
  true, an owner, and an expiry after which CI fails. Categories are verified
  against both a default build and the feature set the published image builds
  with — a claim true only outside the shipped artefact is not a claim about
  what operators run.
- Third-party GitHub Actions are pinned to full commit SHAs, and `Cargo.lock`
  is tracked, so CI no longer resolves an unreviewed graph on every run.

## [0.9.0] - 2026-07-27

### Added

- Privacy-safe scan telemetry: aggregate resolution counts per passport, per day,
  per surface — no IP, user agent, session, or per-event row exists in the schema,
  so nothing about the scanner can leak. The resolver counts terminal-view
  resolutions (`/dpp/{id}` html + json) in memory and flushes them to the node's
  mTLS-gated `POST /vault/internal/scan-batch` (`CN=odal-resolver`); QR-image
  renders are tracked as a **separate** metric and never summed into scans; the
  `/01/{gtin}` redirect is not counted (its followed terminal view is). Operators
  read the counts back via `GET /vault/api/v1/dpp/{id}/stats` and
  `GET /vault/api/v1/stats`. Aggregates are pruned on a rolling 24-month horizon.
  Off unless `SCAN_INGEST_URL` is configured on the resolver.
- CLI surfacing of scan telemetry: `odal stats` (operator-wide rollup) and
  `odal passport stats <id>` (per passport), both with `--days` and `--json`.
- The identity service's mTLS client-cert middleware moved to `dpp-common::mtls`
  and is now parameterised by the allowed subject CN, so the vault's scan-ingest
  route and identity's internal endpoints share one audited implementation.

### Fixed

- **mTLS internal endpoints now fail closed when `MTLS_PROXY_SHARED_SECRET` is
  unset**, instead of the previous fail-open behaviour. Any deployment of
  `/internal/sign`, `/internal/verify`, `/internal/keys/rotate`, or
  `/internal/scan-batch` that has not yet configured the proxy-binding secret
  will start returning 401 until it does — set `MTLS_PROXY_SHARED_SECRET`, or
  `MTLS_ALLOW_INSECURE=true` for local dev/CI.
- The resolver's in-memory scan counter is now bounded (50,000 tracked keys per
  metric) instead of growing without limit if the ingest endpoint is down or
  under high-cardinality traffic; a batch rejected with a 4xx is dropped instead
  of being retried forever.
- The registry-sync, webhook, and continuity-snapshot outbox `mark_*` methods
  now fail closed on an unknown row id instead of silently no-op'ing.

## [0.8.0] - 2026-07-21

### Added

- Signed sector-plugin hot-install: an admin can install or update a sector
  plugin at runtime with no node restart. The node verifies the artifact's
  detached signature against its pinned publisher key, gates the declared ABI,
  instantiate-smokes it, persists it so a restart re-loads the same set, and
  atomically hot-swaps it into service — fail-closed and last-good, so a rejected
  artifact never overwrites the live file or the running plugin. Both a portable
  `.wasm` (compiled on the node) and a precompiled `.cwasm` (loaded only if it
  matches this node's engine) are accepted.
- New endpoint: `POST /api/v1/plugins` (admin-scoped, `multipart/form-data`:
  `wasm` + `sig`, optional `sector`). New CLI: `odal plugin install <file>`
  (uploads the file and its sibling `<file>.sig`).
- Static continuity tier: publishing, suspending, archiving, or declaring
  end-of-life on a passport now queues a reconcile that a background drain
  converges against object storage — a published passport's signed public
  JSON and a rendered, banner-marked HTML page stay reachable at a stable path
  even while the node itself is down. An hourly repair sweep requeues any
  passport whose static-tier state has drifted from the database, covering
  reconciles lost between commit and enqueue as well as retries that were
  exhausted.
- The passport page renderer moved into its own shared crate (`dpp-render`) so
  the live resolver read and the continuity snapshot render through one
  implementation, closing the "two renderers" drift risk.
- Full GS1 Digital Link AI-shape resolution: `/01/{gtin}[/10/{batch}][/21/{serial}]`
  now resolves on the GTIN for every AI combination this node's own printed
  carrier can produce, not just the bare GTIN.
- `odal key use` and `odal bootstrap --admin-pass` accept the secret on stdin,
  warning when it is instead passed as a literal CLI argument (shell history
  and process-list exposure).

### Changed

- The plugin host now enforces ABI compatibility at load: a plugin whose
  declared ABI the running host cannot honour is refused (fail-closed) instead
  of being loaded and left to fail at dispatch. This applies to boot-time
  discovery as well as runtime install.
- The public passport view is now served from the payload actually signed at
  publish time, not re-derived from the live row. A field that is public but
  still mutable after publish (e.g. `lintResult`, re-stamped by every relint)
  could previously drift from the frozen `publicJwsSignature` still attached
  to it, so a consumer verifying the served body against its own signature
  saw a mismatch that was not tampering.
- `dpp-types`' content hasher now re-exports `dpp-core`'s canonical
  implementation instead of a local copy, closing a duplicate-implementation
  gap. Output is byte-identical to the prior implementation (verified against
  a golden value on the persisted audit chain hash).

### Fixed

- The GTIN-based resolver route (`/01/{gtin}`) never verified a passport's JWS
  against the operator DID, unlike every other resolver route — it served
  whatever the vault returned unverified.
- `dpp-vault` posted to `/internal/verify`, a route `dpp-identity` never
  mounted; signature verification on transfer acceptance always silently
  failed on any deployment running the standalone identity service.
- `IdentityHttpClient::sign_passport` reparsed its own input payload as a W3C
  verifiable credential, which fails for every real caller — publish,
  evidence generation, and transfer all sign non-credential-shaped payloads —
  whenever the identity service runs as a separate microservice.
- `GET /api/v1/dpp/by-identity` existed as a handler but was never mounted in
  the vault's router; the CSV/XLSX importer's identity-based matching was
  calling a dead endpoint.
- `ALLOW_UNSIGNED_PLUGINS` (the documented variable, and what `dpp-node`'s own
  error message told operators to set) and `DPP_ALLOW_UNSIGNED_PLUGINS` (what
  the loader actually checked) were two different environment variables
  gating the same decision — following the documented instructions silently
  loaded zero plugins.
- The textile CSV importer was the one sector (of five) whose validator
  skipped GTIN checksum validation; the shipped example template itself
  carried two invalid-checksum GTINs as a result of that gap.
- A structurally malformed signature segment on `/internal/verify` returned
  `500` instead of failing closed with `{"valid": false}`.
- Recording a passport status-change intent overwrote the EU registry-sync
  queue state, so suspending or deactivating a passport before its
  registration drained silently and permanently dropped that registration.

## [0.6.0] - 2026-07-13

This release consumes **dpp-core 0.8.0**, which adds the passport reference
types, the bounded graph cycle/depth check, and the schema-lens registry the
lineage, graph, and view features below build on.

### Added

- Second-life lineage: a passport may cite a `parentPassportRef` (its
  predecessor). The reference is verified by hash-pinning the referenced
  passport's published JWS — passports do not publish an issuer DID, so this is
  integrity-pinning, not signature verification. The resolver exposes the
  `predecessor`/`successor` linkset.
- Bill-of-materials graph: a passport may carry `componentRefs`.
  `GET /api/v1/dpp/{dppId}/verify-tree` walks the component tree recursively and
  verifies each node with bounded depth and node caps, path-based cycle
  detection (diamonds are not cycles), and fail-closed handling. Evidence
  dossiers embed and attest the component-graph report so tampering with it is
  detectable; the resolver exposes the `hasComponent` linkset.
- Schema views: `?schema_view=<version>` on the public reads (by id and by
  GTIN) serves the passport upcast through the registered schema lenses,
  returning `{ passport, schemaView }`.
- Evidence dossiers are now persisted: migration `0021_evidence_dossier.sql`
  adds an append-only `odal.evidence_dossier` table, backed by
  `PgEvidenceDossierRepo`.
- New evidence endpoints: `POST /api/v1/dpp/{dppId}/evidence` generates and
  stores a dossier; `GET /api/v1/evidence/{id}` fetches one; `POST
  /api/v1/evidence/{id}/verify` verifies a stored dossier; `POST
  /api/v1/evidence/verify` verifies an uploaded dossier document.
- `odal verify <dossier-id | file>` now verifies against the node instead of
  reading a local file only — same exit-code convention (0 verified, 1
  tamper, 2 unreadable/unparseable/unreachable).
- Signed outbound webhooks: operators register receiver URLs and the node POSTs
  each passport event to them, HMAC-SHA256 signed. Migration `0022_webhooks.sql`
  adds `odal.webhook_subscription` + a durable `odal.webhook_delivery` outbox,
  backed by `PgWebhookRepo`; a background drain delivers with backoff and
  survives restarts.
- New endpoints: `GET`/`POST /api/v1/webhooks`, `DELETE /api/v1/webhooks/{id}`,
  `POST /api/v1/webhooks/{id}/test` (admin-scoped). New CLI: `odal webhook
  list | add | remove | test`. See `docs/guides/WEBHOOKS.md` for receiver
  signature verification.
- New event `dpp.passport.transferred`, emitted on transfer initiate/accept so
  webhooks (and NATS) fire on handovers — previously transfer only wrote an
  audit entry.
- `WEBHOOK_ALLOW_PRIVATE_TARGETS` (default off): opt-in to deliver to private/
  loopback receivers on a self-hosted node. Off by default, an SSRF guard
  requires https + a public host.
- Fuzz and property tests: cargo-fuzz targets (`parse_csv`,
  `verify_dossier_json`) and proptest suites for the CSV parser, audit types,
  the outbound-URL SSRF guard, and component-graph grading.

### Changed

- An update that fails schema validation now returns `422 Unprocessable Entity`
  instead of `500 Internal Server Error`.
- The evidence dossier wire format (`DossierV1`, `DossierManifest`,
  `SignedLayer`) and the audit-trail wire type (`AuditEntry`) are now defined
  in this repo's `dpp-types` crate. The verification engine (signature,
  hash-chain, and transfer-chain checks) now lives in `dpp-vault`'s
  `domain::verify` module and verifies JWS signatures via `dpp-crypto`
  directly.
- `odal passport evidence <id>` now generates and stores a dossier (`POST`)
  instead of exporting one on the fly (`GET`).

### Removed

- The `dpp-evidence` crate dependency. Its dossier format and verification
  engine are dissolved into this repository (see Changed); the crate itself
  was removed from `dpp-core` and its crates.io release deleted.

### Breaking

- `GET /api/v1/dpp/{dppId}/evidence` now returns stored-dossier summaries
  instead of assembling a dossier on the fly. To get a dossier document,
  `POST` to the same path first, then `GET /api/v1/evidence/{id}`.
- `odal verify` requires a reachable node; it no longer verifies a local
  file with zero network.

## [0.5.0] - 2026-07-08

### Added

- **Evidence dossier export** (N02): `GET /vault/api/v1/dpp/{dppId}/evidence`
  assembles a self-contained, signed dossier proving a passport's full proof
  chain — both JWS signatures, DID document snapshots, the hash-chained audit
  trail, and (when present) the transfer chain and end-of-life record. New
  CLI: `odal passport evidence <id>`. Documented in `api/openapi.yaml`.
- **`odal verify <file>`**: verifies an evidence dossier fully offline using
  `dpp-evidence`'s `verify_dossier_json`, zero trust in the issuing node.
  Reports each check (`manifest_signature`, `content_integrity`,
  `full_view_signature`, `public_view_signature`, `audit_chain`,
  `transfer_chain`, `input_fidelity`, …) and exits 0 (verified), 1 (tamper
  detected), or 2 (not a valid dossier). Also available from the console's
  top-level `Verify` menu item.

### Changed

- `dpp-vault`/`dpp-types` now depend on `dpp-core`'s `dpp-evidence` crate
  (`dpp-evidence = "0.7.0"`) for the dossier wire format and the audit-trail
  type — `dpp-types::audit` re-exports `AuditEntry` from there instead of
  defining it locally (the hash-chain algorithm now has exactly one
  implementation, not a duplicate-by-doc-comment one).

### Breaking

- `IdentityPort` gains a new required method, `own_did_document`. Any custom
  `IdentityPort` implementation must add it.
- `AuditEntry::new`'s third parameter changes from `&AuthContext` to a plain
  actor string. *Migration:* `AuditEntry::new(id, action, auth, prev, new)` ->
  `AuditEntry::new(id, action, &auth.user_id, prev, new)`.

## [0.4.0] - 2026-07-06

### Changed

- dpp-core dependency pins bumped to 0.6.0, adding `dpp-rules` (with the
  `bundle` feature) as a direct dependency — unblocks the signed
  Compliance-Current ruleset bundle loader (`dpp-node::infra::ruleset`,
  added in 0.3.0), which needs `dpp_rules::bundle` to verify and hot-swap
  bundles.

## [0.3.0] - 2026-07-04

### Fixed

- Passport literals in integration tests and vault code missing the `seal`
  field after the dpp-core 0.5.0 bump (`Passport.seal: Option<SealedEnvelope>`).

### Changed

- dpp-core dependency pins bumped 0.4.1 -> 0.5.0.

## [0.2.0] - 2026-07-03

### Added

- **Registry-sync outbox** (`dpp-types::RegistrySyncOutbox`,
  `dpp-dal::PgRegistrySyncRepo`, `dpp-node::infra::registry_drain`): a durable,
  drainable retry queue for EU registry registration. Each passport publish
  enqueues an outbox row; a drain worker registers due rows against
  `RegistrySyncPort`, records the terminal (`registered`/`rejected`) or
  transient (backoff) outcome, and surfaces drain-pass stats to metrics.
- **Tamper-evident audit hash chain** (migration `0015_audit_hash_chain.sql`,
  `dpp-types::audit`): every audit entry now carries `entry_hash` (SHA-256
  over the JCS-canonicalised entry content folded with `prev_hash`), linking
  it to its predecessor. Computed in the app so canonicalisation matches
  verification exactly; the existing append-only trigger already forbids
  UPDATE/DELETE, so the chain cannot be silently rewritten.
- **Ghost-honesty trust-tier guard** (`dpp-types::trust::NodeTrustReport`):
  every trust port (seal, registry sync, archive, …) reports the tier that
  produced it — `Ghost` (placeholder), `Sandbox` (real service, non-production),
  or `Live` — and a production node fails to boot if a required port resolves
  to a ghost. List-driven: a newly wired port only inherits the guard by being
  registered in `NodeTrustReport::ports`.
- **Compliance-Current signed ruleset bundle loader**
  (`dpp-node::infra::ruleset`): rulesets ship as versioned bundles whose
  manifest is signed (compact EdDSA JWS) by an offline publisher key distinct
  from any operator key. The node pins the publisher public key, verifies
  fail-closed, and can hot-swap the active bundle without a restart. The
  bundle format and fail-closed verification live in `dpp_rules::bundle`
  (dpp-core, Apache-2.0); this crate supplies the concrete verifier, signing,
  disk reads, and hot-swappable runtime state.
- **End-of-life declaration and transfer-of-responsibility handshake**
  (`dpp-vault::handlers::eol`, `handlers::transfer`, `dpp-dal::repo_transfer`;
  migrations `0016_deactivated_state.sql`, `0017_passport_transfer.sql`):
  operators can declare a passport's end-of-life (recycled / destroyed /
  exported / lost, with derogation citation where required) and hand off
  responsibility for a passport to another operator via a signed handshake.
- **Facility and operator-identifier retire-not-delete**
  (`dpp-vault::domain::registry_identity_service`, migration
  `0013_facility_retire.sql`): facilities and operator identifiers are retired
  rather than deleted, with append-only audit and enriched registry payloads,
  so a published passport's provenance survives retirement of its source
  facility or identifier.
- Production runbook (`docs/ops/PRODUCTION-RUNBOOK.md`) for running Odal Node
  with real operators.

### Fixed

- `RUSTSEC-2026-0194` (quick-xml) mitigated with an attribute-count precheck
  in the integrator.
- An intermittent false failure in the tampered-signature ruleset test.

### Changed

- dpp-core dependency requirement bumped to `^0.3.0`.

## [0.1.0] - 2026-07-01

Initial release of the dpp-engine workspace, on PostgreSQL as the primary
and only datastore.

### Added

- `/metrics` Prometheus endpoint and HTTP metrics middleware on the node.
- Postgres integration suite `pg_integration.rs` (T1–T5: round-trip parity,
  retention/audit immutability triggers, key-prefix uniqueness, patch-merge
  semantics) plus a dedicated CI lane. Single-tenant, no RLS.
- Wasm plugin host hardening: memory limiter and fail-closed
  `PLUGIN_SIGNING_KEY` validation at startup.
- `reqwest` on `rustls-tls` (no OpenSSL requirement in the node image).

#### dpp-types

- `OperatorConfig` and `UpdateOperatorConfig` types for operator management.
- `OperatorConfigRepository` trait for operator config persistence.
- `AuthContext` with `user_id`, `plan` fields (no operator scope — single-tenant).
- `AuthProvider` trait for pluggable authentication.
- `AuditEntry` with `operator_id` scoping.
- `ApiKey`, `ApiKeyRecord`, `ApiKeyRepository` trait (no operator scoping —
  namespace isolation provides the boundary).
- `STANDALONE_OPERATOR_ID` constant for single-operator MVP.

#### dpp-dal

- `PgDal` — PostgreSQL connection pool (sqlx, single-tenant, no RLS).
- `PgPassportRepo` implementing `PassportRepository` from dpp-core.
- `PgAuditRepo` for append-only audit trail.
- `PgOperatorConfigRepo` for operator config CRUD.
- `PgApiKeyRepo` for API key management.
- Schema migrations via `PgDal::migrate` (`ops/pg/0001_extensions_roles_schemas.sql` through `0012_registry_identity_grants.sql`).

#### dpp-vault

- 27 Axum HTTP endpoints for passport CRUD, operator config, facilities, operator identifiers, and API key management.
- `CompositeAuthProvider` chaining `ApiKeyAuthProvider` and `LocalAuthProvider`.
- `PassportService` orchestrating create, update, publish, suspend, archive.
- `OperatorService` for operator config get/upsert.
- `ApiKeyService` for key lifecycle (create, list, revoke).

#### dpp-identity

- 5 HTTP endpoints: health, ready, DID document, JWS signing, key rotation.
- `KeyStore` integration for Ed25519 key management.

#### dpp-integrator

- 4 HTTP endpoints: health, CSV template download, file upload import, job status polling.
- `InMemoryJobStore` for tests.
- Batch import pipeline with per-row validation and error reporting.

#### dpp-common

- `EventBus` trait with `DppEvent` versioned envelope.
- `NoOpEventBus` for deployments without NATS.
- Well-known event subjects (`dpp.passport.*`, `dpp.import.*`).
- RFC 7807 `HttpProblem` error type.

#### dpp-plugin-host

- Wasmtime-based sandbox for sector Wasm plugins.
- 10M fuel, 64 MiB memory, deny-all WASI.
- `ComplianceRegistry` implementation that dispatches to loaded plugins.
- Fallback to `PassthroughRegistry` when no plugin is available.

#### dpp-node

- Single-binary MVP assembling vault + identity + integrator on one port.
- `NatsEventBus` — NATS JetStream publisher with 7-day retention.
- `PgJobStore` — persistent job store backed by PostgreSQL.
- `NodeConfig` — unified env-based configuration.
- Background cleanup task for expired import jobs (every 6 hours).
- Wasm plugin host boot from `PLUGINS_DIR`.
- Smoke tests (Tier 1: no DB, Tier 2: testcontainers).

#### dpp-resolver

- 4 HTTP endpoints: health, ready, content-negotiated passport read, QR code PNG.
- Redis-backed cache.

#### ops

- PostgreSQL schema migrations in `ops/pg/0001_extensions_roles_schemas.sql` through `0012_registry_identity_grants.sql`.
- Docker Compose for dev infrastructure (PostgreSQL, Redis, NATS).
- `odal` CLI bootstrap flow (`odal bootstrap`) for operator config + first API key.
- `ops/demo/` — CSV/XLSX import fixtures and JSON samples.

[0.1.0]: https://github.com/odal-node/dpp-engine/releases/tag/v0.1.0
