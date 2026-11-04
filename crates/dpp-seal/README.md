# dpp-seal

eIDAS electronic seals for published passports: one `SealPort` implementation, plus the
code that reads a stored seal back, checks its issuer against the EU Trusted Lists and
renews its archive timestamp. Part of [dpp-engine](../../README.md), under the Business
Source License 1.1.

> [!NOTE]
> **Status: experimental.** Sealing works end to end with the node's own development
> sealer, and every seal it makes says it is not qualified. No qualified sealing is
> available yet. A qualified seal certificate is issued to a legal person, so each
> operator needs its own before its seals carry legal weight.

## Backends

`SEAL_PROVIDER` selects the backend. An unrecognised value fails the boot.

| `SEAL_PROVIDER` | Backend | Legal weight | Allowed under `NODE_PROFILE=production` |
|---|---|---|---|
| `local` | The development sealer: real detached CAdES up to the LTA structure, under a certificate and timestamp authority the node generates for itself. Both say "NOT A QUALIFIED SEAL / TIMESTAMP" in their organisation field | None | No |
| unset or `none` | `GhostSeal`: no seal is produced, and every attempt is logged | None | No |

The local sealer exists so every path that reads a seal (inspection, the seal routes,
timestamp renewal, evidence dossiers) can be exercised against a realistic envelope.
The backend is a trait (`SealBackend`) behind `QtspSealAdapter`, so a qualified provider
can be added without changing anything that reads seals.

## What is sealed

`SHA-256(passport.jwsSignature)`: the digest of the compact JWS as stored. The JWS is
fixed at publish and commits to the whole signed payload, so the seal is a
countersignature saying this operator signature existed at this time. Sealing the
document itself would cover fields that change after publish (`status`, `lintResult`)
and break on the next lint. `dpp-vault`'s seal service builds the digest; this crate only
ever sees a hex digest.

Under eIDAS (Regulation (EU) No 910/2014) Art. 35(2), the presumption of integrity and
origin attaches to a seal being qualified, not to its envelope format, so CAdES carries
it the same way JAdES or XAdES would.

## Reading seals back

| Module | Answers |
|---|---|
| `inspect` | What certificate is behind a stored seal, and does the seal still cover the passport's current signature? |
| `qualification` | Was that certificate issued by a qualified trust service provider when the seal was made, or signed by the node itself? |
| `trustlist` | Fetches and parses the EU list of trusted lists and each Member State's list (eIDAS Art. 22), anchored to the Official Journal. Refreshed daily with `TRUSTED_LIST_REFRESH=on` |
| `timestamp` | RFC 3161 timestamps from any authority (`SEAL_TIMESTAMP_SOURCE=rfc3161`), and archive-timestamp renewal for stored seals |

The local sealer's seals verify cryptographically, because they claim nothing beyond
"this key signed this digest". A qualified seal should be validated by a party other than
the node that obtained it.

## Configuration

The SEAL section of [`.env.example`](../../.env.example) documents every variable. For
the experimental setup:

```bash
SEAL_PROVIDER=local
SEAL_LOCAL_KEY_PATH=/data/seal-local      # default ./.seal-local; back it up with the key store
SEAL_CONFORMANCE_LEVEL=LTA                # B, T, LT or LTA; LTA is the default
```

An unrecognised `SEAL_PROVIDER` or `SEAL_CONFORMANCE_LEVEL` fails the boot rather than
falling back, so a typo can never leave passports unsealed, or sealed at a lower level,
without warning.

## Modules

```text
src/
├── backend/        SealBackend trait, QtspSealAdapter, provider selection, GhostSeal
├── local/          development sealer and timestamp authority
├── cades/          CMS/CAdES construction and parsing, certificate paths, archive timestamps
├── inspect.rs      SealInspector
├── qualification/  qualified-issuer determination
├── trustlist/      EU Trusted List fetch, parse, verify and cache
└── timestamp/      RFC 3161 source and archive-timestamp renewal
```

`tests/fixtures/local/README.md` explains the large trusted-list fixtures that are
fetched rather than committed.

## Licence

[Business Source License 1.1](../../LICENSE).
