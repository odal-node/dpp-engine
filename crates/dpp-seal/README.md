# dpp-seal

> **Not yet wired.** This crate exists as a stub. `dpp-node` does not load it yet;
> it will be injected into `PassportService` once a QTSP contract is signed and
> the EU registry API is live (~19 Jul 2026).

eIDAS qualified electronic seal adapter for [Odal Node](https://odal-node.io).

Provides CSC/QTSP wire types and `QtspSealAdapter`, a stub that delegates to
`GhostSeal` (from `dpp-domain::ports::seal`) until a QTSP contract is in place.

## What ships now

| Component | Status |
|---|---|
| `QtspSealAdapter` | Stub — delegates to `GhostSeal` when `QTSP_URL` is unset |
| `csc::CscSignHashRequest/Response` | Wire types modelling CSC Data Model v1.0.0 |
| `csc::CscCredentialInfo` | Capability discovery response shape |

## What comes later

When a QTSP contract is signed and the EU registry API is live:
1. Wire `reqwest` + OAuth2 client-credentials into `QtspSealAdapter::seal()`
2. Implement the CSC `credentials/sign` (hash-signing path) using `csc::CscSignHashRequest`
3. Confirm JAdES acceptance with the EU registry before enabling production mode

## Relationship to other crates

| Crate | Role |
|---|---|
| `dpp-domain::ports::seal` | Defines `SealPort` trait, `GhostSeal`, and the abstract types (`SealRequest`, `SealedEnvelope`) |
| `dpp-node/src/infra/` | Will wire `QtspSealAdapter` into `PassportService` at boot |

## Configuration (future)

```
QTSP_URL=https://qtsp.example.com/csc/v1    # enables the real CSC adapter
QTSP_CLIENT_ID=...                           # OAuth2 client credentials
QTSP_CLIENT_SECRET=...
QTSP_CREDENTIAL_ID=...                       # CSC credentialID for the platform seal
```

When `QTSP_URL` is absent, `QtspSealAdapter` falls back to `GhostSeal` and logs a warning.

## License

BSL-1.1 — see [LICENSE](../../LICENSE)
