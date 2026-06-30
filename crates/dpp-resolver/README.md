# dpp-resolver

Public QR code resolver for [Odal Node](https://odal-node.io) — fetches, verifies,
and serves Digital Product Passport records in response to GS1 Digital Link scans.

`dpp-resolver` is the only internet-facing service with no authentication requirement.
It accepts `GET /dpp/{id}` from any scanner, verifies the Ed25519 JWS signature
against the operator's `did:web` document, and returns HTML (for browser scans)
or JSON-LD (for programmatic access) based on the `Accept` header.

The crate compiles to both a native Axum binary and a `cdylib` for deployment as a
Cloudflare Worker (WASM edge target). The library surface is kept dependency-light
so both targets stay buildable.

---

## HTTP API

No authentication required.

| Method | Path | Description |
|---|---|---|
| `GET` | `/health` | Liveness probe |
| `GET` | `/ready` | Readiness probe (Redis connection check) |
| `GET` | `/dpp/{dppId}` | Resolve a passport — HTML or JSON-LD via `Accept` negotiation |
| `GET` | `/dpp/{dppId}/qr` | Generate a QR code PNG for the passport URL |

### Content negotiation

- `Accept: text/html` → styled HTML product sheet
- `Accept: application/json` (or anything else) → signed JSON-LD payload

---

## Architecture

```
Scan → resolver → Redis cache (TTL) → vault /public/dpp/{id}
                           ↓
               Ed25519 verification (did:web doc)
                           ↓
                   HTML or JSON-LD response
```

`Cache` wraps a `deadpool-redis` pool. On cache miss, the resolver fetches the
passport from `dpp-vault`'s `/public/dpp/{id}` endpoint and caches the response.
The `did:web` document (containing the operator's public key) is also cached
separately to avoid re-fetching on every request.

### Rate limiting (native binary only)

The native `main.rs` wraps the router with a per-IP fixed-window rate limiter
(`RATE_LIMIT_RPM`, default 120 req/min). Health/readiness probes are never
rate-limited. The WASM/edge target uses the edge platform's own rate limiting.

---

## Configuration (environment variables)

| Variable | Default | Description |
|---|---|---|
| `REDIS_URL` | required | Redis connection string |
| `VAULT_BASE_URL` | `http://vault:8001` | Upstream vault for cache misses |
| `OPERATOR_DID_URL` | derived from vault URL | `did:web` document URL for signature verification |
| `CACHE_TTL_SECS` | 300 | Redis TTL for cached passport records |
| `RATE_LIMIT_RPM` | 120 | Per-IP requests per minute (native binary) |
| `PORT` | 8003 | Listening port |

---

## Relationship to other crates

| Crate | Role |
|---|---|
| `dpp-domain` | `Passport` deserialization from the vault's JSON response |
| `dpp-crypto` | Ed25519 JWS verification |
| `dpp-vault` | Upstream data source — resolver fetches from `/public/dpp/{id}` |
| `dpp-node` | Does **not** embed the resolver — it runs as a separate process |

---

## License

BSL-1.1 — see [LICENSE](../../LICENSE)
