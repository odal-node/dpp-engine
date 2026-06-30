# dpp-integrator

CSV/Excel-to-DPP inbound adapter for [Odal Node](https://odal-node.io) —
manufacturers upload spreadsheets; the integrator parses them, validates each row,
and creates draft passports in the vault asynchronously.

This is the high-throughput alternative to the CLI's `odal import` command. While
the CLI posts records one-at-a-time for immediate per-row feedback, the integrator
handles arbitrarily large files as background batch jobs and exposes a polling endpoint
for status.

---

## HTTP API

All endpoints except `/health` require `Authorization: Bearer odal_sk_…`.

| Method | Path | Description |
|---|---|---|
| `GET` | `/health` | Liveness probe |
| `GET` | `/api/v1/templates/{sector}` | Download a pre-filled CSV template for a sector |
| `POST` | `/api/v1/import/{sector}` | Upload a CSV or Excel file; returns a `job_id` |
| `GET` | `/api/v1/imports/{job_id}` | Poll job status and per-row results |

### Sector dispatch

The `sector` path parameter (`battery`, `textile`, `electronics`, …) is passed to the
parser so sector-specific column mappings and validation rules are applied. The sector
key must match a key in `dpp-domain`'s `SectorCatalog`.

### Job lifecycle

`POST /import` returns `{ "job_id": "<uuid>" }` immediately. The batch runs in the
background; `GET /imports/{job_id}` reports `pending → running → done | failed` and
a per-row breakdown of successes and errors. Jobs are held in an `InMemoryJobStore`
(node restart clears them; a persistent store is the Phase 2 plan).

---

## Module structure

```
src/
├── config.rs               Config (vault URL, batch concurrency)
├── domain/
│   ├── csv_parser.rs       CSV + TSV row → DPP create request
│   ├── xlsx_parser.rs      Excel (.xlsx) row → DPP create request
│   ├── validator.rs        Per-row field validation before vault submission
│   └── batch_runner.rs     Async batch executor (bounded concurrency via semaphore)
├── handlers/
│   ├── import.rs           Multipart file upload handler
│   ├── job_status.rs       Job polling handler
│   └── templates.rs        CSV template download
├── infra/
│   ├── job_store.rs        InMemoryJobStore (UUID-keyed, Arc<Mutex<…>>)
│   └── vault_client.rs     VaultHttpClient — POST to vault /api/v1/dpp per row
├── router.rs               Route table
└── state.rs                AppState (vault client, job store, batch concurrency)
```

---

## Relationship to other crates

| Crate | Role |
|---|---|
| `dpp-domain` | `Passport` shape and `SectorCatalog` for sector validation |
| `dpp-vault` | Receives the per-row `POST /api/v1/dpp` calls from `VaultHttpClient` |
| `dpp-node` | Mounts this crate's router under `/integrator` |
| `dpp-cli` | `dpp import` uses the vault endpoint directly; for large async loads use this service |

---

## License

BSL-1.1 — see [LICENSE](../../LICENSE)
