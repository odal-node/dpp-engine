# dpp-integrator

Bulk import for manufacturers who keep product data in spreadsheets: it parses a
CSV, TSV or XLSX upload, validates each row against its product group, and creates
draft passports in the vault. It also serves the import templates, product group
list and JSON Schemas. Part of [dpp-engine](../../README.md), under the Business
Source License 1.1.

The node mounts this crate's router under `/integrator`.

## Try it

```bash
curl -s http://localhost:8001/integrator/api/v1/templates/battery-industrial > battery.csv
# fill in rows, then:
curl -s -X POST http://localhost:8001/integrator/api/v1/import/battery-industrial \
  -H "Authorization: Bearer $ODAL_API_KEY" -F file=@battery.csv
```

Batteries are served per category: `battery-ev`, `battery-lmt` and
`battery-industrial`. An unknown key returns `404` listing the valid ones.

Every battery row states `placedOnMarketDate`. Core cannot tell whether the due
diligence report is owed without it and refuses the publish, so the importer
refuses the row first, naming it, by asking core the same question. Declaring
`belowTurnoverThreshold` does not excuse a missing date, since core asks for the
date first. A second-life battery is asked for one too, although publish would
not need it.

A battery placed on or after 18 August 2027 states the operator's Art. 47
declaration in `dueDiligenceOperatorScope`: `subject`, or `belowTurnoverThreshold`
where the operator is under the turnover threshold. Unless the battery is exempt,
`dueDiligenceUrl` carries the address of its report. A `belowTurnoverThreshold`
declaration exempts the battery, as does a second-life one, which needs neither
column. Both columns are left blank for a battery placed before that date.

## Routes

| Route | Auth | What it does |
|---|---|---|
| `GET /api/v1/templates/{productGroup}` | none | The CSV header row the importer expects |
| `GET /api/v1/product-groups`, `/product-groups/{productGroup}` | none | Product groups and their passport obligations |
| `GET /api/v1/schemas`, `/schemas/{productGroup}[/{version}]` | none | JSON Schemas, current or pinned to a version |
| `POST /api/v1/import/{productGroup}` | Bearer, write | Upload a file (5 MiB limit) |
| `GET /api/v1/imports/{job_id}` | Bearer | Poll an asynchronous import |

The integrator does not check keys itself: it forwards the caller's `Bearer` token
on each row it posts to the vault, so the vault's scope checks apply.

## Synchronous and asynchronous imports

An upload of up to 100 valid rows is processed in the request and the per-row report
is returned directly. A larger upload returns a job id at once and runs in the
background; poll `GET /api/v1/imports/{job_id}` for `queued`, `processing`,
`completed` or `failed` and the per-row results. Rows are submitted with bounded
concurrency (`BATCH_CONCURRENCY`, default 20).

In the node, jobs are stored in PostgreSQL (`PgJobStore` in `dpp-node`), so they
survive a restart. A clean-up task removes finished jobs after 30 days. The
standalone binary uses an in-memory store.

Each row is matched against existing passports by product group, product identifier
and batch, and classified as `create`, `update_draft`, `unchanged` or
`conflict_published`. Re-uploading a sheet therefore updates the drafts that
changed, skips the rows that did not, and reports rows whose passport is already
published instead of duplicating them. Send the multipart field `mode=dry_run` to
get the classified report without writing anything. Every import, dry run or not,
gets a job id and a stored report.

## Modules

```text
src/
├── router.rs
├── handlers/      import, job status, templates, product groups, schemas, health
├── domain/
│   ├── csv_parser.rs, xlsx_parser.rs   row parsing
│   ├── validate/                        per-product-group column checks
│   ├── matcher.rs                       match rows to existing passports
│   ├── battery_template.rs              per-category battery templates
│   └── batch_runner.rs                  bounded-concurrency submission
└── infra/         job store, vault HTTP client
```

## Licence

[Business Source License 1.1](../../LICENSE).
