# dpp-common

Shared telemetry initialisation, config loading, and HTTP error serialisation for
[Odal Node](https://odal-node.io) platform services.

This crate is a thin bootstrapping layer. All platform services (`dpp-vault`,
`dpp-identity`, `dpp-integrator`) import from here instead of each wiring up
`tracing-subscriber` + `opentelemetry` + `config` independently.

---

## When to use this crate

- You are writing or extending a platform service and need structured logging or
  OpenTelemetry tracing.
- You need the standard config-loading convention (`ODAL_*` env variables + optional
  `.env` file via `dotenvy`).
- You need to serialize error responses in the RFC 7807 / Problem Details format.

## When NOT to use this crate

- You only need domain types → `dpp-domain` or `dpp-types`.
- You are writing a plugin or core crate — `dpp-common` is platform-only (BSL-1.1).

---

## Modules

```
dpp_common
├── config        Config-loading helper (wraps the `config` crate + dotenvy)
├── event         Internal event bus types shared across services
├── http_problem  RFC 7807 ProblemDetail response type for Axum handlers
└── telemetry     tracing-subscriber + OpenTelemetry SDK initialisation
```

### `telemetry`

Call `telemetry::init(service_name, log_level)` once at startup. Sets up
a `tracing-subscriber` fmt layer and an optional OTLP exporter when
`OTEL_EXPORTER_OTLP_ENDPOINT` is set.

### `http_problem`

`ProblemDetail` implements `IntoResponse`. Handlers return it instead of raw
`StatusCode` + string, so all error shapes are uniform across services.

### `config`

Each service defines its own `Config` struct and calls `config::load::<Config>()`
which merges env variables (with `ODAL_` prefix stripping) and the optional `.env` file.

---

## Relationship to other crates

| Crate | Role |
|---|---|
| `dpp-vault` | Imports `config`, `telemetry`, `http_problem` |
| `dpp-identity` | Imports `telemetry` |
| `dpp-integrator` | Imports `telemetry`, `http_problem` |
| `dpp-node` | Imports `config`, `telemetry` for the fused binary |

---

## License

BSL-1.1 — see [LICENSE](../../LICENSE)
