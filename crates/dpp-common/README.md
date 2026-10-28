# dpp-common

Shared infrastructure for the engine's services: the error type every HTTP surface
returns, logging set-up, metrics middleware, the event bus trait, idempotency keys,
mTLS checks and the guarded outbound HTTP client. Part of
[dpp-engine](../../README.md), under the Business Source License 1.1.

## Modules

| Module | What it provides |
|---|---|
| `http_problem` | `Problem`, the RFC 9457 problem document every handler returns on error, with constructors such as `not_found` and `unprocessable` |
| `telemetry` | `init(log_level)`: a `tracing` subscriber writing JSON, or human-readable output with `LOG_FORMAT=pretty`. There is no OpenTelemetry exporter |
| `metrics` | Axum middleware recording an HTTP request counter and latency histogram for Prometheus |
| `config` | Environment helpers: `required_var`, `port_var`, `log_level`, `cors_origins`, `resolver_base_url`, and URL credential redaction for logs |
| `event`, `event_codes` | The `EventBus` trait, the versioned `DppEvent` envelope and its subjects, and stable codes for security and business log events |
| `idempotency` | `Idempotency-Key` support: the store port, the policy table of which routes accept a key, and the middleware |
| `mtls` | Client-certificate checks for internal endpoints behind a TLS-terminating proxy |
| `url_guard` | SSRF checks for outbound URLs: `https` only, and the host is re-resolved at request time so a name pointing at a loopback, private, link-local or cloud metadata address is refused. Webhooks use it with an `allow_private` opt-out for a self-hoster's own receivers |
| `outbound` | The HTTP client for targets a third party named (such as a credential issuer's `did:web`): `url_guard` before every request, redirects not followed, a streamed body cap and a timeout |
| `request_id` | Request id generation and propagation |
| `plugin_admin`, `ruleset_admin` | Ports for plugin hot-install and ruleset reload, implemented by the plugin host and the node |
| `scan` | The scan-telemetry batch the resolver sends to the node |

## Conventions it carries

- A new error path returns `Problem`, not an ad hoc body.
- Events are published after the database commit, and a publish failure is logged,
  never returned: the database is the source of truth.
  [`docs/architecture/EVENT-BUS.md`](../../docs/architecture/EVENT-BUS.md) has the
  subjects and delivery guarantees.
- The set of routes that accept `Idempotency-Key` is defined once, in
  `idempotency::policy`, and a test in `dpp-node` checks it against the routers.

## Licence

[Business Source License 1.1](../../LICENSE).
