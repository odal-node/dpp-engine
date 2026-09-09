# Metrics & Observability — Odal Node Engine

Operational telemetry for the node (`dpp-node`) and the public resolver (`dpp-resolver`).
Stack: the [`metrics`](https://docs.rs/metrics) facade + `metrics-exporter-prometheus`.
Last updated: 2026-09-08.

This document is the source of truth for **what is measured, how it is exposed, and what to
alert on**. It also records the gaps still open (see [Roadmap](#roadmap)).

---

## 1. Exposure model (security)

`/metrics` is **never** served on the public API port. Each binary installs a Prometheus
recorder at startup and serves `GET /metrics` on a **separate, private listener**:

| Binary | API port (public) | Metrics listener (private, default) | Env override |
|--------|-------------------|-------------------------------------|--------------|
| `dpp-node` | `0.0.0.0:8001` | `127.0.0.1:9100` | `METRICS_ADDR` |
| `dpp-resolver` | `0.0.0.0:8003` | `127.0.0.1:9101` | `METRICS_ADDR` |

- **Loopback by default.** A scraper in the same pod/host reaches it; the public internet does
  not. To scrape across the network, set `METRICS_ADDR` to a private interface (e.g. behind a
  k8s NetworkPolicy) — do **not** bind it to a routable address without a network boundary.
- **Disable** with `METRICS_ADDR=` (empty).
- A bind/serve failure on the metrics listener is logged but never takes the service down.

> Rationale: exposing `passport_publish_total`, `signing_failures_total`, JWS tamper counts and
> per-route latencies to anyone who can reach the API port is free reconnaissance (finding RT2-7).
> Putting `/metrics` on its own listener is the same fail-closed posture as keeping the internal
> signing routes off the public surface.

### Recorder requirement (RT2-6)

`metrics::counter!(…)` is a **silent no-op unless a recorder is installed in that process**. Both
binaries install one at startup. The resolver previously did not — so `jws_verify_total` (the
public-facing tamper signal) was dropped on the floor. If you add a new deployable that emits
metrics, it **must** install a recorder or the data is lost with no error.

---

## 2. Metric catalog

`route`/`method`/`status` on the HTTP metrics use the **matched path template** (e.g.
`/vault/dpp/{dppId}`), never the resolved URL — so high-cardinality IDs do not explode the label
space. Keep that discipline (see [Label policy](#3-label--cardinality-policy)).

### HTTP (all services, via `dpp_common::http_metrics_middleware`)

| Metric | Type | Labels | Meaning |
|--------|------|--------|---------|
| `http_requests_total` | counter | `route`, `method`, `status` | Every request, by outcome |
| `http_request_duration_seconds` | histogram | `route`, `method` | Request latency |

### Vault / signing

| Metric | Type | Labels | Meaning |
|--------|------|--------|---------|
| `passport_publish_total` | counter | `outcome` = `success` \| `error` | Publish attempts |
| `signing_failures_total` | counter | — | In-process JWS signing failures |
| `auth_failures_total` | counter | `reason` = `missing` \| `suspended` \| `invalid` | Rejected auth — **attack signal** |
| `db_ping_total` | counter | `result` = `ok` \| `error` | Readiness DB pings |
| `db_ping_duration_seconds` | histogram | — | DB ping latency |

### Trust posture (the ghost-honesty invariant)

| Metric | Type | Labels | Meaning |
|--------|------|--------|---------|
| `trust_mode` | gauge | `port` | Tier the adapter behind each trust port resolved to: **`0` ghost** (placeholder), **`1` sandbox** (real service, non-production), **`2` live**. One series per port. |

Set once per port during boot, from the same `NodeTrustReport` the `/vault/api/v1/node/state`
response is built from — so the gauge and the API answer cannot disagree. `port` values come
from the report's list, which is the whole reason the invariant is list-driven: a trust port that
is never registered there is invisible to the boot guard *and* absent from this gauge.

A `production` profile refuses to boot while a required port is a ghost, so `trust_mode == 0`
on a production node means either a **non-required** port degraded, or the boot guard did not see
that port at all. Both are worth waking up for — see the alert rules in §4.

### Resolver (public-facing)

| Metric | Type | Labels | Meaning |
|--------|------|--------|---------|
| `jws_verify_total` | counter | `outcome` = `ok` \| `tampered` \| `disabled` | Signature verification — **`tampered` is the headline security signal** |
| `cache_requests_total` | counter | `result` = `hit` \| `miss` | Resolver response cache |
| `rate_limit_rejections_total` | counter | — | Per-IP 429s — **flood signal** |

### Integrator (bulk import)

| Metric | Type | Labels | Meaning |
|--------|------|--------|---------|
| `import_rows_total` | counter | — | Rows accepted for processing (volume baseline) |
| `import_rejections_total` | counter | `reason` = `unknown_sector` \| `auth` \| `parse` | Rejected uploads — **RT2-1 parser-probing signal** |

---

## 3. Label / cardinality policy

- **Never** use an unbounded value as a label: no `dpp_id`, no client `ip`, no `operator_id`
  (a constant provenance stamp — the node is single-tenant), no free-text error strings.
- Label values must come from a **fixed, small enum** (the `reason`/`outcome`/`result` sets above).
- HTTP route labels must stay on the **matched-path template**, not the resolved path.

A label-space blow-up degrades Prometheus for everyone and can be triggered by an attacker if a
caller-controlled value ever reaches a label — treat new labels as a review checklist item.

---

## 4. Starter alert rules

PromQL sketches — tune thresholds to traffic. The first four are pages, the rest are warnings.

```yaml
# Someone is serving tampered passports against the public resolver. PAGE.
- alert: DppTamperedSignatures
  expr: rate(jws_verify_total{outcome="tampered"}[5m]) > 0
  for: 0m
  labels: { severity: page }

# Signing is broken — publishes will fail. PAGE.
- alert: DppSigningFailures
  expr: rate(signing_failures_total[5m]) > 0
  for: 5m
  labels: { severity: page }

# A trust port is serving placeholder trust. PAGE.
# On a `production` profile this should be unreachable — the node refuses to
# boot on a ghost *required* port — so it firing means either a non-required
# port degraded, or that port never reached the trust report at all and the
# boot guard could not see it. Both need a human.
- alert: DppTrustModeGhost
  expr: trust_mode == 0
  for: 0m
  labels: { severity: page }
  annotations:
    summary: "trust port {{ $labels.port }} is serving ghost (placeholder) trust"

# A port's trust tier fell without a deliberate redeploy — the silent config
# regression the honesty invariant exists to catch. PAGE.
# Written as a *drop* rather than a floor on purpose: the expected value is a
# property of the deployment (a sandbox node legitimately sits at 1), so no
# fleet-wide rule can hardcode one. The 24h window also means a deliberate
# downgrade stops alerting a day after it is made, instead of forever.
- alert: DppTrustModeRegressed
  expr: trust_mode < max_over_time(trust_mode[24h])
  for: 5m
  labels: { severity: page }
  annotations:
    summary: "trust port {{ $labels.port }} dropped below the tier it was serving"

# Credential attack / a client broke after key rotation.
- alert: DppAuthFailureSpike
  expr: rate(auth_failures_total[5m]) > 1
  for: 10m
  labels: { severity: warning }

# Resolver flood (incl. X-Forwarded-For spoof attempts, RT2-3).
- alert: DppResolverRateLimited
  expr: rate(rate_limit_rejections_total[5m]) > 1
  for: 10m
  labels: { severity: warning }

# Someone probing the import parser with bad/oversized files (RT2-1).
- alert: DppImportRejectionSpike
  expr: rate(import_rejections_total[5m]) > 1
  for: 10m
  labels: { severity: warning }

# Liveness: DB unreachable, or 5xx ratio elevated.
- alert: DppDbPingFailing
  expr: rate(db_ping_total{result="error"}[5m]) > 0
  for: 5m
  labels: { severity: warning }
- alert: DppHigh5xxRatio
  expr: |
    sum(rate(http_requests_total{status=~"5.."}[5m]))
      / sum(rate(http_requests_total[5m])) > 0.05
  for: 10m
  labels: { severity: warning }
```

## 5. Scrape configuration

Point Prometheus at the **private** metrics listeners (sidecar / same-host / in-cluster):

```yaml
scrape_configs:
  # Address the target by SERVICE NAME, and take the port from that
  # deployment's METRICS_ADDR. The ports below are the per-binary *defaults*;
  # a deployment that sets one METRICS_ADDR for every service in a compose
  # file gives them all the SAME port, which is legal — they are in separate
  # network namespaces. Never assume the two services differ by port.
  - job_name: dpp-node
    static_configs: [{ targets: ["dpp-node:9100"] }]
  - job_name: dpp-resolver
    static_configs: [{ targets: ["dpp-resolver:9101"] }]
```

### A loopback `METRICS_ADDR` binds the *container's* loopback

This is the constraint that decides where a scraper can run, and it is easy to plan around
wrongly. In a container deployment `METRICS_ADDR=127.0.0.1:<port>` is reachable **only from
inside that container's own network namespace** — not from the host, and therefore not from
anything that arrives at the host, including a tunnel or a bastion. Unless the port is
explicitly published, `curl` on the host answers nothing, and a plan that assumes otherwise
fails identically on every node.

So a scraper must either **run on the same network** as the target (a sidecar, or a service on
the same compose network, addressing it by service name as above), or the deployment must
publish the metrics port deliberately and accept what that exposes.

The tempting third option — setting `METRICS_ADDR` to a routable address so a host-side or
remote scraper can reach it — **re-opens finding RT2-7**: it puts `passport_publish_total`,
`signing_failures_total` and the JWS tamper counts back on the wire. Move the scraper onto the
network; do not move the listener onto it. If a central scraper genuinely must cross a network,
terminate that on a private interface with a network boundary (or front the listener with
bearer/TLS) — never expose a raw `/metrics` publicly.

---

## 6. Test coverage

Integration-level **metric-presence** guards (so an emission can't be silently removed/renamed):

| Metric | Guard test | File |
|--------|-----------|------|
| `passport_publish_total` | `publish_increments_passport_publish_total` | `dpp-node/tests/smoke.rs` (needs `--features integration-tests` + Docker) |
| `auth_failures_total` | `unauthenticated_request_increments_auth_failures_total` | same |
| `import_rejections_total` | `unknown_sector_import_increments_import_rejections_total` | same |
| `jws_verify_total` | `resolve_records_jws_verify_total` | `dpp-resolver/tests/resolver_e2e.rs` (no Docker) |

**Known limitation:** these prove the counter *fires on the handler path*. They do **not** prove a
binary's `main()` actually installs a recorder (RT2-6) — that wiring lives outside the router and
isn't exercised by router-level tests. Treat "does the deployable install a recorder?" as a deploy
smoke-check, not a unit test.

---

## 7. Roadmap

Implemented: exposure split (§1), resolver recorder (§1), and the attack-detection counters
(`auth_failures_total`, `rate_limit_rejections_total`, `import_rejections_total`, `import_rows_total`).

Deferred, in priority order:

1. **`did_fetch_total{outcome}`** (resolver) — separate "can't verify right now" (503) from
   "tampered" (409); today only the tamper/ok/disabled outcomes are counted.
2. **`event_publish_failures_total{subject}`** (node) — fire-after-commit drops NATS events
   silently; a counter makes that visible.
3. **`build_info{version,git_sha}`** gauge (both) — version pinning on dashboards.
4. **Explicit histogram buckets** — `http_request_duration_seconds` / `db_ping_duration_seconds`
   use library defaults; set SLO-shaped buckets via `PrometheusBuilder::set_buckets_for_metric`.
