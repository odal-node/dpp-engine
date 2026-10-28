# Metrics and alerting

Prometheus metrics for `dpp-node` and `dpp-resolver`: where they are served, every
series the code emits, and starter alert rules. The binaries use the
[`metrics`](https://docs.rs/metrics) facade with `metrics-exporter-prometheus`. There is
no OpenTelemetry export.

## Where metrics are served

`/metrics` is never on the public API port. Each binary serves it on a separate
listener:

| Binary | API listener | Metrics listener (default) | Override |
|---|---|---|---|
| `dpp-node` | `0.0.0.0:8001` | `127.0.0.1:9100` | `METRICS_ADDR` |
| `dpp-resolver` | `0.0.0.0:8003` | `127.0.0.1:9101` | `METRICS_ADDR` |

```bash
curl -s http://127.0.0.1:9100/metrics | grep -E '^(trust_mode|passport_publish_total)'
```

- `METRICS_ADDR=` (empty) disables the listener.
- A failure to bind the metrics listener is logged and does not stop the service.
- Keeping metrics off the API port means publish counts, signing failures and tamper
  counts are not visible to anyone who can reach the API.

**Containers:** `127.0.0.1` in `METRICS_ADDR` is the container's own loopback, not the
host's. A scraper must run on the same container network (a sidecar, or a service on
the same Compose network addressing the target by service name). Do not set
`METRICS_ADDR` to a routable address to reach it from outside; if a scraper must cross
a network, use a private interface behind a network boundary, or put TLS and
authentication in front of the listener.

**A new binary must install a recorder.** `metrics::counter!` is a silent no-op in a
process with no recorder installed. Both binaries install one at start-up.

## Catalog

All series below are emitted by the current code. HTTP route labels use the matched
path template (for example `/vault/api/v1/dpp/{dppId}`), never the requested URL.

### HTTP (every service, `dpp_common::metrics`)

| Metric | Type | Labels |
|---|---|---|
| `http_requests_total` | counter | `route`, `method`, `status` |
| `http_request_duration_seconds` | histogram | `route`, `method` |

### Trust

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `trust_mode` | gauge | `port` = `compliance`, `seal`, `registry_sync`, `backup`, `credential_issuers` | Mode the port resolved to at start-up: `0` stub (`ghost`), `1` sandbox, `2` live. Built from the same report as `GET /vault/api/v1/node/state` |

### Passport publishing and auth (`dpp-vault`)

| Metric | Type | Labels |
|---|---|---|
| `passport_publish_total` | counter | `outcome` = `success`, `error` |
| `passport_publish_rejected_total` | counter | `reason` = `invalid_transition`, `missing_registry_identity`, `product_group_data_invalid`, `schema_invalid`, `mandatory_content`, `compliance_violations`, `compliance_unavailable`, `carrier_invalid`, `carrier_taken`, `signing_failed` |
| `publish_schema_unresolved_total` | counter | `productGroup` |
| `signing_failures_total` | counter | |
| `auth_failures_total` | counter | `reason` = `missing`, `invalid`, `suspended` |
| `label_inherited_total` | counter | `requested` = `serial`, `batch`; `resolved` = `batch`, `model`. A printed label resolved to a level above the one it named, for example a mistyped or forged serial resolving to the model record |
| `db_ping_total` | counter | `result` = `ok`, `error` |
| `db_ping_duration_seconds` | histogram | |

### Plugins (`dpp-plugin-host`)

| Metric | Type | Labels |
|---|---|---|
| `plugin_invocations_total` | counter | `productGroup`, `outcome` = `ok`, `error` |
| `plugin_fuel_exhausted_total` | counter | `productGroup` |
| `plugin_mem_capped_total` | counter | `productGroup` |
| `plugin_schema_unsupported_total` | counter | `productGroup` |

### Rulesets

| Metric | Type | Labels |
|---|---|---|
| `ruleset_swaps_total` | counter | |
| `ruleset_load_failures_total` | counter | |

### EU registry outboxes

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `registry_outbox_pending` | gauge | | Registrations waiting to be submitted |
| `registry_outbox_submitted` | gauge | | Submitted, awaiting the registry's asynchronous validation |
| `registry_outbox_stalled` | gauge | | Rows that keep failing |
| `registry_outbox_rejected` | gauge | | Rows the registry rejected |
| `registry_outbox_deactivated` | gauge | | |
| `registry_outbox_rejected_total` | counter | | |
| `registry_outbox_held_unverified_total` | counter | | Rows held because the operator is not verified for the registry |
| `registry_payload_rejected_total` | counter | | Payloads that failed local validation before submission |
| `registry_outbox_drain_seconds` | histogram | | Duration of a drain pass |
| `registry_transfer_outbox_pending` | gauge | | |
| `registry_transfer_outbox_stalled` | gauge | | |
| `registry_transfer_outbox_rejected` | gauge | | |
| `registry_transfer_rejected_total` | counter | | |
| `registry_transfer_drain_seconds` | histogram | | |

### Seals

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `seal_total` | counter | `outcome` = `sealed`, `retried`, `exhausted`, `misbound` | Seal requests processed by the drainer |
| `seal_seconds` | histogram | | Time per seal request |
| `seal_downgraded_total` | counter | | Seals returned at a lower conformance level than requested |
| `seal_outbox_pending`, `seal_outbox_exhausted` | gauge | | Seal queue depth and give-ups |
| `seal_broken`, `seal_unreadable`, `seal_certificate_failed` | gauge | | Stored seals the audit found invalid, unparseable, or with a failing certificate |
| `seal_archival_due`, `seal_archival_lapsed`, `seal_archival_unverifiable` | gauge | | Archive timestamps due for renewal, already lapsed, or not checkable |
| `seal_archival_renewal_total` | counter | `outcome` = `renewed`, `raced`, `store_failed`, `authority_refused`, `no_gain`, `not_renewable`, `source_failed`, `unusable` | |
| `trusted_list_verified`, `trusted_list_unavailable` | gauge | | EU Trusted Lists verified, and territories that could not be read |

### Continuity snapshots

| Metric | Type | Labels |
|---|---|---|
| `snapshot_reconcile_total` | counter | `outcome` = `stored`, `removed`, `retried`, `exhausted` |
| `snapshot_reconcile_seconds` | histogram | |
| `snapshot_outbox_pending`, `snapshot_outbox_exhausted` | gauge | |
| `snapshot_sweep_requeued_total`, `snapshot_refresh_requeued_total` | counter | |
| `snapshot_refresh_capacity` | gauge | |

### Webhooks

| Metric | Type | Labels |
|---|---|---|
| `webhook_delivery_total` | counter | `outcome` = `delivered`, `retried`, `exhausted`, `blocked` |
| `webhook_delivery_seconds` | histogram | |
| `webhook_outbox_pending`, `webhook_outbox_exhausted` | gauge | |

### Import (`dpp-integrator`) and housekeeping

| Metric | Type | Labels |
|---|---|---|
| `import_rows_total` | counter | |
| `import_rejections_total` | counter | `reason` = `unknown_product_group`, `auth`, `parse` |
| `idempotency_keys_purged_total` | counter | |

### Resolver

| Metric | Type | Labels |
|---|---|---|
| `jws_verify_total` | counter | `outcome` = `ok`, `tampered`, `disabled` |
| `cache_requests_total` | counter | `result` = `hit`, `miss` |
| `rate_limit_rejections_total` | counter | |

## Label rules

- Never label with an unbounded value: no passport id, client IP, operator id or error
  text. A caller-controlled value in a label lets anyone inflate the series count.
- Label values come from a small fixed set, as listed above. `productGroup` is bounded
  by the product group catalog.
- HTTP route labels stay on the matched path template.

## Starter alert rules

Adjust thresholds to your traffic. The first four page; the rest warn.

```yaml
groups:
  - name: odal-node
    rules:
      # A passport served by the resolver failed signature verification.
      - alert: DppTamperedSignatures
        expr: rate(jws_verify_total{outcome="tampered"}[5m]) > 0
        labels: { severity: page }

      # Signing is failing, so publishes fail.
      - alert: DppSigningFailures
        expr: rate(signing_failures_total[5m]) > 0
        for: 5m
        labels: { severity: page }

      # A trust port runs on a stub. Under a production profile a required port
      # cannot, so this means an optional port degraded or a port is missing from
      # the start-up check.
      - alert: DppTrustModeStub
        expr: trust_mode == 0
        labels: { severity: page }
        annotations:
          summary: "trust port {{ $labels.port }} is running on a stub"

      # A port's mode dropped without a deliberate change. Written as a drop, not a
      # floor, because the expected mode differs per deployment (a sandbox node sits
      # at 1). A deliberate downgrade stops alerting after 24 hours.
      - alert: DppTrustModeRegressed
        expr: trust_mode < max_over_time(trust_mode[24h])
        for: 5m
        labels: { severity: page }
        annotations:
          summary: "trust port {{ $labels.port }} dropped below its previous mode"

      - alert: DppAuthFailureSpike
        expr: rate(auth_failures_total[5m]) > 1
        for: 10m
        labels: { severity: warning }

      - alert: DppResolverRateLimited
        expr: rate(rate_limit_rejections_total[5m]) > 1
        for: 10m
        labels: { severity: warning }

      - alert: DppImportRejectionSpike
        expr: rate(import_rejections_total[5m]) > 1
        for: 10m
        labels: { severity: warning }

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

      # Outbox rows that gave up need a person.
      - alert: DppOutboxExhausted
        expr: (seal_outbox_exhausted + snapshot_outbox_exhausted + webhook_outbox_exhausted) > 0
        for: 15m
        labels: { severity: warning }

      - alert: DppRegistryOutboxStalled
        expr: registry_outbox_stalled > 0 or registry_transfer_outbox_stalled > 0
        for: 30m
        labels: { severity: warning }

      # Stored seals that no longer verify.
      - alert: DppBrokenSeals
        expr: seal_broken > 0 or seal_unreadable > 0 or seal_certificate_failed > 0
        labels: { severity: warning }
```

## Scrape configuration

Address each target by service name and take the port from that deployment's
`METRICS_ADDR`:

```yaml
scrape_configs:
  - job_name: dpp-node
    static_configs: [{ targets: ["node:9100"] }]
  - job_name: dpp-resolver
    static_configs: [{ targets: ["resolver:9101"] }]
```

The ports are the per-binary defaults. Two services in separate containers can use the
same port, so do not assume they differ.

## Tests that pin metrics

| Metric | Test | File |
|---|---|---|
| `passport_publish_total` | `publish_increments_passport_publish_total` | `crates/dpp-node/tests/smoke.rs` (integration, Docker) |
| `auth_failures_total` | `unauthenticated_request_increments_auth_failures_total` | same |
| `import_rejections_total` | `unknown_product_group_import_increments_import_rejections_total` | same |
| `jws_verify_total` | `resolve_records_jws_verify_total` | `crates/dpp-resolver/tests/resolver_e2e.rs` |
| `label_inherited_total` | `an_inherited_answer_is_counted_and_an_exact_one_is_not` | `crates/dpp-vault/src/domain/service/query.rs` |

These prove the counter fires on the handler path. They do not prove a binary's `main`
installs a recorder; check that in a deployment smoke test.

## Not yet measured

| Planned series | Purpose |
|---|---|
| `did_fetch_total{outcome}` (resolver) | Tell "could not fetch the DID document" (`503`) apart from "tampered" |
| `event_publish_failures_total{subject}` (node) | Make dropped event-bus publishes visible |
| `build_info{version,git_sha}` (both) | Version on dashboards |
| Explicit histogram buckets | `http_request_duration_seconds` and `db_ping_duration_seconds` use library defaults |
