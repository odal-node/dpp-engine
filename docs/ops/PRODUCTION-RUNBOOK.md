# Production Runbook — running Odal Node for real operators

**Date:** 2026-07-03 · **Grounded in:** `docker/docker-compose.yml` (the `odal up` stack), `NodeConfig::from_env()` (`dpp-node/src/config.rs`), the trust-mode boot guard, the registry outbox, the signed ruleset channel.
**Substrate this encodes:** a strictly single-tenant node, one plain dedicated VM per operator — no Kubernetes, and no microVM isolation until operator count forces it.

---

## 0. What "production" means today — three tiers, two blockers (read first)

| Tier | Profile | What it honestly claims | Available |
|---|---|---|---|
| **T1 Pilot-grade** | default (`NODE_PROFILE` unset) | Full lifecycle, signed + verified passports, hash-chained audit, outbox-durable registry intent; **trust ports run Ghost and say so** on `/vault/api/v1/node/state` (`trustMode`) and the `trust_mode` gauge | **Now** |
| **T2 Sealed-grade** | `NODE_PROFILE=production` | Everything above + real qualified seals from a hosted QTSP | After a QTSP credential exists — the adapter is wired, the account is not |
| **T3 Registry-grade** | `NODE_PROFILE=production` | + real EU registry registration | After the Commission publishes its registry spec |

**Blocker A — deliberate:** `NODE_PROFILE=production` **refuses to boot** while seal/registry resolve to Ghost (the honesty invariant working as designed). So every deployment today is **T1 by definition**: run the default profile, point monitoring at `/health`, and make no sealed/registered claims. Do not weaken the guard to "get to production" — the guard *is* the product's credibility.

**`NODE_PROFILE=sandbox`** is the third profile, and it is a property of the *deployment*, not a tier a production node may quietly carry. It is a full node in every respect except that the authorities behind it are test ones: ghosts on required ports are a hard boot failure exactly as in production, but `Sandbox` tiers are accepted, so the environment can be exercised end to end without a production credential. Run it as its own environment — it is the closest rehearsal of production available, and keeping the two profiles apart is what stops a test certificate ever sealing a passport that claims to be real. A `production` node refuses a sandbox tier for that reason.

**Blocker B — operational:** engine `main` now pins **core 0.4.0, which is unpublished** (0.3.0 is the latest on crates.io). The compose `pull` and plain `--build` modes resolve crates.io and **will fail**. Until 0.4.0 is published: build with the local-core overlay (`--build` + `-f docker/docker-compose.local.yml`, i.e. `just up-local`) and record the image digest you deployed. **Before the first external operator deploy: publish core 0.4.0** — your own release rule (CI/release = crates.io) exists precisely so a deploy is reproducible from public sources.

---

## 1. Reference topology — one VM per operator, and why it's the efficient answer

```
            Internet
               │ :443 (TLS)
        ┌──────▼──────┐          One VM = one operator (isolation boundary)
        │ Caddy proxy │          Hetzner/OVH-class, EU region, ~€10–25/mo [E]
        └──┬───────┬──┘          2 vCPU / 4 GB / 40 GB is ample [E]
   api.<op-domain> dpp.<op-domain>
           │           │
     ┌─────▼───┐ ┌─────▼─────┐   docker compose (the shipped stack):
     │ dpp-node│ │dpp-resolver│  postgres:17 · redis · nats · node · resolver
     │  :8000  │ │   :8003   │   volumes: pg-data · node-data(keystore!) ·
     └────┬────┘ └───────────┘            node-plugins · redis · nats
          └── postgres · nats · redis (internal only, no host ports)
```

**Why this beats the alternatives:**
- **It matches the architecture.** The node is strictly single-tenant; an orchestrator's whole value is multiplexing tenants onto shared machines — the thing this design deliberately forbids. One VM per operator makes "your own isolated node, zero shared data paths" *physically true* with zero additional code.
- **It's the smallest ops surface a single administrator can carry.** The compose stack already exists and is `odal up`; systemd + docker + caddy is knowledge you keep for a decade. Kubernetes would add a control plane to operate, YAML to drift, and failure modes you'd learn during an incident — an ops tax with no payer.
- **It keeps the deployment legible.** A dedicated VM keeps the data path, and the disk your keystore lives on, visible and under your control. PaaS platforms (Fly/Render/Heroku-class) complicate the EU-data-residency story and abstract away the storage your keys sit on.
- **It scales by addition, not redesign.** A second operator is a second VM, the same compose file, and about thirty minutes. Automation only pays for itself once operator count or a provisioning commitment forces it.
- **Failure isolation is absolute.** One operator's disk filling cannot touch another operator. For a compliance product, blast-radius honesty is a feature you can sell.

---

## 2. Bring-up, step by step (T1 pilot-grade)

**2.1 DNS + naming (decide once per operator).** Two hostnames on the *operator's* domain (the "your DID, our ops" posture): `api.<operator-domain>` → node (private API, operator-only), `dpp.<operator-domain>` (or `id.`) → resolver (public QR target). `DID_WEB_BASE_URL` **must equal the public HTTPS origin that serves `/.well-known/did.json`** — the DID document route the node exposes; if the DID is `did:web:api.<operator-domain>`, then `https://api.<operator-domain>/.well-known/did.json` must resolve through the proxy. Changing this later invalidates the DID — decide before first publish.

**2.2 VM hardening (30 min, once per VM).** SSH keys only (`PasswordAuthentication no`); `ufw`: allow 22+443 (and 80 for ACME), deny rest; `fail2ban`; unattended security upgrades; separate non-root user with docker group. **Change the compose port mappings to loopback** — `127.0.0.1:8001:8000` and `127.0.0.1:8003:8003` — so node/resolver are reachable only via Caddy. [The shipped compose maps to all interfaces; this one-line change per service is the single most important hardening step.]

**2.3 TLS proxy.** Caddy (host package or a fourth compose service), minimal config:
```
api.<operator-domain> {  reverse_proxy 127.0.0.1:8001 }
dpp.<operator-domain> {  reverse_proxy 127.0.0.1:8003 }
```
Auto-HTTPS, zero certificate ops. (Traefik equivalent if preferred; Caddy is less config.)

**2.4 The `.env` (the whole contract).** From `NodeConfig::from_env()` + compose + the trust-mode/ruleset config — every name below is real:

| Var | Req | Value guidance |
|---|---|---|
| `DATABASE_POSTGRES_PASS` / `DATABASE_APP_PASS` | ✔ | 32+ random chars each; compose fails closed without them |
| `KEY_STORE_PASSPHRASE` | ✔ | Generated, stored in the password manager **and** printed/sealed offline (§4 custody); loss = loss of signing identity |
| `DID_WEB_BASE_URL` | ✔ | `https://api.<operator-domain>` (see 2.1) |
| `KEY_STORE_PATH` | ✔ (compose pins it) | Leave as compose sets it — on the `node-data` volume; the inline warning about the throwaway layer is real |
| `ADMIN_USERNAME` / `ADMIN_PASSWORD` | opt | Set for bootstrap, then prefer API keys; rotate after onboarding |
| `CORS_ALLOWED_ORIGINS` | opt | The dashboard origin only, when it exists |
| `NATS_URL` | opt | Compose provides it; unset ⇒ NoOp bus (acceptable for pilot if you drop the service) |
| `METRICS_ADDR` | opt | `127.0.0.1:9464` — never public (RT2-7) |
| `PLUGINS_DIR` | ✔ (compose: `/plugins`) | Mount the product group `.wasm` files into the `node-plugins` volume |
| `RULESET_BUNDLE_PATH` + `RULESET_PUBLISHER_PUBKEY` | opt | Wire when the first Compliance Current bundle ships — both or neither. Bad bundle ⇒ last-good + `ruleset_load_failures_total`. Drop a new bundle at the path and the node takes it within `RULESET_POLL_INTERVAL_SECS`, or at once on `odal ruleset reload`; no restart |
| `RULESET_POLL_INTERVAL_SECS` | opt | Default `300`. `0` polls never, leaving `POST /vault/api/v1/ruleset/reload` as the only trigger |
| `NODE_PROFILE` | opt | **Leave unset** (T1). Set `production` only at T2 — it will refuse ghosts, correctly |
| `DATABASE_MIGRATE_URL` | opt | Keep for pilot (idempotent sqlx migrations at boot); the least-privilege upgrade (external `just migrate`, app role only at runtime) is a later hardening |
| `EU_REGISTRY_CLIENT_ID/SECRET`, `ARCHIVE_S3_BUCKET`… | opt | T3 / archive tier — leave unset until real |
| `ODAL_VERSION` | ✔ | **Pin a tag/digest. Never `latest` in production.** Same for the `postgres:17` image (pin digest — the compose header says so itself) |

`chmod 600 .env`; it is a secret.

**2.5 First boot.** `docker compose up -d` (with the local-core overlay until Blocker B clears) → postgres init runs `bootstrap.sql` (creates `odal_app`) → node applies `ops/pg` migrations via `DATABASE_MIGRATE_URL` → healthchecks green.

**2.6 Go-live smoke (the gate — do not skip).** (1) `curl` the **authenticated** `/vault/api/v1/node/state` with an API key and confirm expected `profile`, `trustMode` per port, and `rulesetVersion` — the public `/health` answers `{"status":"ok"}` and nothing else, so a probe pointed there passes without checking anything; (2) create → publish a test passport via API key; (3) resolve it: JSON *and* HTML on `dpp.<operator-domain>`, signature verifies (fail-closed path); (4) scan the QR from a phone on mobile data (not the VM's network); (5) tamper test: flip a field in `psql` → resolver returns 409; (6) `verify_chain` on the audit trail returns intact; (7) kill the node mid-publish, restart → outbox row survives (the chaos case, once per deployment). Record all seven in the operator's onboarding record — this doubles as your SLA evidence baseline.

---

## 3. Day-2 operations

**Backups — the only thing that can actually kill you.** Nightly `pg_dump -Fc` + copy of `keystore.enc` (it's on `node-data`) → **off-VM** object storage (EU region, versioned bucket, 30-day retention) — a 10-line cron script; the passphrase is *not* stored beside the dump. Redis/NATS are cache/replayable — exclude. **Monthly restore drill** on a scratch VM: restore dump + keystore → boot → old passport still resolves + verifies; target <1h (the S-4 gate). An untested backup is a hypothesis.

**Monitoring (pilot-appropriate, ~€0).** Split it by what each probe can actually see.

*External* (UptimeRobot-class free tier), on `https://dpp.<domain>/health` + the resolver of a known passport: **liveness only** — 200 and `{"status":"ok"}`. It cannot assert trust tiers. That endpoint deliberately carries nothing else (which ports are degraded is a targeting signal), and the endpoint that does carry them needs a credential — which is not something to hand a third-party uptime SaaS, since even a read-scoped key reads every passport.

*On-VM*, where a credential never leaves the box, is where the honesty invariant is monitored — and it needs no credential at all, because **`trust_mode` is already a labelled gauge on the metrics listener** (`0` ghost, `1` sandbox, `2` live, one series per port). Prometheus scrape of `127.0.0.1:9464`, or simpler for one VM, a cron that greps the metrics endpoint and mails on: any `trust_mode{port=…}` **below its expected value** — *a config regression that silently flips a port's trust tier must page you* — plus `signing_failures_total > 0`, `registry_outbox_stalled > 0`, `ruleset_load_failures_total > 0`, disk >80%. Full Grafana/Loki stack is H3 — do not build it for one operator.

**Upgrades — the ritual.** (1) backup first; (2) bump the pinned `ODAL_VERSION` on the **staging** VM (your own demo VM is staging), run §2.6 smoke; (3) same on prod; (4) migrations apply at boot (forward-only — **rollback = restore from backup**, so step 1 is the rollback plan); (5) post-deploy: §2.6 items 1–3 minimum + diff `rulesetVersion` on `/vault/api/v1/node/state`. Log every upgrade in the operator record (BUILD-LOG habit, operator-facing).

**Key rotation.** The identity service supports rotation. The `kid`-based verification fix has landed (`dpp-crypto::jws::verifier::extract_key_by_fingerprint` resolves any archived key by its `kid` fingerprint, not just the primary) and has a green rotation regression test (`dpp-identity::handlers::rotate_key::tests::signature_signed_before_rotation_still_verifies_after`) confirming a JWS signed before rotation still verifies afterwards. Follow `rotate_key_handler`'s doc comment for the archive-then-generate ordering.

**Key custody (managed mode).** Two documented modes, chosen per contract: (a) Odal-held passphrase (full managed; passphrase in your vault + sealed offline copy), or (b) operator-held (they enter it at provisioning; you cannot sign without them — the deepest sovereignty tier). Either way the *custody statement* is part of the managed contract (pack 04 §3.7).

---

## 4. Efficiency summary (the direct answer)

The most efficient production shape for Odal today is **the shipped compose stack, one dedicated EU VM per operator, loopback-bound services behind Caddy, pinned image versions, nightly off-VM backups with a monthly restore drill, and `/health`-asserting monitoring** — because it is the only shape that simultaneously (a) keeps the isolation claim physically true, (b) adds zero new operational technology for a single administrator, (c) runs on commodity VM hardware, (d) already exists in the repo (`odal up`), and (e) leaves the honesty invariant intact — a "production" that can't lie about its trust tier. Efficiency here is not throughput (a single node trivially serves early workloads); it is **administrator-hours per operator per month**, and this shape minimizes exactly that.

**Do-next order:** provision a demo VM as the permanent staging environment (§2 end-to-end, once) → after that, each operator VM is a 30-minute repeat with a filled-in checklist.

## 5. Go-live checklist (print per operator)
DNS + DID origin decided ✚ VM hardened, loopback bindings ✚ TLS live ✚ `.env` complete, `chmod 600`, secrets in manager + sealed copy ✚ versions pinned (ODAL_VERSION + postgres digest) ✚ first boot green ✚ §2.6 smoke ×7 recorded ✚ backup cron live + first restore drill dated ✚ external probe on `/health` for liveness + on-VM alarm on the `trust_mode` gauge ✚ upgrade ritual + custody mode written into the operator record.
