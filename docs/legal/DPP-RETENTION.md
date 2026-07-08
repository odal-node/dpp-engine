# DPP Retention Model

## The Regulatory Obligation

EU ESPR Article 9 establishes that when placing a product on the EU market, the economic operator must:

1. Ensure the Digital Product Passport remains publicly accessible for the duration defined in the applicable delegated act.
2. Make a backup copy of the DPP available through an independent certified third-party service provider, to guarantee access in the event of insolvency or cessation of activity.

The retention period is set per sector by delegated act:

| Sector | Expected retention period |
|---|---|
| Batteries (EU 2023/1542) | >= 10 years after end of life |
| Textiles | >= 10 years (delegated act pending) |
| Iron & Steel | >= 10 years (delegated act pending) |
| Electronics | >= 10 years (delegated act pending) |

## Domain Invariants

### Retention Lock

Every passport that reaches `Active` (published) status receives `retention_locked = true`. This flag is set on publish and **never cleared**.

```rust
// Set on publish, never unset
passport.retention_locked = true;
```

| Operation | Behaviour on locked passport |
|---|---|
| Status -> Suspended | Allowed — passport remains accessible |
| Status -> Archived | Allowed — passport remains accessible |
| Field update | Blocked — only Draft passports can be patched |
| Delete | **No delete path exists** in `PassportRepository` by design |

### No-Delete Trait Design

The `PassportRepository` trait intentionally has no `delete` method. This is a structural guarantee that published passports cannot be removed — the API surface does not allow it, regardless of the persistence implementation.

### QR URL Permanence

QR codes encode a resolver URL. The URL must remain operational for the duration of the applicable delegated act retention period. The GS1 Digital Link standard provides an additional layer of indirection:

```
https://id.gs1.org/01/{gtin}/21/{serial}
  -> EU Central Registry lookup
  -> redirects to resolver URL
```

This means the resolver URL can change without reprinting physical QR codes — the GS1/EU Registry pointer is updated instead.

## EU Central Registry (dpp-registry)

The Commission's Art. 13 deadline to set up the registry was 19 July 2026; as of this writing the API specification remains unpublished. The engine is already registry-shaped: every publish commits a registration intent to a durable outbox (drained with backoff), so when the `EuRegistrySync` HTTP adapter activates against the published API, the backlog registers without loss. The registry is a pointer index, not data storage — the actual signed passport lives in the operator's infrastructure.
