# Passport retention

How the node keeps published passports available for the period the law requires, and
what it does and does not do about it.

## Where the period comes from

The required retention period depends on the product group and is set by the act that
governs it. The node reads it from `dpp-core`'s instrument catalog
(`InstrumentCatalog::retention_for`), where each period sits beside the act that imposes
it. Nothing in the engine restates a period.

A product group with no catalog entry gets a **ten-year floor**
(`RETENTION_FLOOR_YEARS` in `dpp-vault`). This happens in normal use: a passport can name
a product group this build does not know. Ten years is the shortest period any catalogued
product group declares, so the floor keeps the data at least as long as any known
obligation.

## What the node enforces

| Mechanism | Effect |
|---|---|
| **Retention lock** | Publish sets `retentionLocked`, and nothing clears it. A database trigger then refuses any change to the passport document except an allow-list of fields (status, signatures, carrier URL, lint result, seal) |
| **Sealed deadline** | First publish stores `retentionUntil` = publish time + the product group's period |
| **Retire guard** | `POST /dpp/{id}/retire` (`odal passport retire`) is refused until the period has passed: *"retention policy forbids retiring before 2036-08-18"* |
| **No delete path** | `dpp-domain`'s `PassportRepository` port has no delete method, and the application database role has no `DELETE` grant on passport, audit, evidence or seal tables |
| **Version history** | Every past version of a live passport stays in `passport_version`, append-only |

Changing a published passport means issuing a successor (`amend`), which supersedes the
original without altering it. Suspending a passport (`410 Gone` on its public URL) is
allowed at any time and is reversible.

## The carrier URL must outlive the product

Each passport's QR code encodes a URL on `RESOLVER_BASE_URL`, signed into the passport at
publish. That host must keep resolving for the whole retention period. Changing the
domain means the printed codes stop working; plan the resolver host as a permanent
address.

## Back-up copy

ESPR Art. 10(4) requires a back-up copy of the passport held by an independent digital
product passport service provider, so the passport survives its operator. The node
supports this through its back-up port (`BACKUP_S3_*`) and the continuity snapshot tier
(`SNAPSHOT_*`), which mirrors each published public view to object storage and declares
it to the registry. Whether a given provider satisfies the requirement is a contractual
and legal question, not something the node can determine.

Back-up copies hold one copy per passport. Version history (archiving) is a separate
obligation, kept by the node in `passport_version`.

## EU registry

The digital product passport registry under ESPR Art. 13 stores identifiers and links,
not passport content; the signed passport stays on the operator's node. The node already
writes a registration intent for every publish to a durable outbox, inside the publish
transaction. With no registry credentials configured, the stub adapter holds the backlog,
and configuring a live adapter later submits it.
