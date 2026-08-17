# `ops/pg` — the migration set

Append-only, FK-ordered, never renumbered, and — the part that was not written
down — **never edited once it exists on `main`**.

## Why "never edited" is a separate rule from "never renumbered"

`PgDal::migrate` runs `sqlx::migrate!`, which stores a **checksum** of each
migration file in `_sqlx_migrations`. Editing an applied file — one character of
one comment is enough — makes the recorded checksum disagree, and sqlx aborts.
On a node that has already applied it, the effect is that the node **refuses to
boot**.

"Append-only, never renumbered" is a rule a repo-wide comment sweep can obey
while breaking the checksum, and that is exactly what happened to
`0015_audit_hash_chain.sql`: a formatting commit stripped an internal tag from a
header line. It is the only migration in the set with two commits.

`just reset-db` exists as the development workaround. There is no production
equivalent — the remedy on a live node is a manual `_sqlx_migrations` update.

`just migrations-check` fails the gate on any change to a file that already
exists on the base branch. To change what a migration did, add a new numbered
one.

## The DELETE set

The app role `odal_app` cannot run DDL, and may `DELETE` only from these tables:

```
odal.import_job      (granted 0010) — expired-job cleanup, every 6 hours
odal.scan_telemetry  (granted 0025) — rolling retention horizon
odal.qr_render       (granted 0025) — rolling retention horizon
```

Two more were granted and correctly **revoked** when the retire-not-delete policy
landed: `odal.facility` (0012 → revoked 0013) and `odal.operator_identifier`
(0012 → revoked 0014).

Every table in the live set is a counter or a queue. **No table carrying
passport, audit, evidence, seal or registry-identity data has a DELETE grant**,
and that is the property the shorter sentence elsewhere is protecting.

This list lives here, not in a migration, precisely because of the rule above:
it has to be editable when a grant changes, and a migration is not. `CLAUDE.md`
and `.env.example` point here rather than restating a count — both of them said
"one sanctioned exception" long after there were three, which is how the claim
was found to have drifted.

`just grants-check` fails the gate when this list and the actual grants in
`ops/pg/*.sql` disagree.

## Grants and new tables

`0010`'s `GRANT … ON ALL TABLES` is a one-time snapshot: it covers the tables
that existed when it ran and nothing after. **Every migration that creates a
table must ship its own grant.** Every one since `0010` does — checked
table-by-table — but this holds by discipline rather than by construction, since
there is no `ALTER DEFAULT PRIVILEGES`. `dal/tests/pg_integration.rs` carries a
parity test asserting `odal_app` can read every table, which is the mechanical
half of the same rule.
