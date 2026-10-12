# Trusted-list documents kept locally

The `.xml` files in this directory are **not committed**. They are real published
Member State trusted lists, around 5 MB together, and they exist to demonstrate
one claim that cannot be demonstrated any other way: that the `xml-sec` in this
build verifies a real document over the node-set ceiling older releases had.

The tests that read them skip — loudly — when they are absent, so a checkout
without them is green and says so. Re-run them with the documents present on
every `xml-sec` bump.

## Fetching them

The URLs come from the LOTL itself (`eu-lotl.xml`, committed beside this
directory), under `OtherTSLPointer` for each territory. As of 2026-09-15:

```sh
curl -sSL -o it-trusted-list.xml https://eidas.agid.gov.it/TL/TSL-IT.xml
curl -sSL -o fr-trusted-list.xml https://messervices.cyber.gouv.fr/visas/tl-fr_v6.xml
```

Take the URL from the LOTL rather than from here if the fetch fails — a Member
State moving its endpoint is normal, and the LOTL is the record of where it is.

## What they prove, and what they do not

They prove verification works end to end on a real list that is over the old
ceiling. `xml-sec` before 0.1.17 capped XML node-sets at 65 536 entries; Italy
and France stop there, and fail as a canonicaliser that gives up before the end
of the document, not as a bad signature. This workspace carried a fork with
that one constant raised until upstream shipped the fix in 0.1.17
(`structured-world/xml-sec#158`). Since then the default policy limit is
262 144 entries, with an absolute maximum of 524 288.

They do **not** prove the affected set is only these two. Measured 2026-09-15,
four lists were over the old ceiling at the point where counting stopped:

| territory | bytes | node-set entries counted before the cap |
|---|---|---|
| FR | 2 545 157 | 65 541 |
| CZ | 2 630 805 | 65 543 |
| IT | 2 855 744 | 65 540 |
| ES | 3 027 766 | 65 543 |

Those counts are where the old cap stopped, not the documents' full size;
upstream counted roughly 149k entries for Italy and 144k for France before text
nodes. Byte size does not predict the count, so the list above is a measurement,
not a rule, and it grows.

## The one that still does not verify

**Germany did not verify** when measured on 2026-09-15. At 5 355 449 bytes it
tripped a *different* ceiling, on XML nodes per document, which neither the old
fork nor #158 touched:

```
XML nodes exceeds policy maximum 100000: got 100001
```

One node over. That ceiling is still the hard-coded 100 000 in 0.1.20
(`XML_DOCUMENT_NODE_CEILING`), so expect the same until upstream raises it; the
German list has not been re-measured since.

## The guard that does not need these files

`xml_sec_is_a_release_with_the_raised_node_set_ceiling` reads the resolved
`xml-sec` out of `Cargo.lock` and runs everywhere, including CI. It fails if the
build resolves a release before 0.1.17, or a git source instead of crates.io.
These documents are the end-to-end demonstration; that check is the regression
guard.
