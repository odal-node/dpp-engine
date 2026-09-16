# Trusted-list documents kept locally

The `.xml` files in this directory are **not committed**. They are real published
Member State trusted lists, around 5 MB together, and they exist to demonstrate
one claim that cannot be demonstrated any other way: that the vendored `xml-sec`
fork lets a real over-ceiling document verify.

The tests that read them skip — loudly — when they are absent, so a checkout
without them is green and says so.

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

They prove the fork works end to end on a real published list. The published
`xml-sec` caps XML node-sets at 65 536 entries; Italy carries 65 540 and France
65 541, so without the fork both fail as a canonicaliser that stops before the
end of the document — not as a bad signature.

They do **not** prove the affected set is only these two. Measured 2026-09-15,
four lists are over that ceiling:

| territory | bytes | node-set entries |
|---|---|---|
| FR | 2 545 157 | 65 541 |
| CZ | 2 630 805 | 65 543 |
| IT | 2 855 744 | 65 540 |
| ES | 3 027 766 | 65 543 |

Byte size does not predict the count — Spain is larger than Italy and its count
differs — so the list above is a measurement, not a rule, and it grows.

## The one that still does not verify

**Germany does not verify even with the fork.** At 5 355 449 bytes it trips a
*different* ceiling the fork never touched:

```
XML nodes exceeds policy maximum 100000: got 100001
```

One node over. Upstream `structured-world/xml-sec#158` is about the node-set
constant and would not close this.

## The guard that does not need these files

`the_patched_xml_sec_is_the_one_that_resolved` reads the resolved source out of
`Cargo.lock` and runs everywhere, including CI. It catches the failure that
actually bites — `[patch.crates-io]` silently ceasing to apply when the
requirement moves past the fork's version, which Cargo reports as a warning
rather than an error. These documents are a one-time demonstration; that check
is the regression guard.
