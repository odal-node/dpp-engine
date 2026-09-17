#!/usr/bin/env bash
# Keep "archive" meaning one thing on the wire.
#
# EN 18221:2026 clause 4.2 — one of the six standards cited by Commission
# Implementing Decision (EU) 2026/1736 — uses "archiving" for the retention of
# historical versions of a passport that is **still live**. This system once
# spent the same word on two other things: a terminal lifecycle status (now
# `retired`) and the ESPR Art. 10(4) back-up copy (now `backup`). While all
# three wore it, anyone mapping this system onto the standard by name ticked a
# box that was not ticked, and the clause 4.2 gap stayed invisible for months
# because the name looked already taken.
#
# The rename is not self-sustaining: nothing stops the next lifecycle verb from
# being called `archive` again, and nothing would fail if it were. This gate is
# what stops it.
#
# ── The rule, and why it needs no allow-list ────────────────────────────────
#
# Clause 4.2 archiving is served by `GET /dpp/{dppId}/versions` and carries no
# "archive" in any route path, path file or event subject. So the rule is
# absolute rather than a list of blessed exceptions: **no route path, no
# OpenAPI path file, and no event subject may contain "archiv" at all.**
#
# An absolute rule is the point. An allow-list is a place to add the next one.
#
# Deliberately NOT checked, because each is correct and qualified by its own
# object: `ArchivingPassportRepo` and `PassportVersion` (clause 4.2 itself),
# "archived keys" in the keystore, a seal's "archival timestamp" (ETSI's own
# term), and the `archived` value still permitted in `passport_audit.action`,
# which is history written under the old name and cannot be rewritten without
# breaking the audit hash chain.
set -euo pipefail

status=0

# 1. Route paths. Any `.route("…archive…")` in any router.
if grep -rn --include="*.rs" -E '\.route\("[^"]*archiv' crates/ cli/; then
    echo "ERROR: a route path contains \"archiv\" — the word belongs to EN 18221 clause 4.2 version archiving, which is served at /versions. A lifecycle transition is \`retire\`; the ESPR Art. 10(4) copy is \`backup\`."
    status=1
fi

# 2. OpenAPI path files. A renamed route with a stale file name republishes the
#    word in the description every consumer generates from.
if ls api/paths/**/*archiv* 2>/dev/null || ls api/paths/*archiv* 2>/dev/null; then
    echo "ERROR: an api/paths/ file name contains \"archiv\" — see above."
    status=1
fi

# 3. Event subjects. Renaming a subject is breaking for subscribers, so it is
#    worth failing the build rather than discovering it in a consumer.
if grep -rn --include="*.rs" -E '"dpp\.[a-z]+\.[a-z]*archiv' crates/; then
    echo "ERROR: an event subject contains \"archiv\" — see above."
    status=1
fi

exit "$status"
