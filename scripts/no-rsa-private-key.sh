#!/usr/bin/env bash
# Enforces the claim that suppresses RUSTSEC-2023-0071.
#
# The `rsa` crate carries the Marvin Attack advisory, for which no fix exists
# or is expected: it is a timing sidechannel in RSA **private key** operations,
# recovering a key by timing an attacker's decryption or signing queries. The
# entry in `.cargo/audit.toml` suppresses it on one ground — this workspace
# holds no RSA private key and performs no RSA private-key operation, so there
# is nothing to recover and no oracle to time.
#
# That is a claim about the code, and the audit register's own header says a
# prose claim rots silently without something re-checking it. Its `anchor`
# field can only grep for a symbol; it cannot see a private key arriving three
# crates away. This can.
#
# Two things are checked, matching how such a key could actually appear:
#
#   1. No workspace crate declares `rsa` as a **direct** dependency. Reaching
#      it only through `x509-verify` is what keeps the use verification-only;
#      a direct dependency is how a signing or decryption path starts.
#   2. No workspace source names an RSA private-key type or operation.
#
# If either fires, the suppression is void: delete the ignore entry in
# `.cargo/audit.toml` and deal with the advisory on its merits, or remove the
# private key. Do not widen this script to accommodate the new code.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

STATUS=0

# ── 1. `rsa` must stay transitive ───────────────────────────────────────────
# Matches a dependency line, not a word in a comment or a feature named "rsa"
# inside another crate's feature list.
if grep -rn --include="Cargo.toml" -E '^\s*rsa\s*=' crates cli Cargo.toml 2>/dev/null; then
    echo "ERROR: a workspace crate depends on \`rsa\` directly." >&2
    echo "       RUSTSEC-2023-0071 is suppressed in .cargo/audit.toml on the ground that" >&2
    echo "       this workspace performs no RSA private-key operation. A direct dependency" >&2
    echo "       is how one starts. Re-argue the suppression or drop the dependency." >&2
    STATUS=1
fi

# ── 2. No RSA private-key material in our own source ────────────────────────
# `RsaPrivateKey` is the type; the two `SigningKey`s are the private-key
# signing APIs in `rsa`'s padding modules. `DecryptingKey` covers the
# decryption side, which is where the Marvin Attack was first demonstrated.
if grep -rn --include="*.rs" \
     -e 'RsaPrivateKey' \
     -e 'rsa::pkcs1v15::SigningKey' \
     -e 'rsa::pss::SigningKey' \
     -e 'rsa::pkcs1v15::DecryptingKey' \
     -e 'rsa::oaep' \
     crates/*/src crates/*/tests cli/src 2>/dev/null; then
    echo "ERROR: RSA private-key material or a private-key operation in workspace source." >&2
    echo "       This voids the RUSTSEC-2023-0071 suppression in .cargo/audit.toml, whose" >&2
    echo "       whole ground is that no such key or operation exists here." >&2
    STATUS=1
fi

if [[ $STATUS -eq 0 ]]; then
    echo "no-rsa-private-key: rsa is transitive and verification-only."
fi
exit $STATUS
