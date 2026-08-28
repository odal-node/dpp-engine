#!/usr/bin/env bash
# Self-test for scripts/contract-fixture-check.sh.
#
# A gate nobody has watched fail is a gate nobody knows works — and a grep-based
# gate is one bad anchor away from matching nothing at all while still exiting 0
# on every run. This asserts it rejects what it must reject and, just as
# importantly, accepts what it must accept.

set -euo pipefail

GATE="$(dirname "$0")/contract-fixture-check.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

pass=0
fail=0

expect_reject() {
    local name="$1" file="$2"
    if bash "$GATE" "$file" >/dev/null 2>&1; then
        echo "FAIL: $name — gate accepted a file it must reject"
        fail=$((fail + 1))
    else
        echo "ok:   $name"
        pass=$((pass + 1))
    fi
}

expect_accept() {
    local name="$1" file="$2"
    if bash "$GATE" "$file" >/dev/null 2>&1; then
        echo "ok:   $name"
        pass=$((pass + 1))
    else
        echo "FAIL: $name — gate rejected a file it must accept"
        fail=$((fail + 1))
    fi
}

# 1. The violation this gate exists for.
cat > "$TMP/default.rs" <<'EOF'
mod fixtures {
    pub fn passport() -> Passport {
        Passport {
            id: PassportId::new(),
            ..Default::default()
        }
    }
}
EOF
expect_reject "..Default::default() is rejected" "$TMP/default.rs"

# 2. The other form of the same mistake.
cat > "$TMP/other.rs" <<'EOF'
mod fixtures {
    pub fn passport() -> Passport {
        Passport {
            id: PassportId::new(),
            ..sample_passport()
        }
    }
}
EOF
expect_reject "..other_fixture() is rejected" "$TMP/other.rs"

# 3. A clean fixture must pass — including the JWS compact literals, whose
#    empty payload segment puts ".." mid-string. An unanchored pattern would
#    flag these, and the gate would then fail on correct code until someone
#    "fixed" it by loosening the check.
cat > "$TMP/clean.rs" <<'EOF'
mod fixtures {
    pub fn passport() -> Passport {
        Passport {
            id: PassportId::new(),
            jws_signature: Some("eyJhbGciOiJFZERTQSJ9..aaa".into()),
        }
    }
}
EOF
expect_accept "an exhaustive fixture with JWS literals is accepted" "$TMP/clean.rs"

# 4. Range syntax ABOVE the fixtures module is not a violation — the harness
#    uses it. Scanning the whole file instead of the module would flag it.
cat > "$TMP/harness.rs" <<'EOF'
fn section(src: &str) -> &str {
    &src[..4]
}

mod fixtures {
    pub fn material() -> MaterialEntry {
        MaterialEntry { name: "x".into() }
    }
}
EOF
expect_accept "range syntax outside the fixtures module is accepted" "$TMP/harness.rs"

# 5. A renamed or removed fixtures module must be loud, not silently vacuous.
cat > "$TMP/renamed.rs" <<'EOF'
mod samples {
    pub fn passport() -> Passport {
        Passport {
            ..Default::default()
        }
    }
}
EOF
expect_reject "a missing 'mod fixtures' block is rejected, not skipped" "$TMP/renamed.rs"

# 6. A missing file must be loud too.
expect_reject "a missing file is rejected" "$TMP/does-not-exist.rs"

# 7. The real file must pass, or the gate is wrong about the code it guards.
expect_accept "the committed contract test passes its own gate" \
    "$(dirname "$0")/../crates/dpp-node/tests/openapi_contract.rs"

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
