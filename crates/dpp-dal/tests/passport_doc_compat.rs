//! Stored-document compatibility guard.
//!
//! `PgPassportRepo::read_doc` reads every passport through
//! `dpp_domain::Passport::from_stored`, which tries a direct deserialize and
//! falls back to the registered lens chain for a bridgeable version gap. A
//! stored document is only as readable as that path allows — a dpp-domain
//! release with a non-additive change to a persisted shape (a new required
//! field, a rename with no lens for it) can still make an already-stored
//! document unreadable, forever, for every node that upgrades over old data.
//!
//! This test freezes one real, valid `doc` per shipped sector schema version
//! and asserts it still reads through that same path under the `dpp-domain`
//! version this workspace currently builds against. It will not catch a bump
//! that is already in `Cargo.lock` when the fixture is added — it only
//! catches the *next* one. Add a fixture here whenever a sector's
//! `schema_version` moves, captured from a real document, before bumping
//! `dpp-domain`.
//!
//! Deliberately checks `from_stored`, not raw `serde_json::from_str` — a
//! fixture that only a lens can bridge must still pass here, since that is
//! exactly what production does.
//!
//! Not covered here: a renamed *optional* envelope field (old key silently
//! unrecognised, new field silently `None`) does not fail this check, because
//! it does not fail deserialization at all — see `battery_2.0.0.json`'s
//! `facilityId`, a real historical case predating the additive-only envelope
//! rule. That is a distinct defect class (silent data loss vs. a loud
//! refusal) tracked separately, not something this guard claims to catch.
//!
//! Pure filesystem + in-memory check — no Docker/Postgres required, runs in
//! the fast `cargo nextest run --workspace` gate.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use dpp_domain::Passport;
use dpp_domain::catalog::SectorCatalog;
use dpp_domain::schemas::lens::LensRegistry;

/// Envelope keys that appear in a frozen document and are deliberately no longer
/// modelled by `Passport`.
///
/// Each entry is a decision that a stored key is not carried into the type any
/// more, recorded once, here. The list exists so
/// [`no_frozen_doc_loses_an_envelope_key_unrecorded`] can tell a *deliberate*
/// retirement from an *accidental* one — without it the check would either flag
/// every retired field forever, or have to be silenced by editing a fixture,
/// and a frozen document that gets edited to make a test pass has stopped being
/// evidence about anything.
///
/// Adding a row here is a claim that old documents carrying the key are still
/// correct on disk and the value is simply not represented in the struct. It is
/// **not** a claim that losing it is harmless — see the note on each.
const RETIRED_ENVELOPE_KEYS: &[(&str, &str)] = &[(
    "facilityId",
    "Superseded by the `facility` FacilitySnapshot, which carries the identifier \
     plus the address and registry provenance a bare string could not. The old \
     key is preserved on disk by the write path; it is simply not lifted into \
     the type, because a snapshot cannot be honestly reconstructed from an \
     identifier alone.",
)];

#[test]
fn every_frozen_passport_doc_still_reads() {
    let fixtures_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/passport_docs");
    let lenses = LensRegistry::new();
    let catalog = SectorCatalog::new();

    let mut fixtures: Vec<_> = fs::read_dir(&fixtures_dir)
        .expect("read tests/fixtures/passport_docs")
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|ext| ext == "json"))
        .collect();
    fixtures.sort();
    assert!(
        !fixtures.is_empty(),
        "expected at least one frozen doc under tests/fixtures/passport_docs"
    );

    let mut failures = Vec::new();
    for path in &fixtures {
        let raw = fs::read_to_string(path).unwrap_or_else(|e| panic!("read {path:?}: {e}"));
        let value: serde_json::Value =
            serde_json::from_str(&raw).unwrap_or_else(|e| panic!("{path:?} is not JSON: {e}"));

        match Passport::from_stored(value, &lenses, &catalog) {
            Ok(passport) => {
                // A fixture that parses into the wrong document (e.g. an
                // empty object matching every field's default) would pass
                // silently — pin it to the id/sector this file claims to be.
                let file_name = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
                if let Some(sector) = file_name.split('_').next() {
                    let actual = passport.sector.wire_str();
                    if actual != sector {
                        failures.push(format!(
                            "{}: expected sector `{sector}` from filename, deserialised as `{actual}`",
                            path.display()
                        ));
                    }
                }
            }
            Err(e) => failures.push(format!("{}: {e}", path.display())),
        }
    }

    assert!(
        failures.is_empty(),
        "one or more frozen passport docs no longer read under the current dpp-domain \
         version — a persisted document shape broke compatibility. Either this is an \
         intentional, accepted break (update the fixture and document why old documents \
         of this shape are no longer supported) or dpp-domain needs a lens for the gap:\n{}",
        failures.join("\n")
    );
}

/// Every top-level key in a frozen document must either survive a read/write
/// round-trip through `Passport`, or be named in [`RETIRED_ENVELOPE_KEYS`].
///
/// This catches the defect the test above structurally cannot: a renamed or
/// removed **optional** envelope field does not fail deserialization at all. It
/// is silently dropped, `None` takes its place, and nothing anywhere reports a
/// problem — which is worse than a loud break, because the loud one is visible
/// the first time anybody reads an old row.
///
/// It is a *read-side* check: it says which keys the type no longer represents.
/// Whether the value survives in the database is a property of the write path
/// and is asserted against real Postgres in `pg_doc_key_preservation`.
///
/// A stored key whose value is `null` is not counted as lost. `Passport` is
/// `skip_serializing_if = "Option::is_none"` throughout, so a null in a fixture
/// round-trips to an absent key, and treating that as loss would fire on almost
/// every fixture and get the check switched off.
#[test]
fn no_frozen_doc_loses_an_envelope_key_unrecorded() {
    let fixtures_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/passport_docs");
    let lenses = LensRegistry::new();
    let catalog = SectorCatalog::new();
    let retired: BTreeSet<&str> = RETIRED_ENVELOPE_KEYS.iter().map(|(k, _)| *k).collect();

    let mut fixtures: Vec<_> = fs::read_dir(&fixtures_dir)
        .expect("read tests/fixtures/passport_docs")
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|ext| ext == "json"))
        .collect();
    fixtures.sort();

    let mut failures = Vec::new();
    for path in &fixtures {
        let raw = fs::read_to_string(path).unwrap_or_else(|e| panic!("read {path:?}: {e}"));
        let stored: serde_json::Value =
            serde_json::from_str(&raw).unwrap_or_else(|e| panic!("{path:?} is not JSON: {e}"));

        let Ok(passport) = Passport::from_stored(stored.clone(), &lenses, &catalog) else {
            continue; // the test above owns unreadable fixtures
        };
        let round_tripped = serde_json::to_value(&passport).expect("serialise");

        let before = stored.as_object().expect("fixture is a JSON object");
        let after = round_tripped
            .as_object()
            .expect("passport serialises to an object");

        for (key, value) in before {
            // A stored null has nothing to lose.
            if value.is_null() || after.contains_key(key) || retired.contains(key.as_str()) {
                continue;
            }
            failures.push(format!(
                "{}: `{key}` is present in the stored document and absent after a \
                 round-trip through Passport",
                path.display()
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "a frozen passport document carries an envelope key the current `Passport` no \
         longer represents, and it is not recorded as retired.\n\n{}\n\nDo not edit the \
         fixture — it is the historical record, and changing it to make this pass \
         removes the only evidence the check runs on. Either restore the field (a \
         rename must keep accepting the old key), or add it to RETIRED_ENVELOPE_KEYS \
         with the reason it is no longer carried.",
        failures.join("\n")
    );
}
