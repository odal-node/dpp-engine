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

use std::fs;
use std::path::Path;

use dpp_domain::Passport;
use dpp_domain::catalog::SectorCatalog;
use dpp_domain::schemas::lens::LensRegistry;

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
