//! Stored-document compatibility guard.
//!
//! `PgPassportRepo::from_doc` deserialises the `doc JSONB` column straight
//! into `dpp_domain::domain::passport::Passport` on every read — there is no
//! version-dispatch layer in between. A stored document is only as readable
//! as it is compatible with whatever `dpp-domain` version the node currently
//! links against, and a domain-crate release with a non-additive change to a
//! persisted shape (a new required field, a rename) silently breaks every
//! already-stored document of that shape: reads 500 with "missing field",
//! forever, for every node that upgrades over old data.
//!
//! This test freezes one real, valid `doc` per shipped sector schema version
//! and asserts it still deserialises under the `dpp-domain` version this
//! workspace currently builds against. It will not catch a bump that is
//! already in `Cargo.lock` when the fixture is added — it only catches the
//! *next* one. Add a fixture here whenever a sector's `schema_version` moves,
//! captured from a real document, before bumping `dpp-domain`.
//!
//! Pure filesystem + in-memory check — no Docker/Postgres required, runs in
//! the fast `cargo nextest run --workspace` gate.

use std::fs;
use std::path::Path;

use dpp_domain::domain::passport::Passport;

#[test]
fn every_frozen_passport_doc_still_deserialises() {
    let fixtures_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/passport_docs");

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
        match serde_json::from_str::<Passport>(&raw) {
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
        "one or more frozen passport docs no longer deserialise under the current \
         dpp-domain version — a persisted document shape broke compatibility. Either \
         this is an intentional, accepted break (update the fixture and document why \
         old documents of this shape are no longer supported) or dpp-domain needs to \
         make the change additive:\n{}",
        failures.join("\n")
    );
}
