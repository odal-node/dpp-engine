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
//! This test freezes one real, valid `doc` per shipped product group schema version
//! and asserts it still reads through that same path under the `dpp-domain`
//! version this workspace currently builds against. It will not catch a bump
//! that is already in `Cargo.lock` when the fixture is added — it only
//! catches the *next* one. Add a fixture here whenever a product group's
//! `schema_version` moves, captured from a real document, before bumping
//! `dpp-domain`.
//!
//! Deliberately checks `from_stored`, not raw `serde_json::from_str` — a
//! fixture that only a lens can bridge must still pass here, since that is
//! exactly what production does.
//!
//! Not covered here: a renamed *optional* envelope field (old key silently
//! unrecognised, new field silently `None`) does not fail this check, because
//! it does not fail deserialization at all — see `battery/v2.0.0.json`'s
//! `facilityId`, a real historical case predating the additive-only envelope
//! rule. That is a distinct defect class (silent data loss vs. a loud
//! refusal) tracked separately, not something this guard claims to catch.
//!
//! Pure filesystem + in-memory check — no Docker/Postgres required, runs in
//! the fast `cargo nextest run --workspace` gate.
//!
//! # ⚠️ This guard is currently vacuous, and that is not a quiet state
//!
//! Every frozen document predates the `sector` → `productGroup` envelope rename
//! and is now listed in [`UNREADABLE_FIXTURES`]. Nothing here reads, so nothing
//! here is being checked: the test passes because each failure is documented,
//! not because the read path works.
//!
//! It regains its teeth the moment one current-shape document is captured — from
//! a real create, not hand-authored, or it is only evidence that the current code
//! agrees with itself. Capture one per shipped product-group schema version and
//! delete the corresponding row from [`UNREADABLE_FIXTURES`]; the old files stay
//! on disk as the record of what the break was.
//!
//! # Layout
//!
//! One directory per product group, one file per frozen schema version —
//! `{catalog_key}/v{version}.json`, mirroring
//! `dpp-core/crates/dpp-domain/schemas/{product group}/v{version}.json` exactly, so
//! a reader who knows one convention already knows the other. A flat
//! `{product group}_{version}.json` naming was tried first and abandoned: it does not
//! scale past a handful of product groups before every product group's versions interleave
//! in one listing.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use dpp_domain::Passport;
use dpp_domain::catalog::ProductGroupCatalog;
use dpp_domain::schemas::lens::LensRegistry;

/// Every frozen fixture, paired with the catalog key its parent directory
/// claims — `(catalog_key, path)`, sorted for a stable failure order.
fn collect_fixtures() -> Vec<(String, PathBuf)> {
    let fixtures_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/passport_docs");
    let mut fixtures: Vec<(String, PathBuf)> = fs::read_dir(&fixtures_dir)
        .expect("read tests/fixtures/passport_docs")
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .flat_map(|product_group_dir| {
            let product_group = product_group_dir
                .file_name()
                .and_then(|n| n.to_str())
                .expect("product_group directory name is valid UTF-8")
                .to_owned();
            fs::read_dir(&product_group_dir)
                .unwrap_or_else(|e| panic!("read {product_group_dir:?}: {e}"))
                .filter_map(|e| e.ok())
                .map(|e| e.path())
                .filter(|p| p.extension().is_some_and(|ext| ext == "json"))
                .map(move |path| (product_group.clone(), path))
                .collect::<Vec<_>>()
        })
        .collect();
    fixtures.sort();
    fixtures
}

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

/// Frozen documents that deliberately no longer read, and why.
///
/// The counterpart to [`RETIRED_ENVELOPE_KEYS`], and it exists for the same
/// reason: the alternative is editing a frozen document until the test passes,
/// and a fixture that has been edited has stopped being evidence about anything.
/// These stay on disk exactly as they were captured; the break is recorded here
/// instead.
///
/// Each row is an **accepted, permanent** compatibility break. A node holding a
/// document of that shape cannot read it after upgrading past the version named
/// in the reason, and no lens can rescue it — where the gap is a field the
/// regulation later made mandatory, there is no honest value to invent, and
/// `dpp-domain` refuses rather than fabricating one.
///
/// This is only defensible while no such document exists in any deployment. It
/// stops being defensible the moment one does.
const UNREADABLE_FIXTURES: &[(&str, &str)] = &[
    (
        "battery/v1.0.0.json",
        "No `batteryType`. Required from battery schema v2.5.0 — EU 2023/1542 Annex VI \
         Part A point 2, via Annex XIII point 1(a) — and closed to a fixed set, so it \
         cannot be defaulted or derived from anything else the document carries.",
    ),
    (
        "battery/v2.0.0.json",
        "No lens path to the current schema. The 2.0.0 shape predates several \
         non-additive changes and the chain was never built; a document of this \
         shape has been unreachable since the first gap in that chain.",
    ),
    (
        "battery/v2.1.0.json",
        "No lens path to the current schema — same chain gap as v2.0.0.",
    ),
    (
        "battery/v2.2.0.json",
        "No lens path to the current schema — same chain gap as v2.0.0.",
    ),
    (
        "battery/v2.3.0.json",
        "No lens path to the current schema — same chain gap as v2.0.0.",
    ),
    (
        "battery/v2.4.0.json",
        "A lens path exists and refuses: `batteryType` is required from v2.5.0 and this \
         record predates the mandate. The refusal is `dpp-domain`'s, and it is correct — \
         upgrading would mean inventing a regulatory classification the operator never \
         stated.",
    ),
    (
        "aluminium/v1.1.0.json",
        "The envelope keys `sector` and `sectorData` were renamed to `productGroup` \n         and `productGroupData`. `productGroup` is required, so a document of this \n         shape is refused loudly rather than read with the field silently missing. \n         Deliberate and permanent: the term the Regulation defines is product \n         group, and a read-only alias would have kept both spellings alive in a \n         codebase whose whole problem was two names for one concept. No lens \n         bridges it, and none is wanted.",
    ),
    (
        "battery/v2.6.0.json",
        "The envelope keys `sector` and `sectorData` were renamed to `productGroup` \n         and `productGroupData`. `productGroup` is required, so a document of this \n         shape is refused loudly rather than read with the field silently missing. \n         Deliberate and permanent: the term the Regulation defines is product \n         group, and a read-only alias would have kept both spellings alive in a \n         codebase whose whole problem was two names for one concept. No lens \n         bridges it, and none is wanted.",
    ),
    (
        "construction/v1.1.0.json",
        "The envelope keys `sector` and `sectorData` were renamed to `productGroup` \n         and `productGroupData`. `productGroup` is required, so a document of this \n         shape is refused loudly rather than read with the field silently missing. \n         Deliberate and permanent: the term the Regulation defines is product \n         group, and a read-only alias would have kept both spellings alive in a \n         codebase whose whole problem was two names for one concept. No lens \n         bridges it, and none is wanted.",
    ),
    (
        "detergent/v1.1.0.json",
        "The envelope keys `sector` and `sectorData` were renamed to `productGroup` \n         and `productGroupData`. `productGroup` is required, so a document of this \n         shape is refused loudly rather than read with the field silently missing. \n         Deliberate and permanent: the term the Regulation defines is product \n         group, and a read-only alias would have kept both spellings alive in a \n         codebase whose whole problem was two names for one concept. No lens \n         bridges it, and none is wanted.",
    ),
    (
        "electronics/v1.1.0.json",
        "The envelope keys `sector` and `sectorData` were renamed to `productGroup` \n         and `productGroupData`. `productGroup` is required, so a document of this \n         shape is refused loudly rather than read with the field silently missing. \n         Deliberate and permanent: the term the Regulation defines is product \n         group, and a read-only alias would have kept both spellings alive in a \n         codebase whose whole problem was two names for one concept. No lens \n         bridges it, and none is wanted.",
    ),
    (
        "electronics/v1.2.0.json",
        "The envelope keys `sector` and `sectorData` were renamed to `productGroup` \n         and `productGroupData`. `productGroup` is required, so a document of this \n         shape is refused loudly rather than read with the field silently missing. \n         Deliberate and permanent: the term the Regulation defines is product \n         group, and a read-only alias would have kept both spellings alive in a \n         codebase whose whole problem was two names for one concept. No lens \n         bridges it, and none is wanted.",
    ),
    (
        "furniture/v1.1.0.json",
        "The envelope keys `sector` and `sectorData` were renamed to `productGroup` \n         and `productGroupData`. `productGroup` is required, so a document of this \n         shape is refused loudly rather than read with the field silently missing. \n         Deliberate and permanent: the term the Regulation defines is product \n         group, and a read-only alias would have kept both spellings alive in a \n         codebase whose whole problem was two names for one concept. No lens \n         bridges it, and none is wanted.",
    ),
    (
        "steel/v1.1.0.json",
        "The envelope keys `sector` and `sectorData` were renamed to `productGroup` \n         and `productGroupData`. `productGroup` is required, so a document of this \n         shape is refused loudly rather than read with the field silently missing. \n         Deliberate and permanent: the term the Regulation defines is product \n         group, and a read-only alias would have kept both spellings alive in a \n         codebase whose whole problem was two names for one concept. No lens \n         bridges it, and none is wanted.",
    ),
    (
        "textile/v1.1.0.json",
        "The envelope keys `sector` and `sectorData` were renamed to `productGroup` \n         and `productGroupData`. `productGroup` is required, so a document of this \n         shape is refused loudly rather than read with the field silently missing. \n         Deliberate and permanent: the term the Regulation defines is product \n         group, and a read-only alias would have kept both spellings alive in a \n         codebase whose whole problem was two names for one concept. No lens \n         bridges it, and none is wanted.",
    ),
    (
        "textile/v1.2.0.json",
        "The envelope keys `sector` and `sectorData` were renamed to `productGroup` \n         and `productGroupData`. `productGroup` is required, so a document of this \n         shape is refused loudly rather than read with the field silently missing. \n         Deliberate and permanent: the term the Regulation defines is product \n         group, and a read-only alias would have kept both spellings alive in a \n         codebase whose whole problem was two names for one concept. No lens \n         bridges it, and none is wanted.",
    ),
    (
        "toy/v1.1.0.json",
        "The envelope keys `sector` and `sectorData` were renamed to `productGroup` \n         and `productGroupData`. `productGroup` is required, so a document of this \n         shape is refused loudly rather than read with the field silently missing. \n         Deliberate and permanent: the term the Regulation defines is product \n         group, and a read-only alias would have kept both spellings alive in a \n         codebase whose whole problem was two names for one concept. No lens \n         bridges it, and none is wanted.",
    ),
    (
        "tyre/v1.0.0.json",
        "The envelope keys `sector` and `sectorData` were renamed to `productGroup` \n         and `productGroupData`. `productGroup` is required, so a document of this \n         shape is refused loudly rather than read with the field silently missing. \n         Deliberate and permanent: the term the Regulation defines is product \n         group, and a read-only alias would have kept both spellings alive in a \n         codebase whose whole problem was two names for one concept. No lens \n         bridges it, and none is wanted.",
    ),
    (
        "unsold-goods/v1.0.0.json",
        "The envelope keys `sector` and `sectorData` were renamed to `productGroup` \n         and `productGroupData`. `productGroup` is required, so a document of this \n         shape is refused loudly rather than read with the field silently missing. \n         Deliberate and permanent: the term the Regulation defines is product \n         group, and a read-only alias would have kept both spellings alive in a \n         codebase whose whole problem was two names for one concept. No lens \n         bridges it, and none is wanted.",
    ),
];

/// The documented-unreadable list, as `product_group/file.json` keys.
fn unreadable_key(path: &Path) -> String {
    let file = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default();
    let product_group = path
        .parent()
        .and_then(|p| p.file_name())
        .and_then(|n| n.to_str())
        .unwrap_or_default();
    format!("{product_group}/{file}")
}

#[test]
fn every_frozen_passport_doc_still_reads() {
    let lenses = LensRegistry::new();
    let catalog = ProductGroupCatalog::new();
    let fixtures = collect_fixtures();
    assert!(
        !fixtures.is_empty(),
        "expected at least one frozen doc under tests/fixtures/passport_docs"
    );

    let mut failures = Vec::new();
    // A row that has stopped being true must be removed, not left to rot. If a
    // lens later bridges one of these, this is what says so.
    let mut unexpectedly_readable = Vec::new();

    for (product_group, path) in &fixtures {
        let raw = fs::read_to_string(path).unwrap_or_else(|e| panic!("read {path:?}: {e}"));
        let value: serde_json::Value =
            serde_json::from_str(&raw).unwrap_or_else(|e| panic!("{path:?} is not JSON: {e}"));

        let key = unreadable_key(path);
        if let Some((_, reason)) = UNREADABLE_FIXTURES.iter().find(|(k, _)| *k == key) {
            if Passport::from_stored(value, &lenses, &catalog).is_ok() {
                unexpectedly_readable.push(format!(
                    "{key}: recorded as permanently unreadable, but it reads. Remove the row \
                     from UNREADABLE_FIXTURES — the recorded reason is no longer true:\n    {reason}"
                ));
            }
            continue;
        }

        match Passport::from_stored(value, &lenses, &catalog) {
            Ok(passport) => {
                // A fixture that parses into the wrong document (e.g. an
                // empty object matching every field's default) would pass
                // silently — pin it to the product group its directory claims.
                let actual = passport.product_group.catalog_key();
                if actual != product_group {
                    failures.push(format!(
                        "{}: expected product_group `{product_group}` from its directory, deserialised as `{actual}`",
                        path.display()
                    ));
                }
            }
            Err(e) => failures.push(format!("{}: {e}", path.display())),
        }
    }

    assert!(
        unexpectedly_readable.is_empty(),
        "UNREADABLE_FIXTURES is stale:\n{}",
        unexpectedly_readable.join("\n")
    );

    assert!(
        failures.is_empty(),
        "one or more frozen passport docs no longer read under the current dpp-domain \
         version — a persisted document shape broke compatibility. Either dpp-domain needs \
         a lens for the gap, or the break is accepted and permanent, in which case record \
         it in UNREADABLE_FIXTURES with the reason. Do not edit the fixture: a frozen \
         document that has been edited to pass a test is no longer evidence of \
         anything:\n{}",
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
    let lenses = LensRegistry::new();
    let catalog = ProductGroupCatalog::new();
    let retired: BTreeSet<&str> = RETIRED_ENVELOPE_KEYS.iter().map(|(k, _)| *k).collect();
    let fixtures = collect_fixtures();

    let mut failures = Vec::new();
    for (_product_group, path) in &fixtures {
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
