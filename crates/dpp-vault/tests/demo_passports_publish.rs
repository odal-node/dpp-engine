//! The shipped demo passports must actually pass the publish-time content gate.
//!
//! `ops/demo/passports/*.json` exist to be the operator-facing proof that a
//! fully-populated Annex XIII battery publishes — the CSV importer cannot carry
//! those fields, so these files are the only demonstration that the path works
//! at all. Nothing checked them. A field renamed in `BatteryData`, or a row
//! added to the Commission's per-category requirements table, silently turns
//! the demo into a wall of "is mandatory for a '<type>' battery and is absent",
//! and the first person to find out is whoever runs the demo.
//!
//! Pure deserialise-and-check: no Docker, no HTTP, so it runs in the fast gate.
//!
//! # Why the whole file, not a fixture
//!
//! The point is the *shipped bytes*. A fixture built in Rust would drift from
//! the JSON on disk in exactly the way that makes the demo fail, which is the
//! failure this exists to catch.

use std::fs;
use std::path::{Path, PathBuf};

use dpp_domain::ProductGroupData;
use dpp_rules::batteries::passport_content;

fn demo_passport_files() -> Vec<PathBuf> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../ops/demo/passports");
    let mut files: Vec<PathBuf> = fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("read {}: {e}", dir.display()))
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .collect();
    files.sort();
    assert!(
        !files.is_empty(),
        "no demo passports found in {} — if they moved, move this test with them",
        dir.display()
    );
    files
}

/// The demo file's `productGroupData` as the domain sees it.
///
/// The files are *create-request* bodies, not `Passport` records — the two
/// differ above `productGroupData` (`repairabilityScore` is a scalar on the
/// request and a struct on the record), so the whole file cannot be
/// deserialised as a `Passport`. `productGroupData` itself is the same shape on
/// both, and it is the only part the content gate reads.
fn product_group_data(path: &Path) -> ProductGroupData {
    let raw = fs::read_to_string(path).expect("read demo passport");
    let body: serde_json::Value = serde_json::from_str(&raw)
        .unwrap_or_else(|e| panic!("{} is not JSON: {e}", path.display()));
    let data = body
        .get("productGroupData")
        .unwrap_or_else(|| panic!("{} carries no productGroupData", path.display()));
    serde_json::from_value(data.clone()).unwrap_or_else(|e| {
        panic!(
            "{}'s productGroupData is not a ProductGroupData: {e}",
            path.display()
        )
    })
}

/// Every demo file must land on its typed variant, not the open `Other` one.
///
/// `Other` is deliberately forgiving — a product group this build has no
/// variant for round-trips rather than failing — which means a typo in
/// `productGroup` produces data that stores fine and is checked by nothing.
/// Asserting the variant keeps that forgiveness from hiding a broken demo file.
#[test]
fn every_demo_passport_deserialises_to_its_typed_product_group() {
    for path in demo_passport_files() {
        assert!(
            !matches!(product_group_data(&path), ProductGroupData::Other { .. }),
            "{} fell through to ProductGroupData::Other — its `productGroup` tag names \
             a group this build has no typed variant for, so nothing validates it",
            path.display()
        );
    }
}

/// The publish-time content gate must accept every one of them.
///
/// This is the assertion that matters, and it is the same question
/// `Passport::check_mandatory_content` asks: for this battery's category, is
/// every field the Commission's guidance makes mandatory actually present and
/// non-null? Asked directly against `dpp_rules` rather than through a
/// `Passport`, because the record needs eighteen fields this file does not
/// carry and none of them change the answer.
///
/// The failure message names the file *and* its missing fields, so a broken
/// demo says which file and which Annex XIII rows — rather than surfacing later
/// as an unattributed wall of text beside whichever passport happened to be in
/// the publish queue.
#[test]
fn every_demo_passport_satisfies_the_mandatory_content_gate() {
    let mut broken: Vec<String> = Vec::new();

    for path in demo_passport_files() {
        let data = product_group_data(&path);
        let value = serde_json::to_value(&data).expect("product group data re-serialises");

        // Only a battery is gated, and only for the three categories the
        // Commission's guidance covers — a portable pack is ungated on purpose.
        let Some(battery_type) = value.get("batteryType").and_then(serde_json::Value::as_str)
        else {
            continue;
        };

        // Present-but-null is absent: `skip_serializing_if` means a `None` never
        // reaches the wire, so an explicit null carries no value either way.
        let missing: Vec<&str> = passport_content::mandatory_fields(battery_type)
            .filter(|f| value.get(*f).is_none_or(serde_json::Value::is_null))
            .collect();

        if !missing.is_empty() {
            broken.push(format!(
                "  {} ({battery_type}, {} field(s)):\n    {}",
                path.file_name().unwrap_or_default().to_string_lossy(),
                missing.len(),
                missing.join("\n    "),
            ));
        }
    }

    assert!(
        broken.is_empty(),
        "demo passports that cannot be published:\n{}\n\n\
         These files are the only demonstration that a complete Annex XIII battery \
         publishes — the CSV importer cannot carry these fields. Fix the file; if the \
         requirements table changed, fix the file to match it rather than relaxing this.",
        broken.join("\n")
    );
}

/// The complement, and the one a mandatory-fields check can never catch: a
/// category carrying content the guidance says does not belong to it.
///
/// `05-battery-lmt-lfp.json` exists partly to demonstrate this — an LMT pack is
/// barred from `capacityThresholdForExhaustionPct`, which is EV-only.
#[test]
fn no_demo_passport_carries_content_its_category_may_not() {
    let mut broken: Vec<String> = Vec::new();

    for path in demo_passport_files() {
        let data = product_group_data(&path);
        let value = serde_json::to_value(&data).expect("product group data re-serialises");
        let Some(battery_type) = value.get("batteryType").and_then(serde_json::Value::as_str)
        else {
            continue;
        };
        let Some(object) = value.as_object() else {
            continue;
        };

        let present: Vec<&str> = object
            .iter()
            .filter(|(_, v)| !v.is_null())
            .map(|(k, _)| k.as_str())
            .collect();
        let barred: Vec<&str> =
            passport_content::fields_not_applicable(&present, battery_type).collect();

        if !barred.is_empty() {
            broken.push(format!(
                "  {} ({battery_type}): {}",
                path.file_name().unwrap_or_default().to_string_lossy(),
                barred.join(", "),
            ));
        }
    }

    assert!(
        broken.is_empty(),
        "demo passports carrying content their category may not:\n{}",
        broken.join("\n")
    );
}

/// Compile-time proof that the payload trait is what reads the GTIN — the same
/// accessor `publish` uses — rather than a per-variant match in this test.
#[test]
fn every_demo_passport_carries_a_gtin() {
    for path in demo_passport_files() {
        let data = product_group_data(&path);
        assert!(
            data.gtin().is_some(),
            "{} carries no GTIN — the resolver has nothing to mint a Digital Link from",
            path.display()
        );
    }
}
