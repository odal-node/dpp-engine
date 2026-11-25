//! An integer a passport is given that signing cannot hold is refused where it
//! is given, never at publish.
//!
//! dpp-core 0.24.0's `canonicalize` refuses an integer whose magnitude is beyond
//! 2^53 − 1, because a double cannot hold it exactly and two verifiers would
//! disagree on the bytes. Publish serialises the passport and signs that value,
//! so a number that is read into a passport and then fails there answers `500`
//! and leaves the draft a draft, with nothing in the message an operator could
//! correct. The end-of-life summary is free JSON and is guarded on its own route;
//! this asks the same question of every numeric position a passport reads.
//!
//! Each frozen stored document, and each shipped demo passport's
//! `productGroupData`, has every number in it replaced in turn by an integer past
//! the limit. The document is then read the way a stored passport is read, and
//! serialised and canonicalised the way publish does. Reading may refuse it: that
//! is the answer a create gives, a `422`. Reading may accept it, as a float field
//! does, and then it must canonicalise. What must never happen is a value that is
//! read and then refused when signing.
//!
//! One exception is checked, not skipped. A product group core has no typed
//! variant for carries its data verbatim, so any number reads. Publish refuses
//! such a passport at `validate_passport` before it signs, and the walk asserts
//! that refusal for each one it meets. The retired `unsold-goods` document is the
//! one frozen example.
//!
//! No Docker: a deserialise-and-canonicalise check, so it runs in the fast gate.

use std::fs;
use std::path::{Path, PathBuf};

use dpp_domain::catalog::ProductGroupCatalog;
use dpp_domain::schemas::lens::LensRegistry;
use dpp_domain::{Passport, ProductGroupData};
use serde_json::{Value, json};

/// Integers a double cannot hold exactly, one of each sign and the widest.
fn too_wide() -> [Value; 3] {
    [
        json!(9_007_199_254_740_993_u64),
        json!(-9_007_199_254_740_993_i64),
        json!(u64::MAX),
    ]
}

/// A JSON Pointer to every number in `value`.
fn number_pointers(value: &Value, at: &str, out: &mut Vec<String>) {
    match value {
        Value::Number(_) => out.push(at.to_owned()),
        Value::Array(items) => {
            for (i, item) in items.iter().enumerate() {
                number_pointers(item, &format!("{at}/{i}"), out);
            }
        }
        Value::Object(map) => {
            for (key, item) in map {
                let key = key.replace('~', "~0").replace('/', "~1");
                number_pointers(item, &format!("{at}/{key}"), out);
            }
        }
        _ => {}
    }
}

fn with_value_at(doc: &Value, pointer: &str, value: &Value) -> Value {
    let mut out = doc.clone();
    *out.pointer_mut(pointer)
        .expect("the pointer names a number") = value.clone();
    out
}

fn frozen_docs() -> Vec<(PathBuf, Value)> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../dpp-dal/tests/fixtures/passport_docs");
    let mut files = Vec::new();
    for group in fs::read_dir(&dir).unwrap_or_else(|e| panic!("read {}: {e}", dir.display())) {
        let group = group.expect("a directory entry").path();
        if !group.is_dir() {
            continue;
        }
        for file in fs::read_dir(&group).expect("a product group directory") {
            let file = file.expect("a directory entry").path();
            if file.extension().is_some_and(|x| x == "json") {
                let raw = fs::read_to_string(&file).expect("read a frozen document");
                let doc = serde_json::from_str(&raw)
                    .unwrap_or_else(|e| panic!("{} is not JSON: {e}", file.display()));
                files.push((file, doc));
            }
        }
    }
    files.sort_by(|a, b| a.0.cmp(&b.0));
    files
}

fn demo_product_group_data() -> Vec<(PathBuf, Value)> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../ops/demo/passports");
    let mut files: Vec<PathBuf> = fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("read {}: {e}", dir.display()))
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .collect();
    files.sort();
    files
        .into_iter()
        .map(|file| {
            let raw = fs::read_to_string(&file).expect("read a demo passport");
            let body: Value = serde_json::from_str(&raw)
                .unwrap_or_else(|e| panic!("{} is not JSON: {e}", file.display()));
            let data = body
                .get("productGroupData")
                .unwrap_or_else(|| panic!("{} carries no productGroupData", file.display()))
                .clone();
            (file, data)
        })
        .collect()
}

/// What came of putting one too-wide integer at one position.
#[derive(Default)]
struct Tally {
    positions: usize,
    refused_on_read: usize,
    /// Read, carried verbatim, and refused by publish before it signs.
    refused_at_publish_gate: usize,
    read_and_signable: usize,
    /// Read, then refused by the canonicaliser: the defect this test exists for.
    read_then_unsignable: Vec<String>,
}

fn canonicalises(value: &Value) -> Result<(), String> {
    dpp_crypto::jws::canonicalize(value)
        .map(|_| ())
        .map_err(|e| e.to_string())
}

#[test]
fn a_number_a_stored_passport_reads_is_one_signing_can_hold() {
    let lenses = LensRegistry::new();
    let catalog = ProductGroupCatalog::new();
    let mut tally = Tally::default();

    for (path, doc) in frozen_docs() {
        // A document that does not read today is listed in `passport_doc_compat`
        // with its reason; there is nothing to mutate in it.
        if Passport::from_stored(doc.clone(), &lenses, &catalog).is_err() {
            continue;
        }
        let mut pointers = Vec::new();
        number_pointers(&doc, "", &mut pointers);
        for pointer in pointers {
            for wide in too_wide() {
                tally.positions += 1;
                let mutated = with_value_at(&doc, &pointer, &wide);
                match Passport::from_stored(mutated, &lenses, &catalog) {
                    Err(_) => tally.refused_on_read += 1,
                    // A product group core has no typed variant for carries its
                    // data verbatim, numbers included: the one place free-form
                    // JSON reaches a passport. Publish refuses it at
                    // `validate_passport`, the first gate before it signs
                    // anything, so it can never reach the canonicaliser.
                    Ok(passport)
                        if matches!(
                            passport.product_group_data,
                            Some(ProductGroupData::Other(_))
                        ) =>
                    {
                        assert!(
                            dpp_domain::validate_passport(&passport).is_err(),
                            "{} at {pointer}: a passport of a group core does not type passed \
                             the publish gate, and its data is carried verbatim",
                            path.display()
                        );
                        tally.refused_at_publish_gate += 1;
                    }
                    Ok(passport) => {
                        let payload =
                            serde_json::to_value(&passport).expect("a passport serialises");
                        match canonicalises(&payload) {
                            Ok(()) => tally.read_and_signable += 1,
                            Err(e) => tally
                                .read_then_unsignable
                                .push(format!("{} at {pointer} = {wide}: {e}", path.display())),
                        }
                    }
                }
            }
        }
    }

    assert!(
        tally.positions > 300 && tally.refused_on_read > 0 && tally.read_and_signable > 0,
        "the walk must reach both outcomes, or it checks nothing: {} positions, {} refused, {} \
         signable",
        tally.positions,
        tally.refused_on_read,
        tally.read_and_signable
    );
    assert!(
        tally.read_then_unsignable.is_empty(),
        "a passport reads an integer that signing then refuses, so publish answers 500 with \
         the draft unchanged:\n{}",
        tally.read_then_unsignable.join("\n")
    );
}

#[test]
fn a_number_a_demo_passports_data_reads_is_one_signing_can_hold() {
    let mut tally = Tally::default();

    for (path, data) in demo_product_group_data() {
        let mut pointers = Vec::new();
        number_pointers(&data, "", &mut pointers);
        for pointer in pointers {
            for wide in too_wide() {
                tally.positions += 1;
                let mutated = with_value_at(&data, &pointer, &wide);
                match serde_json::from_value::<ProductGroupData>(mutated) {
                    Err(_) => tally.refused_on_read += 1,
                    Ok(read) => {
                        let payload = serde_json::to_value(&read).expect("data serialises");
                        match canonicalises(&payload) {
                            Ok(()) => tally.read_and_signable += 1,
                            Err(e) => tally
                                .read_then_unsignable
                                .push(format!("{} at {pointer} = {wide}: {e}", path.display())),
                        }
                    }
                }
            }
        }
    }

    assert!(
        tally.positions > 100 && tally.refused_on_read > 0 && tally.read_and_signable > 0,
        "the walk must reach both outcomes, or it checks nothing: {} positions, {} refused, {} \
         signable",
        tally.positions,
        tally.refused_on_read,
        tally.read_and_signable
    );
    assert!(
        tally.read_then_unsignable.is_empty(),
        "product group data reads an integer that signing then refuses, so publish answers 500 \
         with the draft unchanged:\n{}",
        tally.read_then_unsignable.join("\n")
    );
}

/// The check above would pass if `canonicalize` accepted everything. This is the
/// fact it stands on: the canonicaliser refuses each of the integers it is given.
#[test]
fn the_canonicaliser_refuses_each_integer_the_walk_uses() {
    for wide in too_wide() {
        assert!(
            canonicalises(&json!({ "n": wide })).is_err(),
            "{wide} was canonicalised: the walk above proves nothing"
        );
    }
    assert!(canonicalises(&json!({ "n": 9_007_199_254_740_991_u64 })).is_ok());
}
