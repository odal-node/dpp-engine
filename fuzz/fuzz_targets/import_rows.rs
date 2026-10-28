#![no_main]
//! Fuzz what an import does with the rows it parsed — every cell of an uploaded
//! spreadsheet reaches a product group's validator as a string, and the
//! validators parse GTINs, dates, numbers and the JSON some columns carry.
//! Property: for every template key an operator can import under, validating
//! any row returns `Ok`/`Err`, never panics, and the repeated-serial check
//! accounts for every valid row, keeping it or refusing it and never both.
//!
//! The rows come from `parse_csv`, the parser the import route runs on a CSV
//! upload, so the fuzzer writes cells rather than building the row maps itself.

use dpp_integrator::domain::csv_parser::parse_csv;
use dpp_integrator::domain::matcher::refuse_repeated_carrier_serials;
use dpp_integrator::domain::validate::{importable_keys, validate_row};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(rows) = parse_csv(data) else {
        return;
    };
    for key in importable_keys() {
        let valid: Vec<_> = rows
            .iter()
            .enumerate()
            .filter_map(|(i, row)| validate_row(key, row, i + 1).ok().map(|req| (i + 1, req)))
            .collect();
        let count = valid.len();
        let (kept, refused) = refuse_repeated_carrier_serials(valid);
        assert_eq!(
            kept.len() + refused.len(),
            count,
            "the repeated-serial check lost or duplicated a row under `{key}`"
        );
    }
});
