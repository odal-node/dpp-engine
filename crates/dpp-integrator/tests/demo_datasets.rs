//! The demo battery datasets the README in `ops/demo/datasets` describes as
//! importing cleanly still pass row validation.
//!
//! Nothing else reads these files, so a change to what the importer refuses can
//! break the demo with every gate green. That happened once: requiring a placing
//! date for EV, LMT and industrial batteries refused every such row in both files
//! until they gained the column.

use std::path::PathBuf;

use dpp_integrator::domain::csv_parser::parse_csv;
use dpp_integrator::domain::validate::{RowValidationError, validate_row};

fn dataset(name: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../ops/demo/datasets")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

#[test]
fn every_row_of_the_valid_battery_datasets_passes_validation() {
    for name in ["09-battery-valid.csv", "18-battery-extended.csv"] {
        let rows = parse_csv(&dataset(name)).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        assert!(!rows.is_empty(), "{name} holds no rows");
        let refused: Vec<String> = rows
            .iter()
            .enumerate()
            .filter_map(|(i, row)| match validate_row("battery", row, i + 1) {
                Ok(_) => None,
                Err(RowValidationError::Invalid(errors)) => {
                    Some(format!("row {}: {errors:?}", i + 1))
                }
                Err(RowValidationError::UnsupportedProductGroup) => {
                    Some(format!("row {}: battery is not a supported group", i + 1))
                }
            })
            .collect();
        assert!(refused.is_empty(), "{name}: {refused:#?}");
    }
}
