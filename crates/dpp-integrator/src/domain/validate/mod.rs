//! Sector dispatch for row-level validation.

mod aluminium;
mod battery;
mod steel;
mod textile;
mod tyre;

pub use aluminium::validate_aluminium_row;
pub use battery::validate_battery_row;
pub use steel::validate_steel_row;
pub use textile::validate_textile_row;
pub use tyre::validate_tyre_row;

use std::collections::HashMap;

use super::request::{CreatePassportRequest, RowError};

/// Sector keys with a row validator wired up — the single list both the
/// pre-upload sector check and [`validate_row`] read, so the two cannot
/// silently drift apart. Not every catalog sector has a validator yet
/// (electronics, construction, toy, furniture, detergent, and unsold-goods
/// bulk import are not covered) — that gap is real, not an oversight, and
/// callers must not assume this list is exhaustive over all sectors.
pub const SUPPORTED_SECTORS: &[&str] = &["battery", "textile", "steel", "aluminium", "tyre"];

/// Row-level validation failure: either the sector has no validator at all,
/// or the row itself failed field validation. Kept as a distinct, typed case
/// rather than an `unreachable!()` at the call site.
pub enum RowValidationError {
    UnsupportedSector,
    Invalid(Vec<RowError>),
}

/// Dispatch a raw row to its sector's validator.
pub fn validate_row(
    sector: &str,
    row: &HashMap<String, String>,
    row_num: usize,
) -> Result<CreatePassportRequest, RowValidationError> {
    let result = match sector {
        "battery" => validate_battery_row(row, row_num),
        "textile" => validate_textile_row(row, row_num),
        "steel" => validate_steel_row(row, row_num),
        "aluminium" => validate_aluminium_row(row, row_num),
        "tyre" => validate_tyre_row(row, row_num),
        _ => return Err(RowValidationError::UnsupportedSector),
    };
    result.map_err(RowValidationError::Invalid)
}
