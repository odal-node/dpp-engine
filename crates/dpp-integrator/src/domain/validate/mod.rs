//! ProductGroup dispatch for row-level validation.

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

/// ProductGroup keys with a row validator wired up — the single list both the
/// pre-upload product group check and [`validate_row`] read, so the two cannot
/// silently drift apart. Not every catalog product group has a validator yet
/// (electronics, construction, toy, furniture, detergent, and unsold-goods
/// bulk import are not covered) — that gap is real, not an oversight, and
/// callers must not assume this list is exhaustive over all product groups.
pub const SUPPORTED_SECTORS: &[&str] = &["battery", "textile", "steel", "aluminium", "tyre"];

/// Whether `key` names something this crate can import.
///
/// Accepts a battery **template** key (`battery-ev`, …) as well as the product
/// group itself, because an operator who downloads `battery-ev` posts it back to
/// `battery-ev` — and a route that hands out a name it then refuses is worse
/// than one that never offered it.
///
/// The import handler's pre-upload guard and [`validate_row`] both go through
/// here, so the two cannot come to disagree about what is importable. They
/// already had: the guard held its own list and rejected the template keys
/// before the dispatch that understood them was ever reached.
#[must_use]
pub fn is_importable(key: &str) -> bool {
    SUPPORTED_SECTORS
        .contains(&crate::domain::battery_template::product_group_for_template_key(key))
}

/// Row-level validation failure: either the product group has no validator at all,
/// or the row itself failed field validation. Kept as a distinct, typed case
/// rather than an `unreachable!()` at the call site.
pub enum RowValidationError {
    UnsupportedProductGroup,
    Invalid(Vec<RowError>),
}

/// Dispatch a raw row to its product group's validator.
pub fn validate_row(
    product_group: &str,
    row: &HashMap<String, String>,
    row_num: usize,
) -> Result<CreatePassportRequest, RowValidationError> {
    // A battery template key (`battery-ev`, …) imports as `battery`; every
    // other key is its own product group. See `battery_template`.
    let result =
        match crate::domain::battery_template::product_group_for_template_key(product_group) {
            "battery" => validate_battery_row(row, row_num),
            "textile" => validate_textile_row(row, row_num),
            "steel" => validate_steel_row(row, row_num),
            "aluminium" => validate_aluminium_row(row, row_num),
            "tyre" => validate_tyre_row(row, row_num),
            _ => return Err(RowValidationError::UnsupportedProductGroup),
        };
    result.map_err(RowValidationError::Invalid)
}
