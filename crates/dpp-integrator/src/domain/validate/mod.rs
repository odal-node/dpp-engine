//! ProductGroup dispatch for row-level validation.

mod aluminium;
mod battery;
mod construction;
mod furniture;
mod mattress;
mod steel;
mod textile;
mod toy;
mod tyre;

pub use aluminium::validate_aluminium_row;
pub use battery::validate_battery_row;
pub use construction::validate_construction_row;
pub use furniture::validate_furniture_row;
pub use mattress::validate_mattress_row;
pub use steel::validate_steel_row;
pub use textile::validate_textile_row;
pub use toy::validate_toy_row;
pub use tyre::validate_tyre_row;

use std::collections::HashMap;

use super::request::{CreatePassportRequest, RowError};

/// One CSV column a product group's row validator reads.
///
/// # Why the column list is data rather than only code
///
/// The importer reads columns imperatively (`require_str(row, "productName", …)`)
/// and the CSV template served to operators was a hand-written header listing
/// the same names. Two lists, agreeing by hand — the arrangement this codebase
/// has watched fail three times now, most expensively when a restated
/// `PROTECTED_PATCH_FIELDS` drifted three entries short of the canonical one.
///
/// Nothing had gone wrong here yet: checked column by column, every template
/// matched its validator. But nothing would have *said* so. A column renamed in
/// a validator and not in its template produces an operator downloading a
/// template whose header the importer rejects, and the first person to find out
/// is that operator.
///
/// So the template is now generated from this list and a test asserts the
/// committed file still matches, the same arrangement `openapi-check` uses for
/// the API bundle. The link from this list to the validator body stays a
/// convention; the link from this list to the template is mechanical, and that
/// is the half that was silently maintained by hand.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Column {
    /// The CSV header name, camelCase, exactly as the validator reads it.
    pub name: &'static str,
    /// Whether a row is rejected when this column is absent or empty.
    pub required: bool,
}

impl Column {
    #[must_use]
    pub const fn required(name: &'static str) -> Self {
        Self {
            name,
            required: true,
        }
    }

    #[must_use]
    pub const fn optional(name: &'static str) -> Self {
        Self {
            name,
            required: false,
        }
    }

    /// The header cell as it appears in a served template.
    #[must_use]
    pub fn header_cell(&self) -> String {
        let tag = if self.required {
            "REQUIRED"
        } else {
            "OPTIONAL"
        };
        format!("{} [{tag}]", self.name)
    }
}

/// Envelope columns every product group accepts, read by the shared helpers
/// rather than by any one validator.
///
/// Listed once so a product group cannot forget them and cannot spell them
/// differently — they are the same columns for every product group by
/// construction, not by twelve separate decisions.
pub const ENVELOPE_COLUMNS: &[Column] = &[
    Column::optional("placedOnMarketDate"),
    Column::optional("commodityCode"),
];

/// Render a template header row from a product group's column list.
#[must_use]
pub fn template_header(columns: &[Column]) -> String {
    columns
        .iter()
        .map(Column::header_cell)
        .collect::<Vec<_>>()
        .join(",")
}

/// The columns a product group's validator reads, in template order — the
/// product group's own, then the envelope columns every product group shares.
///
/// `None` for a product group with no row validator, which is the same answer
/// [`validate_row`] gives, from a match over the same keys, so the two cannot
/// disagree about what is supported.
///
/// The envelope columns are appended here rather than repeated in each product
/// group's list: they are the same columns for every product group by
/// construction, and a list that has to remember them is a list that can forget
/// them.
#[must_use]
pub fn columns_for(product_group: &str) -> Option<Vec<Column>> {
    let own: &[Column] = match product_group {
        "battery" => battery::COLUMNS,
        "textile" => textile::COLUMNS,
        "steel" => steel::COLUMNS,
        "aluminium" => aluminium::COLUMNS,
        "tyre" => tyre::COLUMNS,
        "mattress" => mattress::COLUMNS,
        "furniture" => furniture::COLUMNS,
        "toy" => toy::COLUMNS,
        "construction" => construction::COLUMNS,
        _ => return None,
    };
    Some(
        own.iter()
            .copied()
            .chain(ENVELOPE_COLUMNS.iter().copied())
            .collect(),
    )
}

/// ProductGroup keys with a row validator wired up — the single list the
/// pre-upload product group check, [`validate_row`] and [`columns_for`] all
/// read, so they cannot silently drift apart.
///
/// **Not exhaustive over the catalog, and deliberately so.** Two product groups
/// have a typed shape that a row of CSV cannot carry, and adding them means
/// inventing a wire format rather than filling a gap:
///
/// - `detergent` requires `surfactants`, a list of `{name, biodegradable,
///   concentrationBand}`. Flattening a variable-length list of three-field
///   records into fixed columns means either a delimiter convention inside a
///   cell or a column-per-index cap, and both are formats an operator has to be
///   taught. Worth doing deliberately, not as a side effect of this list.
/// - `unsold-goods` is not a product row at all. An Art. 24 disclosure is one
///   undertaking, one financial year, and N discard lines — a spreadsheet of
///   them is a different document with a header section, not a passport per
///   row. It needs its own import shape.
///
/// `electronics` is absent for a smaller reason: its `productCategory` and
/// `energyEfficiencyClass` are typed enums in core with no string parse path,
/// so a validator would have to invent one. That is a core-shaped decision.
pub const SUPPORTED_PRODUCT_GROUPS: &[&str] = &[
    "battery",
    "textile",
    "steel",
    "aluminium",
    "tyre",
    "mattress",
    "furniture",
    "toy",
    "construction",
];

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
    let result = match product_group {
        "battery" => validate_battery_row(row, row_num),
        "textile" => validate_textile_row(row, row_num),
        "steel" => validate_steel_row(row, row_num),
        "aluminium" => validate_aluminium_row(row, row_num),
        "tyre" => validate_tyre_row(row, row_num),
        "mattress" => validate_mattress_row(row, row_num),
        "furniture" => validate_furniture_row(row, row_num),
        "toy" => validate_toy_row(row, row_num),
        "construction" => validate_construction_row(row, row_num),
        _ => return Err(RowValidationError::UnsupportedProductGroup),
    };
    result.map_err(RowValidationError::Invalid)
}

#[cfg(test)]
mod tests {
    use super::{Column, ENVELOPE_COLUMNS, SUPPORTED_PRODUCT_GROUPS, columns_for, template_header};

    /// The committed CSV template must be the header this product group's column
    /// list generates.
    ///
    /// This is the assertion the two lists never had. Both were maintained by
    /// hand and both happened to be correct; nothing said so, and a column
    /// renamed on one side would have been found by an operator downloading a
    /// template the importer then rejected.
    ///
    /// Same arrangement `openapi-check` uses for the API bundle: the artifact
    /// stays committed, and a test proves it still matches what generates it.
    #[test]
    fn every_template_header_matches_its_validator_columns() {
        let mut wrong = Vec::new();
        for group in SUPPORTED_PRODUCT_GROUPS {
            let columns = columns_for(group).expect("a supported product group has columns");
            let expected = template_header(&columns);
            let committed = crate::handlers::templates::template_for(group)
                .expect("a supported product group has a template")
                .lines()
                .next()
                .expect("a template has a header row")
                .to_owned();
            if committed != expected {
                wrong.push(format!(
                    "  {group}\n    template:  {committed}\n    validator: {expected}"
                ));
            }
        }
        assert!(
            wrong.is_empty(),
            "a CSV template header no longer matches the columns its validator reads. An \
             operator downloading that template gets one the importer rejects, and nothing \
             else would say so:\n{}",
            wrong.join("\n")
        );
    }

    /// Every supported product group has a template, and every template belongs
    /// to a supported product group.
    ///
    /// The two lists are separate matches over the same keys, so this is the
    /// check that they stay the same set — the gap this closes is a product
    /// group with an importer and no template, which is the shape #192 reported
    /// (and which had since been filled by hand for three product groups).
    #[test]
    fn supported_product_groups_and_templates_are_the_same_set() {
        for group in SUPPORTED_PRODUCT_GROUPS {
            assert!(
                crate::handlers::templates::template_for(group).is_some(),
                "{group} has a row validator but no CSV template, so it can only be used by \
                 someone who reads the validator source to learn the column names"
            );
            assert!(
                columns_for(group).is_some(),
                "{group} is listed as supported but declares no columns"
            );
        }
    }

    /// A column list with a repeated name would produce a template with two
    /// identical headers, and the second would be unreachable.
    #[test]
    fn no_product_group_declares_a_column_twice() {
        for group in SUPPORTED_PRODUCT_GROUPS {
            let columns = columns_for(group).expect("a supported product group has columns");
            let mut names: Vec<&str> = columns.iter().map(|c| c.name).collect();
            let before = names.len();
            names.sort_unstable();
            names.dedup();
            assert_eq!(
                names.len(),
                before,
                "{group} declares a column more than once"
            );
        }
    }

    /// The envelope columns land on every product group, and land last.
    #[test]
    fn every_product_group_carries_the_envelope_columns() {
        for group in SUPPORTED_PRODUCT_GROUPS {
            let columns = columns_for(group).expect("a supported product group has columns");
            let tail: Vec<Column> = columns[columns.len() - ENVELOPE_COLUMNS.len()..].to_vec();
            assert_eq!(
                tail,
                ENVELOPE_COLUMNS.to_vec(),
                "{group} must end with the envelope columns every product group shares"
            );
        }
    }

    /// Every example row shipped in a template must pass its own validator.
    ///
    /// A template is the first thing an operator touches, and its example rows
    /// are what they copy. Shipping one the importer rejects teaches them the
    /// format is broken before they have written a line of their own — and the
    /// header check above cannot catch it, because a header can be perfectly
    /// correct while the row beneath it holds an invalid GTIN or an enum value
    /// no validator accepts.
    #[test]
    fn every_template_example_row_passes_its_own_validator() {
        let mut rejected = Vec::new();
        for group in SUPPORTED_PRODUCT_GROUPS {
            let template = crate::handlers::templates::template_for(group)
                .expect("a supported product group has a template");

            // Parsed with the importer's own reader rather than by splitting on
            // commas. A template cell may be quoted and contain commas — the
            // textile `fibreComposition` example is a JSON array — so a naive
            // split disagrees with the thing this test exists to imitate.
            let rows = crate::domain::csv_parser::parse_csv(template.as_bytes())
                .unwrap_or_else(|e| panic!("{group} template is not parseable CSV: {e:?}"));

            for (offset, row) in rows.iter().enumerate() {
                if let Err(errs) = super::validate_row(group, row, offset + 1) {
                    let detail = match errs {
                        super::RowValidationError::UnsupportedProductGroup => {
                            "product group has no validator".to_owned()
                        }
                        super::RowValidationError::Invalid(e) => e
                            .iter()
                            .map(|e| format!("{}: {}", e.field, e.message))
                            .collect::<Vec<_>>()
                            .join("; "),
                    };
                    rejected.push(format!("  {group} row {}: {detail}", offset + 1));
                }
            }
        }
        assert!(
            rejected.is_empty(),
            "a template ships an example row its own importer rejects, so the first thing an \
             operator copies does not work:\n{}",
            rejected.join("\n")
        );
    }
}
