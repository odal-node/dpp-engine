//! Field extraction helpers shared by every product group's row validator.

use std::collections::HashMap;

use dpp_domain::identifier::gtin::Gtin;
use dpp_domain::passport::MaterialEntry;

use super::request::RowError;

/// Parse `gtin` (when present) into the validated [`Gtin`] newtype, pushing a
/// `RowError` instead if it is not a structurally valid GS1 GTIN-14 (14 digits +
/// mod-10 check digit). Shared by the product group importers so steel/aluminium/tyre
/// validate the checksum the same way the battery importer already does — a bad
/// checksum must not pass through the pipeline unchecked.
///
/// Returns the parsed value rather than validating and discarding it: the product group
/// structs now hold `Gtin`, and parsing once here means a call site cannot end up
/// re-parsing a string it has already proven valid.
pub(super) fn parse_gtin(
    gtin: Option<&str>,
    row_num: usize,
    errors: &mut Vec<RowError>,
) -> Option<Gtin> {
    let g = gtin?;
    match Gtin::parse(g) {
        Ok(parsed) => Some(parsed),
        Err(e) => {
            errors.push(RowError {
                row: row_num,
                field: "gtin".into(),
                message: e.to_string(),
            });
            None
        }
    }
}

/// Normalize a header key for case/separator-insensitive matching: drop
/// non-alphanumerics (`_`, `-`, spaces) and lowercase. So `manufacturerName`,
/// `manufacturer_name`, and `Manufacturer Name` all map to `manufacturername`.
fn normalize_key(key: &str) -> String {
    key.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

/// Look up a field tolerantly: exact key first, then a case/separator-insensitive
/// match. This lets **every** product group validator accept both camelCase and
/// snake_case headers (`manufacturerName` ≡ `manufacturer_name`) with no per-field
/// alias lists. Semantically-different headers (e.g. `manufacturerCountry` vs a
/// full `manufacturer_address`) still need explicit aliases via [`aliased`].
pub(super) fn get_field<'a>(row: &'a HashMap<String, String>, field: &str) -> Option<&'a String> {
    if let Some(v) = row.get(field) {
        return Some(v);
    }
    let target = normalize_key(field);
    row.iter()
        .find(|(k, _)| normalize_key(k) == target)
        .map(|(_, v)| v)
}

pub(super) fn require_str(
    row: &HashMap<String, String>,
    field: &str,
    row_num: usize,
    errors: &mut Vec<RowError>,
) -> Option<String> {
    match get_field(row, field).filter(|v| !v.trim().is_empty()) {
        Some(v) => Some(v.clone()),
        None => {
            errors.push(RowError {
                row: row_num,
                field: field.to_owned(),
                message: format!("{field} is required"),
            });
            None
        }
    }
}

pub(super) fn require_f64(
    row: &HashMap<String, String>,
    field: &str,
    row_num: usize,
    errors: &mut Vec<RowError>,
) -> Option<f64> {
    let raw = require_str(row, field, row_num, errors)?;
    match raw.parse::<f64>() {
        Ok(v) if v.is_finite() => Some(v),
        Ok(_) => {
            errors.push(RowError {
                row: row_num,
                field: field.to_owned(),
                message: format!("Expected a finite number, got '{raw}'"),
            });
            None
        }
        Err(_) => {
            errors.push(RowError {
                row: row_num,
                field: field.to_owned(),
                message: format!("Expected a number, got '{raw}'"),
            });
            None
        }
    }
}

pub(super) fn require_u32(
    row: &HashMap<String, String>,
    field: &str,
    row_num: usize,
    errors: &mut Vec<RowError>,
) -> Option<u32> {
    let raw = require_str(row, field, row_num, errors)?;
    match raw.parse::<u32>() {
        Ok(v) => Some(v),
        Err(_) => {
            errors.push(RowError {
                row: row_num,
                field: field.to_owned(),
                message: format!("Expected a positive integer, got '{raw}'"),
            });
            None
        }
    }
}

/// Parse a required boolean cell.
///
/// Accepts the spellings a spreadsheet actually produces — `true`/`false`,
/// `yes`/`no`, `1`/`0` — case-insensitively. Excel writes `TRUE` from a checkbox
/// and `yes` from a human, and rejecting either would mean an operator whose
/// file looks correct in the application they authored it in.
///
/// Deliberately not lenient about anything else: an unrecognised value is an
/// error rather than a silent `false`, because `false` is a positive claim here
/// (a toy without CE marking is a different product, not a missing field).
pub(super) fn require_bool(
    row: &HashMap<String, String>,
    field: &str,
    row_num: usize,
    errors: &mut Vec<RowError>,
) -> Option<bool> {
    let raw = require_str(row, field, row_num, errors)?;
    match raw.trim().to_ascii_lowercase().as_str() {
        "true" | "yes" | "1" => Some(true),
        "false" | "no" | "0" => Some(false),
        _ => {
            errors.push(RowError {
                row: row_num,
                field: field.to_owned(),
                message: format!("Expected true/false, yes/no or 1/0, got '{raw}'"),
            });
            None
        }
    }
}

/// [`require_bool`] for a column that may be absent or empty.
///
/// An absent cell is `None`; a present but unparseable one is an error, for the
/// same reason as above — silently dropping a value the operator wrote is worse
/// than telling them it was not understood.
pub(super) fn optional_bool(
    row: &HashMap<String, String>,
    field: &str,
    row_num: usize,
    errors: &mut Vec<RowError>,
) -> Option<bool> {
    let raw = optional_str(row, field)?;
    match raw.trim().to_ascii_lowercase().as_str() {
        "true" | "yes" | "1" => Some(true),
        "false" | "no" | "0" => Some(false),
        _ => {
            errors.push(RowError {
                row: row_num,
                field: field.to_owned(),
                message: format!("Expected true/false, yes/no or 1/0, got '{raw}'"),
            });
            None
        }
    }
}

pub(super) fn optional_f64(
    row: &HashMap<String, String>,
    field: &str,
    row_num: usize,
    errors: &mut Vec<RowError>,
) -> Option<f64> {
    let raw = get_field(row, field).filter(|v| !v.trim().is_empty())?;
    match raw.parse::<f64>() {
        Ok(v) if v.is_finite() => Some(v),
        Ok(_) => {
            errors.push(RowError {
                row: row_num,
                field: field.to_owned(),
                message: format!("Expected a finite number, got '{raw}'"),
            });
            None
        }
        Err(_) => {
            errors.push(RowError {
                row: row_num,
                field: field.to_owned(),
                message: format!("Expected a number, got '{raw}'"),
            });
            None
        }
    }
}

pub(super) fn optional_str(row: &HashMap<String, String>, field: &str) -> Option<String> {
    get_field(row, field)
        .filter(|v| !v.trim().is_empty())
        .cloned()
}

/// An optional customs tariff classification column (HS-6, CN-8 or TARIC-10).
///
/// Validated here, against the domain type, rather than left for the vault to
/// reject. Both refuse the same values, but only this one can say *which row* —
/// a bulk import that fails with "invalid commodity code" and no row number
/// leaves the operator to find it across a spreadsheet by hand.
///
/// The value is sent on as a string, because that is what the request carries;
/// parsing it is a check, not a conversion.
pub(super) fn optional_commodity_code(
    row: &HashMap<String, String>,
    field: &str,
    row_num: usize,
    errors: &mut Vec<RowError>,
) -> Option<String> {
    let raw = get_field(row, field).filter(|v| !v.trim().is_empty())?;
    let trimmed = raw.trim();
    match dpp_domain::identifier::commodity_code::CommodityCode::parse(trimmed) {
        Ok(_) => Some(trimmed.to_owned()),
        Err(e) => {
            errors.push(RowError {
                row: row_num,
                field: field.to_owned(),
                message: format!("Invalid commodity code '{raw}': {e}"),
            });
            None
        }
    }
}

/// An optional ISO-8601 (`YYYY-MM-DD`) date column.
///
/// Rejects rather than ignores a malformed value. An unparseable date here is
/// not a cosmetic problem: `placedOnMarketDate` is the regulated event that
/// fixes **which law governs the product**, and dropping it silently would
/// import a passport whose governing law is simply unknown — indistinguishable
/// from one where the operator deliberately left the column blank.
pub(super) fn optional_date(
    row: &HashMap<String, String>,
    field: &str,
    row_num: usize,
    errors: &mut Vec<RowError>,
) -> Option<chrono::NaiveDate> {
    let raw = get_field(row, field).filter(|v| !v.trim().is_empty())?;
    match chrono::NaiveDate::parse_from_str(raw.trim(), "%Y-%m-%d") {
        Ok(date) => Some(date),
        Err(_) => {
            errors.push(RowError {
                row: row_num,
                field: field.to_owned(),
                message: format!("Expected an ISO-8601 date (YYYY-MM-DD), got '{raw}'"),
            });
            None
        }
    }
}

/// First present, non-empty value among header `aliases`. Each alias is matched
/// case/separator-insensitively via [`get_field`], so the list only needs to
/// cover *semantic* variants (e.g. `manufacturerCountry` vs `manufacturerAddress`).
pub(super) fn aliased<'a>(
    row: &'a HashMap<String, String>,
    aliases: &[&str],
) -> Option<&'a String> {
    aliases
        .iter()
        .find_map(|k| get_field(row, k).filter(|v| !v.trim().is_empty()))
}

/// Required string accepting any of `aliases`; reports the error under `canonical`.
pub(super) fn require_aliased(
    row: &HashMap<String, String>,
    aliases: &[&str],
    canonical: &str,
    row_num: usize,
    errors: &mut Vec<RowError>,
) -> Option<String> {
    match aliased(row, aliases) {
        Some(v) => Some(v.clone()),
        None => {
            errors.push(RowError {
                row: row_num,
                field: canonical.to_owned(),
                message: format!("{canonical} is required"),
            });
            None
        }
    }
}

/// Maximum `material_N_*` column groups parsed from a row.
const MAX_MATERIAL_COLUMNS: usize = 10;

/// Parse `material_N_name` / `_weightKg` / `_recycledPct` / `_countryOfOrigin`
/// column groups into a bill of materials. Groups with a blank name are skipped
/// (handles trailing empty material slots in templates).
pub(super) fn parse_materials(row: &HashMap<String, String>) -> Vec<MaterialEntry> {
    let mut out = Vec::new();
    for i in 1..=MAX_MATERIAL_COLUMNS {
        let name =
            match get_field(row, &format!("material_{i}_name")).filter(|v| !v.trim().is_empty()) {
                Some(n) => n.clone(),
                None => continue,
            };
        let weight_kg = get_field(row, &format!("material_{i}_weightKg"))
            .and_then(|v| v.parse::<f64>().ok())
            .filter(|v| v.is_finite())
            .unwrap_or(0.0);
        let recycled_pct = get_field(row, &format!("material_{i}_recycledPct"))
            .and_then(|v| v.parse::<f64>().ok())
            .filter(|v| v.is_finite());
        let country_of_origin = get_field(row, &format!("material_{i}_countryOfOrigin"))
            .filter(|v| !v.trim().is_empty())
            .cloned();
        out.push(MaterialEntry {
            name,
            weight_kg,
            recycled_pct,
            country_of_origin,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_field_matches_snake_and_camel() {
        let row = HashMap::from([("manufacturer_name".to_string(), "Acme".to_string())]);
        assert_eq!(
            get_field(&row, "manufacturerName").map(String::as_str),
            Some("Acme")
        );
        assert_eq!(
            get_field(&row, "manufacturer_name").map(String::as_str),
            Some("Acme")
        );
        assert_eq!(
            get_field(&row, "MANUFACTURERNAME").map(String::as_str),
            Some("Acme")
        );
        assert!(get_field(&row, "somethingElse").is_none());
    }

    /// A spreadsheet writes booleans several ways and an operator writes more,
    /// so the accepted set is deliberately wider than Rust's `bool` parse.
    #[test]
    fn require_bool_accepts_the_spellings_a_spreadsheet_produces() {
        for (raw, expected) in [
            ("true", true),
            ("TRUE", true),
            ("Yes", true),
            ("1", true),
            ("false", false),
            ("FALSE", false),
            ("no", false),
            ("0", false),
        ] {
            let row = HashMap::from([("ceMarking".to_owned(), raw.to_owned())]);
            let mut errors = Vec::new();
            assert_eq!(
                require_bool(&row, "ceMarking", 1, &mut errors),
                Some(expected),
                "{raw} should parse as {expected}"
            );
            assert!(errors.is_empty(), "{raw} should not error");
        }
    }

    /// An unrecognised value is an error, never a silent `false`. `false` is a
    /// positive claim here — a toy without CE marking is a different product,
    /// not a missing field — so guessing it would put a conformity statement on
    /// a passport the operator never made.
    #[test]
    fn an_unparseable_boolean_is_an_error_not_a_false() {
        let row = HashMap::from([("ceMarking".to_owned(), "maybe".to_owned())]);
        let mut errors = Vec::new();
        assert_eq!(require_bool(&row, "ceMarking", 3, &mut errors), None);
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].field, "ceMarking");
        assert_eq!(errors[0].row, 3);
    }

    /// An absent optional boolean is `None` and not an error; a present but
    /// unparseable one still is, because dropping a value the operator wrote is
    /// worse than telling them it was not understood.
    #[test]
    fn optional_bool_distinguishes_absent_from_unparseable() {
        let mut errors = Vec::new();
        assert_eq!(
            optional_bool(&HashMap::new(), "containsBattery", 1, &mut errors),
            None
        );
        assert!(errors.is_empty(), "absent is not an error");

        let row = HashMap::from([("containsBattery".to_owned(), "sometimes".to_owned())]);
        assert_eq!(optional_bool(&row, "containsBattery", 1, &mut errors), None);
        assert_eq!(errors.len(), 1, "present but unparseable is an error");
    }
}
