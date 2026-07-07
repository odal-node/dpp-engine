//! Field extraction helpers shared by every sector's row validator.

use std::collections::HashMap;

use dpp_domain::domain::passport::MaterialEntry;

use super::request::RowError;

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
/// match. This lets **every** sector validator accept both camelCase and
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

/// Parse `material_N_name` / `_weightKg` / `_recycledPct` / `_originCountry`
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
        let origin_country = get_field(row, &format!("material_{i}_originCountry"))
            .filter(|v| !v.trim().is_empty())
            .cloned();
        out.push(MaterialEntry {
            name,
            weight_kg,
            recycled_pct,
            origin_country,
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
}
