//! Field-extraction helpers for `sectorData` — the same get→as_T→format→
//! fallback shape repeats across every sector section in [`super::sections`].

use serde_json::Value;

use crate::esc::esc;

/// HTML-escaped string field, or `fallback` if absent or the wrong type.
pub(crate) fn str_field(sd: &Value, key: &str, fallback: &str) -> String {
    esc(sd.get(key).and_then(|v| v.as_str()).unwrap_or(fallback))
}

/// A float field formatted by `fmt`, or `fallback` if absent or the wrong type.
pub(crate) fn f64_field(
    sd: &Value,
    key: &str,
    fallback: &str,
    fmt: impl FnOnce(f64) -> String,
) -> String {
    sd.get(key)
        .and_then(|v| v.as_f64())
        .map(fmt)
        .unwrap_or_else(|| fallback.to_owned())
}

/// An integer field formatted by `fmt`, or `fallback` if absent or the wrong type.
pub(crate) fn u64_field(
    sd: &Value,
    key: &str,
    fallback: &str,
    fmt: impl FnOnce(u64) -> String,
) -> String {
    sd.get(key)
        .and_then(|v| v.as_u64())
        .map(fmt)
        .unwrap_or_else(|| fallback.to_owned())
}

/// A boolean field mapped to `yes`/`no`, or `fallback` if absent or the wrong type.
pub(crate) fn bool_field(sd: &Value, key: &str, fallback: &str, yes: &str, no: &str) -> String {
    sd.get(key)
        .and_then(|v| v.as_bool())
        .map(|v| if v { yes } else { no })
        .unwrap_or(fallback)
        .to_owned()
}

/// The length of an array field, or `fallback` if absent or the wrong type.
pub(crate) fn array_len_field(sd: &Value, key: &str, fallback: &str) -> String {
    sd.get(key)
        .and_then(|v| v.as_array())
        .map(|a| a.len().to_string())
        .unwrap_or_else(|| fallback.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn str_field_escapes_and_falls_back() {
        let sd = serde_json::json!({"name": "A & B"});
        assert_eq!(str_field(&sd, "name", "-"), "A &amp; B");
        assert_eq!(str_field(&sd, "missing", "-"), "-");
    }

    #[test]
    fn f64_field_formats_and_falls_back() {
        let sd = serde_json::json!({"pct": 12.5});
        assert_eq!(f64_field(&sd, "pct", "-", |v| format!("{v:.1}%")), "12.5%");
        assert_eq!(f64_field(&sd, "missing", "-", |v| format!("{v:.1}%")), "-");
    }

    #[test]
    fn u64_field_formats_and_falls_back() {
        let sd = serde_json::json!({"years": 5});
        assert_eq!(
            u64_field(&sd, "years", "-", |v| format!("{v} years")),
            "5 years"
        );
        assert_eq!(
            u64_field(&sd, "missing", "-", |v| format!("{v} years")),
            "-"
        );
    }

    #[test]
    fn bool_field_maps_and_falls_back() {
        let sd = serde_json::json!({"ce": true});
        assert_eq!(bool_field(&sd, "ce", "-", "Yes", "No"), "Yes");
        let sd = serde_json::json!({"ce": false});
        assert_eq!(bool_field(&sd, "ce", "-", "Yes", "No"), "No");
        let sd = serde_json::json!({});
        assert_eq!(bool_field(&sd, "ce", "-", "Yes", "No"), "-");
    }

    #[test]
    fn array_len_field_counts_and_falls_back() {
        let sd = serde_json::json!({"items": ["a", "b", "c"]});
        assert_eq!(array_len_field(&sd, "items", "-"), "3");
        assert_eq!(array_len_field(&sd, "missing", "-"), "-");
    }
}
