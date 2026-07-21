//! Toy safety sector HTML section.

use crate::fields::{bool_field, str_field};

pub(super) fn build_toy_section(p: &serde_json::Value) -> String {
    let sd = match p.get("sectorData") {
        Some(v) => v,
        None => return String::new(),
    };
    let age = str_field(sd, "ageGroup", "-");
    let material = str_field(sd, "primaryMaterial", "-");
    let country = str_field(sd, "countryOfManufacture", "-");
    let ce = bool_field(sd, "ceMarking", "-", "Yes", "No");
    format!(
        r#"<h2>Toy Safety Information</h2>
    <table aria-label="Toy data">
      <tr><th scope="row">Age Group</th><td>{age}</td></tr>
      <tr><th scope="row">Primary Material</th><td>{material}</td></tr>
      <tr><th scope="row">Country of Manufacture</th><td>{country}</td></tr>
      <tr><th scope="row">CE Marking</th><td>{ce}</td></tr>
    </table>"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_data_populates_all_fields() {
        let p = serde_json::json!({"sectorData": {
            "ageGroup": "3+",
            "primaryMaterial": "ABS Plastic",
            "countryOfManufacture": "CN",
            "ceMarking": true,
        }});
        let html = build_toy_section(&p);
        assert!(html.contains("3+"));
        assert!(html.contains("ABS Plastic"));
        assert!(html.contains("CN"));
        assert!(html.contains(">Yes<"));
    }

    #[test]
    fn ce_marking_false_renders_no() {
        let p = serde_json::json!({"sectorData": {"ceMarking": false}});
        let html = build_toy_section(&p);
        assert!(html.contains(">No<"));
    }

    #[test]
    fn missing_fields_fall_back_to_dashes() {
        let p = serde_json::json!({"sectorData": {}});
        let html = build_toy_section(&p);
        assert!(html.contains("Toy Safety Information"));
        assert!(html.contains(">-<"));
    }

    #[test]
    fn absent_sector_data_returns_empty_string() {
        let p = serde_json::json!({});
        assert_eq!(build_toy_section(&p), "");
    }
}
