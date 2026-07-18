//! Construction products sector HTML section.

use crate::esc::esc;

pub(super) fn build_construction_section(p: &serde_json::Value) -> String {
    let sd = match p.get("sectorData") {
        Some(v) => v,
        None => return String::new(),
    };
    let family = esc(sd
        .get("productFamily")
        .and_then(|v| v.as_str())
        .unwrap_or("-"));
    let country = esc(sd
        .get("countryOfManufacture")
        .and_then(|v| v.as_str())
        .unwrap_or("-"));
    let unit = esc(sd
        .get("functionalUnit")
        .and_then(|v| v.as_str())
        .unwrap_or("unit"));
    let co2e = sd
        .get("co2ePerFunctionalUnitKg")
        .and_then(|v| v.as_f64())
        .map(|v| format!("{v:.2} kg CO\u{2082}e / {unit}"))
        .unwrap_or_else(|| "-".into());
    let ce = sd
        .get("ceMarking")
        .and_then(|v| v.as_bool())
        .map(|v| if v { "Yes" } else { "No" })
        .unwrap_or("-");
    format!(
        r#"<h2>Construction Product Information</h2>
    <table aria-label="Construction product data">
      <tr><th scope="row">Product Family</th><td>{family}</td></tr>
      <tr><th scope="row">Country of Manufacture</th><td>{country}</td></tr>
      <tr><th scope="row">Carbon Footprint</th><td>{co2e}</td></tr>
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
            "productFamily": "Insulation Board",
            "countryOfManufacture": "FR",
            "functionalUnit": "m2",
            "co2ePerFunctionalUnitKg": 3.25,
            "ceMarking": true,
        }});
        let html = build_construction_section(&p);
        assert!(html.contains("Insulation Board"));
        assert!(html.contains("FR"));
        assert!(html.contains("3.25 kg CO\u{2082}e / m2"));
        assert!(html.contains(">Yes<"));
    }

    #[test]
    fn ce_marking_false_renders_no() {
        let p = serde_json::json!({"sectorData": {"ceMarking": false}});
        let html = build_construction_section(&p);
        assert!(html.contains(">No<"));
    }

    #[test]
    fn missing_fields_fall_back_to_dashes_and_default_unit() {
        let p = serde_json::json!({"sectorData": {}});
        let html = build_construction_section(&p);
        assert!(html.contains("Construction Product Information"));
        assert!(html.contains(">-<"));
    }

    #[test]
    fn absent_sector_data_returns_empty_string() {
        let p = serde_json::json!({});
        assert_eq!(build_construction_section(&p), "");
    }
}
