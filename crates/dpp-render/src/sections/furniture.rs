//! Furniture sector HTML section.

use crate::fields::{f64_field, str_field};

pub(super) fn build_furniture_section(p: &serde_json::Value) -> String {
    let sd = match p.get("sectorData") {
        Some(v) => v,
        None => return String::new(),
    };
    let product_type = str_field(sd, "productType", "-");
    let material = str_field(sd, "primaryMaterial", "-");
    let country = str_field(sd, "countryOfManufacture", "-");
    let co2e = f64_field(sd, "co2ePerUnitKg", "Not disclosed", |v| {
        format!("{v:.2} kg CO\u{2082}e")
    });
    let repair = f64_field(sd, "repairabilityScore", "-", |v| format!("{v:.1} / 10"));
    format!(
        r#"<h2>Furniture Information</h2>
    <table aria-label="Furniture data">
      <tr><th scope="row">Product Type</th><td>{product_type}</td></tr>
      <tr><th scope="row">Primary Material</th><td>{material}</td></tr>
      <tr><th scope="row">Country of Manufacture</th><td>{country}</td></tr>
      <tr><th scope="row">Carbon Footprint</th><td>{co2e}</td></tr>
      <tr><th scope="row">Repairability Score</th><td>{repair}</td></tr>
    </table>"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_data_populates_all_fields() {
        let p = serde_json::json!({"sectorData": {
            "productType": "Office Chair",
            "primaryMaterial": "Steel & Fabric",
            "countryOfManufacture": "SE",
            "co2ePerUnitKg": 18.4,
            "repairabilityScore": 6.0,
        }});
        let html = build_furniture_section(&p);
        assert!(html.contains("Office Chair"));
        assert!(
            html.contains("Steel &amp; Fabric"),
            "esc() must escape '&'; got: {html}"
        );
        assert!(html.contains("SE"));
        assert!(html.contains("18.40 kg CO\u{2082}e"));
        assert!(html.contains("6.0 / 10"));
    }

    #[test]
    fn missing_co2e_reports_not_disclosed() {
        let p = serde_json::json!({"sectorData": {}});
        let html = build_furniture_section(&p);
        assert!(html.contains("Not disclosed"));
        assert!(html.contains(">-<"));
    }

    #[test]
    fn absent_sector_data_returns_empty_string() {
        let p = serde_json::json!({});
        assert_eq!(build_furniture_section(&p), "");
    }
}
