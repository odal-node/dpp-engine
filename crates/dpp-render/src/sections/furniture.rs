//! Furniture sector HTML section.

use crate::esc::esc;

pub(super) fn build_furniture_section(p: &serde_json::Value) -> String {
    let sd = match p.get("sectorData") {
        Some(v) => v,
        None => return String::new(),
    };
    let product_type = esc(sd
        .get("productType")
        .and_then(|v| v.as_str())
        .unwrap_or("-"));
    let material = esc(sd
        .get("primaryMaterial")
        .and_then(|v| v.as_str())
        .unwrap_or("-"));
    let country = esc(sd
        .get("countryOfManufacture")
        .and_then(|v| v.as_str())
        .unwrap_or("-"));
    let co2e = sd
        .get("co2ePerUnitKg")
        .and_then(|v| v.as_f64())
        .map(|v| format!("{v:.2} kg CO\u{2082}e"))
        .unwrap_or_else(|| "Not disclosed".into());
    let repair = sd
        .get("repairabilityScore")
        .and_then(|v| v.as_f64())
        .map(|v| format!("{v:.1} / 10"))
        .unwrap_or_else(|| "-".into());
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
