//! Electronics sector HTML section.

use super::super::esc::esc;

pub(super) fn build_electronics_section(p: &serde_json::Value) -> String {
    let sd = match p.get("sectorData") {
        Some(v) => v,
        None => return String::new(),
    };
    let category = esc(sd
        .get("productCategory")
        .and_then(|v| v.as_str())
        .unwrap_or("-"));
    let efficiency = esc(sd
        .get("energyEfficiencyClass")
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
    let lifetime = sd
        .get("expectedLifetimeYears")
        .and_then(|v| v.as_u64())
        .map(|v| format!("{v} years"))
        .unwrap_or_else(|| "-".into());
    format!(
        r#"<h2>Electronics Information</h2>
    <table aria-label="Electronics data">
      <tr><th scope="row">Product Category</th><td>{category}</td></tr>
      <tr><th scope="row">Energy Efficiency</th><td>{efficiency}</td></tr>
      <tr><th scope="row">Carbon Footprint</th><td>{co2e}</td></tr>
      <tr><th scope="row">Repairability Score</th><td>{repair}</td></tr>
      <tr><th scope="row">Expected Lifetime</th><td>{lifetime}</td></tr>
    </table>"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_data_populates_all_fields() {
        let p = serde_json::json!({"sectorData": {
            "productCategory": "Smartphone",
            "energyEfficiencyClass": "A",
            "co2ePerUnitKg": 42.1,
            "repairabilityScore": 7.5,
            "expectedLifetimeYears": 5,
        }});
        let html = build_electronics_section(&p);
        assert!(html.contains("Smartphone"));
        assert!(html.contains(">A<"));
        assert!(html.contains("42.10 kg CO\u{2082}e"));
        assert!(html.contains("7.5 / 10"));
        assert!(html.contains("5 years"));
    }

    #[test]
    fn missing_co2e_reports_not_disclosed() {
        let p = serde_json::json!({"sectorData": {}});
        let html = build_electronics_section(&p);
        assert!(html.contains("Not disclosed"));
        assert!(html.contains(">-<"));
    }

    #[test]
    fn absent_sector_data_returns_empty_string() {
        let p = serde_json::json!({});
        assert_eq!(build_electronics_section(&p), "");
    }
}
