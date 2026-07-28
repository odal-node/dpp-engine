//! Electronics sector HTML section.

use crate::fields::{f64_field, str_field, u64_field};

pub(super) fn build_electronics_section(p: &serde_json::Value) -> String {
    let sd = match p.get("sectorData") {
        Some(v) => v,
        None => return String::new(),
    };
    let category = str_field(sd, "productCategory", "-");
    let efficiency = str_field(sd, "energyEfficiencyClass", "-");
    let co2e = f64_field(sd, "co2ePerUnitKg", "Not disclosed", |v| {
        format!("{v:.2} kg CO\u{2082}e")
    });
    // `ElectronicsData::repairability_score` is a `RepairabilityScore` struct
    // (`{ overall, criteria }`), not a scalar — unlike furniture's, which really
    // is an `f64`. Reading it as a scalar always missed and rendered the dash, so
    // the public electronics page never showed a repairability score. The section
    // fixture asserted against a bare float, which is why no test caught it.
    let repair = sd
        .get("repairabilityScore")
        .and_then(|v| v.get("overall"))
        .and_then(serde_json::Value::as_f64)
        .map(|v| format!("{v:.1} / 10"))
        .unwrap_or_else(|| "-".to_owned());
    let lifetime = u64_field(sd, "expectedLifetimeYears", "-", |v| format!("{v} years"));
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
        let p = crate::sections::typed_fixture(serde_json::json!({
            "sector": "electronics",
            "gtin": "09506000134352",
            "productCategory": "Smartphone",
            "energyEfficiencyClass": "A",
            "co2ePerUnitKg": 42.1,
            "repairabilityScore": { "overall": 7.5 },
            "expectedLifetimeYears": 5,
        }));
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
