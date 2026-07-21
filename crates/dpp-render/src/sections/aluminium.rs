//! Aluminium sector HTML section.

use crate::fields::{f64_field, str_field};

pub(super) fn build_aluminium_section(p: &serde_json::Value) -> String {
    let sd = match p.get("sectorData") {
        Some(v) => v,
        None => return String::new(),
    };
    let grade = str_field(sd, "alloyGrade", "-");
    let route = str_field(sd, "productionRoute", "-");
    let country = str_field(sd, "countryOfProduction", "-");
    let co2e = f64_field(sd, "co2ePerTonneKg", "-", |v| {
        format!("{v:.2} kg CO\u{2082}e / t")
    });
    let recycled = f64_field(sd, "recycledContentPct", "-", |v| format!("{v:.1}%"));
    format!(
        r#"<h2>Aluminium Product Information</h2>
    <table aria-label="Aluminium data">
      <tr><th scope="row">Alloy Grade</th><td>{grade}</td></tr>
      <tr><th scope="row">Production Route</th><td>{route}</td></tr>
      <tr><th scope="row">Country of Production</th><td>{country}</td></tr>
      <tr><th scope="row">Carbon Intensity</th><td>{co2e}</td></tr>
      <tr><th scope="row">Recycled Content</th><td>{recycled}</td></tr>
    </table>"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_data_populates_all_fields() {
        let p = serde_json::json!({"sectorData": {
            "alloyGrade": "6061-T6",
            "productionRoute": "Primary",
            "countryOfProduction": "DE",
            "co2ePerTonneKg": 8500.5,
            "recycledContentPct": 22.3,
        }});
        let html = build_aluminium_section(&p);
        assert!(html.contains("6061-T6"));
        assert!(html.contains("Primary"));
        assert!(html.contains("DE"));
        assert!(html.contains("8500.50 kg CO\u{2082}e / t"));
        assert!(html.contains("22.3%"));
    }

    #[test]
    fn missing_fields_fall_back_to_dashes() {
        let p = serde_json::json!({"sectorData": {}});
        let html = build_aluminium_section(&p);
        assert!(html.contains("Aluminium Product Information"));
        assert!(html.contains(">-<"));
    }

    #[test]
    fn absent_sector_data_returns_empty_string() {
        let p = serde_json::json!({});
        assert_eq!(build_aluminium_section(&p), "");
    }
}
