//! Aluminium sector HTML section.

use crate::esc::esc;

pub(super) fn build_aluminium_section(p: &serde_json::Value) -> String {
    let sd = match p.get("sectorData") {
        Some(v) => v,
        None => return String::new(),
    };
    let grade = esc(sd.get("alloyGrade").and_then(|v| v.as_str()).unwrap_or("-"));
    let route = esc(sd
        .get("productionRoute")
        .and_then(|v| v.as_str())
        .unwrap_or("-"));
    let country = esc(sd
        .get("countryOfProduction")
        .and_then(|v| v.as_str())
        .unwrap_or("-"));
    let co2e = sd
        .get("co2ePerTonneKg")
        .and_then(|v| v.as_f64())
        .map(|v| format!("{v:.2} kg CO\u{2082}e / t"))
        .unwrap_or_else(|| "-".into());
    let recycled = sd
        .get("recycledContentPct")
        .and_then(|v| v.as_f64())
        .map(|v| format!("{v:.1}%"))
        .unwrap_or_else(|| "-".into());
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
