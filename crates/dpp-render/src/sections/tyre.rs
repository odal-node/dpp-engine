//! Tyre sector HTML section.

use crate::fields::{f64_field, str_field};

pub(super) fn build_tyre_section(p: &serde_json::Value) -> String {
    let sd = match p.get("sectorData") {
        Some(v) => v,
        None => return String::new(),
    };
    let class = str_field(sd, "tyreClass", "-");
    let fuel = str_field(sd, "fuelEfficiencyClass", "-");
    let wet = str_field(sd, "wetGripClass", "-");
    let noise = f64_field(sd, "externalRollingNoiseDb", "-", |v| format!("{v:.0} dB"));
    let noise_class = str_field(sd, "noisePerformanceClass", "-");
    format!(
        r#"<h2>Tyre Labelling Information</h2>
    <table aria-label="Tyre data">
      <tr><th scope="row">Tyre Class</th><td>{class}</td></tr>
      <tr><th scope="row">Fuel Efficiency (EU 2020/740)</th><td>{fuel}</td></tr>
      <tr><th scope="row">Wet Grip Class</th><td>{wet}</td></tr>
      <tr><th scope="row">External Rolling Noise</th><td>{noise}</td></tr>
      <tr><th scope="row">Noise Performance Class</th><td>{noise_class}</td></tr>
    </table>"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_data_populates_all_fields() {
        let p = serde_json::json!({"sectorData": {
            "tyreClass": "C1",
            "fuelEfficiencyClass": "B",
            "wetGripClass": "A",
            "externalRollingNoiseDb": 68.0,
            "noisePerformanceClass": "1",
        }});
        let html = build_tyre_section(&p);
        assert!(html.contains(">C1<"));
        assert!(html.contains(">B<"));
        assert!(html.contains(">A<"));
        assert!(html.contains("68 dB"));
        assert!(html.contains(">1<"));
    }

    #[test]
    fn missing_fields_fall_back_to_dashes() {
        let p = serde_json::json!({"sectorData": {}});
        let html = build_tyre_section(&p);
        assert!(html.contains("Tyre Labelling Information"));
        assert!(html.contains(">-<"));
    }

    #[test]
    fn absent_sector_data_returns_empty_string() {
        let p = serde_json::json!({});
        assert_eq!(build_tyre_section(&p), "");
    }
}
