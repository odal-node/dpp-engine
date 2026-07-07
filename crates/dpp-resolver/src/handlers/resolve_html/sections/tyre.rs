//! Tyre sector HTML section.

use super::super::esc::esc;

pub(super) fn build_tyre_section(p: &serde_json::Value) -> String {
    let sd = match p.get("sectorData") {
        Some(v) => v,
        None => return String::new(),
    };
    let class = esc(sd.get("tyreClass").and_then(|v| v.as_str()).unwrap_or("-"));
    let fuel = esc(sd
        .get("fuelEfficiencyClass")
        .and_then(|v| v.as_str())
        .unwrap_or("-"));
    let wet = esc(sd
        .get("wetGripClass")
        .and_then(|v| v.as_str())
        .unwrap_or("-"));
    let noise = sd
        .get("externalRollingNoiseDb")
        .and_then(|v| v.as_f64())
        .map(|v| format!("{v:.0} dB"))
        .unwrap_or_else(|| "-".into());
    let noise_class = esc(sd
        .get("noisePerformanceClass")
        .and_then(|v| v.as_str())
        .unwrap_or("-"));
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
