//! Aluminium sector HTML section.

use super::super::esc::esc;

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
