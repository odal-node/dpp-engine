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
